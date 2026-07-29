#!/usr/bin/env bash
set -euo pipefail

harness_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$harness_dir/../../../.." && pwd)"
source_url="https://github.com/cyrusimap/cyrus-imapd/releases/download/cyrus-imapd-3.12.2/cyrus-imapd-3.12.2.tar.gz"
source_sha256="681ca57483b3dd9ee91f171e11e5ee21684d1da87262e27ea6ff9bd076e9514d"
image="${BICHON_CYRUS_IMAGE:-bichon-cyrus-test:3.12.2}"
cargo_bin="${CARGO:-cargo}"
run_id="bichon-cyrus-uidonly-$$"
container="$run_id"
state_volume="${run_id}-state"
spool_volume="${run_id}-spool"
work_root="$(mktemp -d "${TMPDIR:-/tmp}/bichon-cyrus-uidonly.XXXXXX")"
built_image=0

cleanup() {
    status=$?
    trap - EXIT

    if docker container inspect "$container" >/dev/null 2>&1; then
        if [ "$status" -ne 0 ]; then
            docker logs --tail 80 "$container" >&2 || true
        fi
        if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = "true" ]; then
            docker stop -t 20 "$container" >/dev/null || true
        fi
        docker rm "$container" >/dev/null 2>&1 || true
    fi
    docker volume rm "$state_volume" "$spool_volume" >/dev/null 2>&1 || true
    if [ "$built_image" -eq 1 ] && [ "${BICHON_CYRUS_KEEP_IMAGE:-0}" != "1" ]; then
        docker image rm "$image" >/dev/null 2>&1 || true
    fi
    rm -rf "$work_root"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

for command in docker curl python3 "$cargo_bin"; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required command not found: $command" >&2
        exit 2
    fi
done

if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "Building pinned Cyrus 3.12.2 test image..."
    curl --fail --location --silent --show-error \
        "$source_url" \
        --output "$work_root/cyrus-imapd-3.12.2.tar.gz"
    actual_sha256="$(
        python3 - "$work_root/cyrus-imapd-3.12.2.tar.gz" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
with path.open("rb") as source:
    for block in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(block)
print(digest.hexdigest())
PY
    )"
    if [ "$actual_sha256" != "$source_sha256" ]; then
        echo "Cyrus source checksum mismatch" >&2
        exit 2
    fi
    cp "$harness_dir/Dockerfile" "$work_root/Dockerfile"
    cp "$harness_dir/container-entrypoint.sh" "$work_root/container-entrypoint.sh"
    docker build --tag "$image" "$work_root"
    built_image=1
fi

docker volume create --label "bichon.test=$run_id" "$state_volume" >/dev/null
docker volume create --label "bichon.test=$run_id" "$spool_volume" >/dev/null
docker run --detach \
    --name "$container" \
    --label "bichon.test=$run_id" \
    --read-only \
    --tmpfs /run:rw,nosuid,nodev,noexec,size=16m \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
    --publish 127.0.0.1::143 \
    --mount "type=volume,source=$state_volume,target=/var/lib/cyrus" \
    --mount "type=volume,source=$spool_volume,target=/var/spool/cyrus" \
    --mount "type=bind,source=$harness_dir/imapd.conf,target=/etc/imapd.conf,readonly" \
    --mount "type=bind,source=$harness_dir/cyrus.conf,target=/etc/cyrus.conf,readonly" \
    "$image" >/dev/null

port_line="$(docker port "$container" 143/tcp)"
case "$port_line" in
    127.0.0.1:*) port="${port_line##*:}" ;;
    *)
        echo "Cyrus was not bound exclusively to localhost: $port_line" >&2
        exit 2
        ;;
esac

printf '%s\n' 'synthetic-only-password' \
    | docker exec -i "$container" saslpasswd2 -p -c \
        -f /var/lib/cyrus/sasldb2 -u synthetic.invalid cyrus
printf '%s\n' 'synthetic-only-password' \
    | docker exec -i "$container" saslpasswd2 -p -c \
        -f /var/lib/cyrus/sasldb2 -u synthetic.invalid archive-test
docker exec "$container" chown cyrus:mail /var/lib/cyrus/sasldb2
docker exec "$container" chmod 640 /var/lib/cyrus/sasldb2

python3 - "$port" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as stream:
            if stream.recv(4096).startswith(b"* OK"):
                break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("Cyrus did not become ready")
PY

echo "Running Bichon UIDONLY Cyrus interoperability test..."
(
    cd "$repo_root"
    BICHON_CYRUS_PORT="$port" \
    BICHON_CYRUS_ARCHIVE_ROOT="$work_root/archive" \
        "$cargo_bin" test -p bichon-core --lib --no-default-features --locked \
        imap::uidonly_acquisition::tests::cyrus_uidonly_exact_raw_roundtrip \
        -- --ignored --exact --test-threads=1
)
