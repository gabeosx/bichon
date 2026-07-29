# Cyrus UIDONLY interoperability test

This opt-in test runs Bichon's UIDONLY acquisition path against a disposable
Cyrus IMAP 3.12.2 server. It uses three synthetic messages and verifies exact
raw-message acquisition, restart behavior, canonical records, and staging
cleanup.

Run it from the repository root:

```sh
crates/core/tests/cyrus/run.sh
```

The first run downloads the Cyrus 3.12.2 source release, verifies its SHA-256,
and builds a local test image. Docker binds the server to a random localhost
port and uses two uniquely named volumes. The script removes its container,
volumes, temporary archive, and newly built image when it exits.

Set `BICHON_CYRUS_KEEP_IMAGE=1` to retain a newly built image for later runs, or
set `BICHON_CYRUS_IMAGE` to use an existing compatible Cyrus 3.12.2 image.

Requirements:

- Docker
- curl
- Python 3
- the Rust toolchain used to build Bichon

Cyrus implements UIDONLY and PARTIAL but not MESSAGELIMIT. MESSAGELIMIT and
malformed-response behavior remain covered by deterministic Rust tests.
