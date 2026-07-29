#!/bin/sh
set -eu

state_uid="$(id -u cyrus)"
state_gid="$(id -g cyrus)"
for state_dir in /var/lib/cyrus /var/spool/cyrus/mail; do
    mkdir -p "$state_dir"
    if [ -z "$(find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        chown "$state_uid:$state_gid" "$state_dir"
    fi
    actual="$(stat -c '%u:%g' "$state_dir")"
    if [ "$actual" != "$state_uid:$state_gid" ]; then
        echo "unexpected Cyrus state owner for $state_dir" >&2
        exit 78
    fi
done

exec /usr/sbin/gosu cyrus:cyrus \
    /usr/local/cyrus/libexec/master -D \
    -C /etc/imapd.conf -M /etc/cyrus.conf
