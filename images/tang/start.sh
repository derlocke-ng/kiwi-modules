#!/bin/sh
# The keys are made once and belong to the unprivileged tang user; tangd runs as that user.
set -eu
PORT=${TANG_PORT:-7500}
chown -R tang:tang /db
chmod 0700 /db
if ! ls /db/*.jwk >/dev/null 2>&1; then
    setpriv --reuid=tang --regid=tang --clear-groups /usr/libexec/tangd-keygen /db
fi
# not exec: as PID 1 tangd would ignore the signal that stops the container
setpriv --reuid=tang --regid=tang --clear-groups /usr/libexec/tangd -l -p "$PORT" /db &
tangd=$!
trap 'kill "$tangd"; wait "$tangd"; exit 0' TERM INT
wait "$tangd"
