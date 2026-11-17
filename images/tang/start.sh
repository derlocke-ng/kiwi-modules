#!/bin/sh
# The keys are made once and belong to the unprivileged tang user; tangd runs as that user.
set -eu
PORT=${TANG_PORT:-7500}
chown -R tang:tang /db
chmod 0700 /db
# A key file with something in it: a power cut just after the keys were made once left them
# empty, and the ring then answered with nothing a machine could use.
have_keys() { for f in /db/*.jwk; do [ -s "$f" ] && return 0; done; return 1; }
if ! have_keys; then
    for f in /db/*.jwk; do                  # empty ones, from such a cut: kept aside, never served
        [ -e "$f" ] && mkdir -p /db/.empty && mv "$f" /db/.empty/
    done
    # made beside, on the disk, then put in place: a cut now leaves no keys or whole ones
    rm -rf /db/.new && mkdir /db/.new && chown tang:tang /db/.new
    setpriv --reuid=tang --regid=tang --clear-groups /usr/libexec/tangd-keygen /db/.new
    sync /db/.new/*.jwk
    mv /db/.new/*.jwk /db/
    rmdir /db/.new
    sync /db
fi
# not exec: as PID 1 tangd would ignore the signal that stops the container
setpriv --reuid=tang --regid=tang --clear-groups /usr/libexec/tangd -l -p "$PORT" /db &
tangd=$!
trap 'kill "$tangd"; wait "$tangd"; exit 0' TERM INT
wait "$tangd"
