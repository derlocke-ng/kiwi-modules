#!/usr/bin/env bash
# kiwi-modules installer — the kiwi-updater contract:
#   ./install.sh install|update|uninstall [--purge]
# KIWI_SCOPE=user (default) installs under ~/.local; KIWI_PREFIX overrides the prefix.
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n ${KIWI_PREFIX:-} ]]; then
    PREFIX=$KIWI_PREFIX
elif [[ ${KIWI_SCOPE:-user} == system ]]; then
    PREFIX=/usr/local
else
    PREFIX="$HOME/.local"
fi
LIB="$PREFIX/lib/kiwi-modules"

say()  { printf ':: %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

do_install() {
    command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required" >&2; exit 1; }
    python3 -c 'import yaml' 2>/dev/null ||
        warn "python3 cannot import yaml — install python3-pyyaml (or pip install --user pyyaml)"
    python3 -c 'import jinja2' 2>/dev/null ||
        warn "python3 cannot import jinja2 — install python3-jinja2 (or pip install --user jinja2)"
    say "installing the library to $LIB"
    rm -rf "$LIB"
    mkdir -p "$LIB"
    cp -r "$SRC/lib" "$SRC/modules" "$SRC/profiles" "$SRC/examples" "$LIB/"
    find "$LIB" -name '__pycache__' -type d -prune -exec rm -rf {} +
    say "installing kiwi-modules to $PREFIX/bin"
    install -Dm755 "$SRC/bin/kiwi-modules" "$PREFIX/bin/kiwi-modules"
    say "done — kiwi-modules render machine.yaml -o DIR"
}

do_uninstall() {
    say "removing $PREFIX/bin/kiwi-modules and $LIB"
    rm -f "$PREFIX/bin/kiwi-modules"
    rm -rf "$LIB"
}

case ${1:-} in
    install|update) do_install ;;
    uninstall) do_uninstall ;;
    *) echo "usage: $0 install|update|uninstall [--purge]" >&2; exit 1 ;;
esac
