#!/usr/bin/env bash
# AUREON Console installer - idempotent, no silent overwrites.
# Author: Antonio Lourenco Ferreira. License: MIT.
set -euo pipefail

PREFIX="${PREFIX:-$HOME/.local}"
BINDIR="${BINDIR:-$PREFIX/bin}"
VENV_DIR="${VENV_DIR:-$PREFIX/share/aureon/venv}"
if [ "$(id -u)" = "0" ]; then
    DEFAULT_STATE_DIR="/var/lib/aureon"
else
    # Least privilege: a per-user install keeps its history in the user's own
    # XDG data directory instead of a root-owned system path.
    DEFAULT_STATE_DIR="$HOME/.local/share/aureon"
fi
STATE_DIR="${AUREON_STATE_DIR:-$DEFAULT_STATE_DIR}"
FORCE=0
WITH_DEV=0

usage() {
    cat <<'EOF'
AUREON Console installer

  ./install.sh                 install for the current user (~/.local)
  sudo ./install.sh            install system-wide (root-owned venv, /var/lib/aureon)
  ./install.sh --dev           also install test dependencies
  ./install.sh --force         reinstall over an existing installation (backs it up first)
  ./install.sh --prefix DIR    install into another prefix
  ./install.sh --uninstall     remove the application (data is preserved by default)
  ./install.sh --purge-data    also delete the AUREON database and backups (asks first)
EOF
}

PURGE=0
UNINSTALL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --dev) WITH_DEV=1 ;;
        --force) FORCE=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --purge-data) PURGE=1 ;;
        --prefix) PREFIX="$2"; BINDIR="$2/bin"; VENV_DIR="$2/share/aureon/venv"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
done

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$UNINSTALL" = "1" ]; then
    echo "==> Removing AUREON Console"
    if [ -x "$BINDIR/aureon" ]; then
        rm -f "$BINDIR/aureon"
        echo "    removed $BINDIR/aureon"
    fi
    if [ -d "$VENV_DIR" ]; then
        rm -rf "$VENV_DIR"
        echo "    removed $VENV_DIR"
    fi
    # Only the venv tree is removed. "$PREFIX/share/aureon" may also hold the
    # history database (that is the default state directory for a per-user
    # install), so it must never be deleted as a whole.
    rmdir "$PREFIX/share/aureon" 2>/dev/null || true
    if [ "$PURGE" = "1" ]; then
        if [ "$STATE_DIR" = "/" ] || [ -z "$STATE_DIR" ]; then
            echo "refusing to purge '$STATE_DIR'" >&2; exit 1
        fi
        printf 'Delete AUREON history database and backups in %s? [y/N] ' "$STATE_DIR"
        read -r answer
        case "$answer" in
            y|Y|yes|YES) rm -rf "$STATE_DIR"; echo "    removed $STATE_DIR" ;;
            *) echo "    left $STATE_DIR untouched" ;;
        esac
    else
        echo "    history data in $STATE_DIR was preserved (use --purge-data to delete it)"
    fi
    echo "Done."
    exit 0
fi

echo "==> AUREON Console installer"
echo "    prefix   : $PREFIX"
echo "    venv     : $VENV_DIR"
echo "    state    : $STATE_DIR"

for tool in python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done

PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
python3 - <<'PY' || { echo "Python 3.9 or newer is required (found $PYVER)" >&2; exit 1; }
import sys
raise SystemExit(0 if sys.version_info >= (3, 9) else 1)
PY

if [ -d "$VENV_DIR" ] && [ "$FORCE" = "0" ]; then
    echo "an installation already exists at $VENV_DIR" >&2
    echo "re-run with --force to replace it (a backup is taken first)" >&2
    exit 3
fi

if [ -d "$VENV_DIR" ] && [ "$FORCE" = "1" ]; then
    BACKUP="$VENV_DIR.bak.$(date +%Y%m%d-%H%M%S)"
    echo "==> Backing up existing installation to $BACKUP"
    mv "$VENV_DIR" "$BACKUP"
fi

echo "==> Creating virtual environment"
python3 -m venv "$VENV_DIR"

echo "==> Installing AUREON Console"
"$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
"$VENV_DIR/bin/pip" install "$SRC_DIR"
if [ "$WITH_DEV" = "1" ]; then
    "$VENV_DIR/bin/pip" install "$SRC_DIR[dev]"
fi

mkdir -p "$BINDIR"
ln -sf "$VENV_DIR/bin/aureon" "$BINDIR/aureon"
echo "    linked $BINDIR/aureon"

if [ "$(id -u)" = "0" ]; then
    install -d -m 0700 -o root -g root "$STATE_DIR"
    echo "    state directory: $STATE_DIR"
fi

echo "==> Verifying installation"
"$BINDIR/aureon" --version
"$BINDIR/aureon" doctor || true

cat <<EOF

Installation complete.

    export PATH="$BINDIR:\$PATH"
    aureon                 # open the console as your normal user
    sudo aureon            # optional: live Fail2ban ban list only

Documentation: docs/INSTALLATION.md
EOF
