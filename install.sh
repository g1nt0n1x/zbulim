#!/usr/bin/env bash
# Install zbulim to /usr/local/bin

set -e

DEST="/usr/local/bin/zbulim"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo ./install.sh"
    exit 1
fi

cp zbulim "$DEST"
chmod +x "$DEST"
echo "Installed → $DEST"
echo "Run: zbulim <target>"