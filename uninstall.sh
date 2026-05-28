#!/usr/bin/env bash
set -Eeuo pipefail

TRUEAEGIS_HOME="${TRUEAEGIS_HOME:-$HOME/TrueAegis}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

echo "[*] Removing TrueAegis launchers..."

rm -f "$BIN_DIR/trueaegis"
rm -f "$BIN_DIR/trueaegis-web"
rm -f "$BIN_DIR/netsniper"

echo "[+] Launchers removed."
echo ""
echo "[!] Project files and virtual environment were not deleted."
echo "To remove everything manually:"
echo "  rm -rf \"$TRUEAEGIS_HOME\""
