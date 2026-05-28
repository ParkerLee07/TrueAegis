#!/usr/bin/env bash
set -Eeuo pipefail

TRUEAEGIS_HOME="${TRUEAEGIS_HOME:-$HOME/TrueAegis}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

echo "[*] Removing TrueAegis launchers..."

rm -f "$BIN_DIR/trueaegis"
rm -f "$BIN_DIR/netsniper"
rm -f "$BIN_DIR/trueaegis-web"

echo "[+] Launchers removed."
echo ""
echo "[!] Project files were not deleted."
echo "To remove all TrueAegis files manually:"
echo "rm -rf \"$TRUEAEGIS_HOME\""
