#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# ============================================================
# TrueAegis Uninstaller
#
# Usage:
#   ./uninstall.sh
#   ./uninstall.sh --purge
#   ./uninstall.sh --purge-netsniper
#   ./uninstall.sh --purge --purge-netsniper
# ============================================================

TRUEAEGIS_HOME="${TRUEAEGIS_HOME:-$HOME/TrueAegis}"
NETSNIPER_BASE="${NETSNIPER_BASE:-$HOME/NetSniper}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

PURGE_TRUEAEGIS=0
PURGE_NETSNIPER=0

for arg in "$@"; do
    case "$arg" in
        --purge)
            PURGE_TRUEAEGIS=1
            ;;
        --purge-netsniper)
            PURGE_NETSNIPER=1
            ;;
        -h|--help)
            cat <<'EOF'
Usage:
  ./uninstall.sh
  ./uninstall.sh --purge
  ./uninstall.sh --purge-netsniper
  ./uninstall.sh --purge --purge-netsniper

Options:
  --purge             Delete the TrueAegis project directory.
  --purge-netsniper  Delete the NetSniper project directory too.
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Run ./uninstall.sh --help for usage."
            exit 1
            ;;
    esac
done

echo "[+] Removing TrueAegis launchers"

rm -f "$BIN_DIR/trueaegis"
rm -f "$BIN_DIR/trueaegis-web"

echo "[+] Removing NetSniper launcher installed by TrueAegis"

rm -f "$BIN_DIR/netsniper"

if [[ "$PURGE_TRUEAEGIS" -eq 1 ]]; then
    echo "[+] Removing TrueAegis project directory: $TRUEAEGIS_HOME"
    rm -rf "$TRUEAEGIS_HOME"
else
    echo "[!] TrueAegis project files and reports were not deleted."
    echo "    To remove them too, run:"
    echo "    ./uninstall.sh --purge"
fi

if [[ "$PURGE_NETSNIPER" -eq 1 ]]; then
    echo "[+] Removing NetSniper project directory: $NETSNIPER_BASE"
    rm -rf "$NETSNIPER_BASE"
else
    echo "[!] NetSniper project files and scan outputs were not deleted."
    echo "    To remove them too, run:"
    echo "    ./uninstall.sh --purge-netsniper"
fi

echo "[+] TrueAegis uninstall complete"
