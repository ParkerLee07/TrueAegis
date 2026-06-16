#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

TRUEAEGIS_HOME="${TRUEAEGIS_HOME:-$HOME/TrueAegis}"
NETSNIPER_HOME="${NETSNIPER_HOME:-$HOME/NetSniper}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

PURGE=0
PURGE_NETSNIPER=0

for arg in "$@"; do
    case "$arg" in
        --purge)
            PURGE=1
            ;;
        --purge-netsniper)
            PURGE_NETSNIPER=1
            ;;
        -h|--help)
            echo "Usage: ./uninstall.sh [--purge] [--purge-netsniper]"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

echo "[+] Removing TrueAegis launchers"

rm -f "$BIN_DIR/trueaegis"
rm -f "$BIN_DIR/trueaegis-web"

echo "[+] Removing NetSniper launcher installed by TrueAegis"

rm -f "$BIN_DIR/netsniper"

if [[ "$PURGE" -eq 1 ]]; then
    echo "[+] Removing TrueAegis project directory: $TRUEAEGIS_HOME"
    rm -rf "$TRUEAEGIS_HOME"
else
    echo "[!] TrueAegis project files and reports were not deleted."
    echo "    To remove them, run:"
    echo "    ./uninstall.sh --purge"
fi

if [[ "$PURGE_NETSNIPER" -eq 1 ]]; then
    echo "[+] Removing NetSniper directory: $NETSNIPER_HOME"
    rm -rf "$NETSNIPER_HOME"
else
    echo "[!] NetSniper was not deleted."
    echo "    To remove it too, run:"
    echo "    ./uninstall.sh --purge-netsniper"
fi

echo "[+] TrueAegis uninstall complete"
