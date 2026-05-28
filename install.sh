#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

TRUEAEGIS_HOME="${TRUEAEGIS_HOME:-$HOME/TrueAegis}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
BLUE='\033[1;34m'
RESET='\033[0m'

info() { echo -e "${BLUE}[i]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn() { echo -e "${YELLOW}[!]${RESET} $1"; }
error() { echo -e "${RED}[-]${RESET} $1"; }

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        error "$1 is required but not installed."
        return 1
    fi
}

echo ""
echo "================================"
echo "       TrueAegis Installer"
echo "================================"
echo ""

require_command python3
require_command pip3 || warn "pip3 not found. Python packages may need manual install."
require_command nmap || warn "nmap not found. NetSniper scanning requires nmap."
require_command jq || warn "jq not found. NetSniper analysis requires jq."

mkdir -p "$TRUEAEGIS_HOME"
mkdir -p "$BIN_DIR"

for dir in reports validation_results workspace workspace/scans workspace/snapshots workspace/deltas web_logs; do
    mkdir -p "$TRUEAEGIS_HOME/$dir"
done

if [ -f requirements.txt ]; then
    info "Installing Python dependencies..."
    python3 -m pip install --user -r requirements.txt || warn "Dependency install failed. Try manually: pip install -r requirements.txt"
fi

if [ -f trueaegis.py ]; then
    cp trueaegis.py "$TRUEAEGIS_HOME/trueaegis.py"
    success "Installed trueaegis.py"
else
    warn "trueaegis.py not found in current directory."
fi

if [ -f netsniper.sh ]; then
    cp netsniper.sh "$TRUEAEGIS_HOME/netsniper.sh"
    chmod +x "$TRUEAEGIS_HOME/netsniper.sh"
    success "Installed netsniper.sh"
else
    warn "netsniper.sh not found in current directory."
fi

for dir in remediations knowledge intelligence validators web; do
    if [ -d "$dir" ]; then
        cp -r "$dir" "$TRUEAEGIS_HOME/"
        success "Installed $dir/"
    else
        warn "$dir/ not found."
    fi
done

cat > "$BIN_DIR/trueaegis" <<EOF
#!/usr/bin/env bash
python3 "$TRUEAEGIS_HOME/trueaegis.py" "\$@"
EOF

cat > "$BIN_DIR/netsniper" <<EOF
#!/usr/bin/env bash
bash "$TRUEAEGIS_HOME/netsniper.sh" "\$@"
EOF

cat > "$BIN_DIR/trueaegis-web" <<EOF
#!/usr/bin/env bash
TRUEAEGIS_HOME="$TRUEAEGIS_HOME" python3 "$TRUEAEGIS_HOME/web/app.py" "\$@"
EOF

chmod +x "$BIN_DIR/trueaegis" "$BIN_DIR/netsniper" "$BIN_DIR/trueaegis-web"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    warn "$BIN_DIR is not in your PATH."
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    warn "Added PATH update to ~/.bashrc. Run: source ~/.bashrc"
fi

echo ""
success "TrueAegis installation complete."
echo ""
echo "Run:"
echo "  netsniper"
echo "  trueaegis"
echo "  trueaegis-web"
echo ""
