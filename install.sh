#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# =========================
# TrueAegis Installer
# Kali / Debian safe version
# =========================

TRUEAEGIS_REPO="${TRUEAEGIS_REPO:-https://github.com/ParkerLee07/TrueAegis.git}"
NETSNIPER_REPO="${NETSNIPER_REPO:-https://github.com/ParkerLee07/NetSniper.git}"

TRUEAEGIS_HOME="${TRUEAEGIS_HOME:-$HOME/TrueAegis}"
NETSNIPER_BASE="${NETSNIPER_BASE:-$HOME/NetSniper}"

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
VENV_DIR="$TRUEAEGIS_HOME/.venv"

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
        exit 1
    fi
}

echo ""
echo "================================"
echo "       TrueAegis Installer"
echo "   Kali / Debian Safe Install"
echo "================================"
echo ""

require_command python3
require_command bash
require_command git

if ! python3 -m venv --help >/dev/null 2>&1; then
    error "python3-venv is required."
    echo ""
    echo "Install it with:"
    echo "  sudo apt update"
    echo "  sudo apt install python3-venv"
    exit 1
fi

mkdir -p "$BIN_DIR"

# -------------------------
# Install / update TrueAegis
# -------------------------
if [ -d "$TRUEAEGIS_HOME/.git" ]; then
    info "Updating existing TrueAegis repo at $TRUEAEGIS_HOME"
    git -C "$TRUEAEGIS_HOME" pull
else
    info "Cloning TrueAegis into $TRUEAEGIS_HOME"
    rm -rf "$TRUEAEGIS_HOME"
    git clone "$TRUEAEGIS_REPO" "$TRUEAEGIS_HOME"
fi

# -------------------------
# Install / update NetSniper
# -------------------------
if [ -d "$NETSNIPER_BASE/.git" ]; then
    info "Updating existing NetSniper repo at $NETSNIPER_BASE"
    git -C "$NETSNIPER_BASE" pull
else
    info "Cloning NetSniper into $NETSNIPER_BASE"
    rm -rf "$NETSNIPER_BASE"
    git clone "$NETSNIPER_REPO" "$NETSNIPER_BASE"
fi

# -------------------------
# Dependency warnings
# -------------------------
if ! command -v nmap >/dev/null 2>&1; then
    warn "nmap not found. NetSniper scanning requires nmap."
    echo "Install with: sudo apt install nmap"
fi

if ! command -v jq >/dev/null 2>&1; then
    warn "jq not found. NetSniper analysis may require jq."
    echo "Install with: sudo apt install jq"
fi

if ! command -v smbclient >/dev/null 2>&1; then
  warn "smbclient not found. TrueAegis SMB validation will report DEPENDENCY_MISSING."
  echo "Install with: sudo apt install smbclient"
fi

# -------------------------
# Workspace setup
# -------------------------
for dir in reports validation_results workspace workspace/scans workspace/snapshots workspace/deltas web_logs; do
    mkdir -p "$TRUEAEGIS_HOME/$dir"
done

# -------------------------
# Python virtual environment
# -------------------------
info "Creating Python virtual environment at $VENV_DIR"
python3 -m venv "$VENV_DIR"

info "Upgrading pip inside virtual environment"
"$VENV_DIR/bin/python" -m pip install --upgrade pip

if [ -f "$TRUEAEGIS_HOME/requirements.txt" ]; then
    info "Installing Python dependencies from requirements.txt"
    "$VENV_DIR/bin/python" -m pip install -r "$TRUEAEGIS_HOME/requirements.txt"
else
    warn "requirements.txt not found. Installing default dependencies."
    "$VENV_DIR/bin/python" -m pip install rich flask reportlab
fi

# -------------------------
# File permissions
# -------------------------
if [ -f "$TRUEAEGIS_HOME/trueaegis.py" ]; then
    chmod +x "$TRUEAEGIS_HOME/trueaegis.py"
else
    error "trueaegis.py not found in $TRUEAEGIS_HOME"
    exit 1
fi

if [ -f "$NETSNIPER_BASE/netsniper.sh" ]; then
    chmod +x "$NETSNIPER_BASE/netsniper.sh"
else
    warn "netsniper.sh not found at $NETSNIPER_BASE/netsniper.sh"
fi

# -------------------------
# Launchers
# -------------------------
cat > "$BIN_DIR/trueaegis" <<EOF
#!/usr/bin/env bash
export TRUEAEGIS_HOME="$TRUEAEGIS_HOME"
export NETSNIPER_BASE="$NETSNIPER_BASE"
exec "$VENV_DIR/bin/python" "$TRUEAEGIS_HOME/trueaegis.py" "\$@"
EOF

cat > "$BIN_DIR/netsniper" <<EOF
#!/usr/bin/env bash
export NETSNIPER_BASE="$NETSNIPER_BASE"
cd "$NETSNIPER_BASE"

if [ -f "./netsniper.sh" ]; then
    exec bash "./netsniper.sh" "\$@"
else
    echo "[ERROR] netsniper.sh not found in $NETSNIPER_BASE"
    exit 1
fi
EOF

if [ -f "$TRUEAEGIS_HOME/web/app.py" ]; then
    cat > "$BIN_DIR/trueaegis-web" <<EOF
#!/usr/bin/env bash
export TRUEAEGIS_HOME="$TRUEAEGIS_HOME"
export NETSNIPER_BASE="$NETSNIPER_BASE"
exec "$VENV_DIR/bin/python" "$TRUEAEGIS_HOME/web/app.py" "\$@"
EOF
    chmod +x "$BIN_DIR/trueaegis-web"
else
    warn "web/app.py not found. Skipping trueaegis-web launcher."
fi

chmod +x "$BIN_DIR/trueaegis"
chmod +x "$BIN_DIR/netsniper"

success "Created launchers:"
echo "  $BIN_DIR/trueaegis"
echo "  $BIN_DIR/netsniper"

if [ -f "$BIN_DIR/trueaegis-web" ]; then
    echo "  $BIN_DIR/trueaegis-web"
fi

# -------------------------
# PATH handling
# -------------------------
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    warn "$BIN_DIR is not currently in your PATH."

    if [ -f "$HOME/.bashrc" ]; then
        if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc"; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
            success "Added ~/.local/bin to PATH in ~/.bashrc"
        fi
        warn "Run: source ~/.bashrc"
    else
        warn "Add this to your shell config:"
        echo 'export PATH="$HOME/.local/bin:$PATH"'
    fi
fi

echo ""
success "TrueAegis installation complete."
echo ""
echo "Configured paths:"
echo "  TRUEAEGIS_HOME=$TRUEAEGIS_HOME"
echo "  NETSNIPER_BASE=$NETSNIPER_BASE"
echo "  VENV_DIR=$VENV_DIR"
echo ""
echo "Run:"
echo "  trueaegis"
echo "  netsniper"
if [ -f "$BIN_DIR/trueaegis-web" ]; then
    echo "  trueaegis-web"
fi
echo ""
