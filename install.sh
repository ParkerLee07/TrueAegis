#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# =========================
# TrueAegis Installer
# Kali / Debian safe version
# =========================
#
# This installer avoids Kali's externally-managed Python restriction
# by creating a project-local virtual environment instead of installing
# packages into the system Python environment.

TRUEAEGIS_HOME="${TRUEAEGIS_HOME:-$HOME/TrueAegis}"
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
        return 1
    fi
}

copy_dir_if_exists() {
    local dir="$1"

    if [ -d "$dir" ]; then
        rm -rf "$TRUEAEGIS_HOME/$dir"
        cp -r "$dir" "$TRUEAEGIS_HOME/"
        success "Installed $dir/"
    else
        warn "$dir/ not found. Skipping."
    fi
}

copy_file_if_exists() {
    local file="$1"

    if [ -f "$file" ]; then
        cp "$file" "$TRUEAEGIS_HOME/"
        success "Installed $file"
    else
        warn "$file not found. Skipping."
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

if ! python3 -m venv --help >/dev/null 2>&1; then
    error "python3-venv is required."
    echo ""
    echo "Install it with:"
    echo "  sudo apt update"
    echo "  sudo apt install python3-venv"
    echo ""
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    warn "nmap not found. NetSniper scanning requires nmap."
    echo "Install with: sudo apt install nmap"
fi

if ! command -v jq >/dev/null 2>&1; then
    warn "jq not found. NetSniper analysis requires jq."
    echo "Install with: sudo apt install jq"
fi

mkdir -p "$TRUEAEGIS_HOME"
mkdir -p "$BIN_DIR"

for dir in reports validation_results workspace workspace/scans workspace/snapshots workspace/deltas web_logs; do
    mkdir -p "$TRUEAEGIS_HOME/$dir"
done

info "Creating Python virtual environment at $VENV_DIR"
python3 -m venv "$VENV_DIR"

info "Upgrading pip inside virtual environment"
"$VENV_DIR/bin/python" -m pip install --upgrade pip

if [ -f requirements.txt ]; then
    info "Installing Python dependencies into TrueAegis virtual environment"
    "$VENV_DIR/bin/python" -m pip install -r requirements.txt
else
    warn "requirements.txt not found. Installing default dependencies."
    "$VENV_DIR/bin/python" -m pip install rich flask reportlab
fi

copy_file_if_exists "trueaegis.py"
copy_file_if_exists "netsniper.sh"

if [ -f "$TRUEAEGIS_HOME/netsniper.sh" ]; then
    chmod +x "$TRUEAEGIS_HOME/netsniper.sh"
fi

copy_dir_if_exists "remediations"
copy_dir_if_exists "knowledge"
copy_dir_if_exists "intelligence"
copy_dir_if_exists "validators"
copy_dir_if_exists "web"

cat > "$BIN_DIR/trueaegis" <<EOF
#!/usr/bin/env bash
TRUEAEGIS_HOME="$TRUEAEGIS_HOME" "$VENV_DIR/bin/python" "$TRUEAEGIS_HOME/trueaegis.py" "\$@"
EOF

cat > "$BIN_DIR/trueaegis-web" <<EOF
#!/usr/bin/env bash
TRUEAEGIS_HOME="$TRUEAEGIS_HOME" "$VENV_DIR/bin/python" "$TRUEAEGIS_HOME/web/app.py" "\$@"
EOF

cat > "$BIN_DIR/netsniper" <<EOF
#!/usr/bin/env bash
bash "$TRUEAEGIS_HOME/netsniper.sh" "\$@"
EOF

chmod +x "$BIN_DIR/trueaegis"
chmod +x "$BIN_DIR/trueaegis-web"
chmod +x "$BIN_DIR/netsniper"

success "Created launchers:"
echo "  $BIN_DIR/trueaegis"
echo "  $BIN_DIR/trueaegis-web"
echo "  $BIN_DIR/netsniper"

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
echo "Run:"
echo "  trueaegis"
echo "  trueaegis-web"
echo "  netsniper"
echo ""
echo "Python dependencies were installed safely into:"
echo "  $VENV_DIR"
echo ""
