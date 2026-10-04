#!/usr/bin/env bash
#
# CloudGate 2.0 — 1-Click Installer
# Installs CloudGate and sets up the global `cloudgate` CLI command.
#

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "============================================================"
echo "         CloudGate 2.0 — Deployment & Setup Script          "
echo "============================================================"
echo -e "${NC}"

# 1. Check Python 3
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[ERROR] Python 3 is required but not installed.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}[✓] Detected Python ${PYTHON_VERSION}${NC}"

# 2. Check Pip
if ! command -v pip3 &>/dev/null && ! command -v pip &>/dev/null; then
    echo -e "${RED}[ERROR] pip is required. Please install python3-pip.${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 3. Install CloudGate and dependencies
echo -e "\n${CYAN}[*] Installing CloudGate package & dependencies (Rich, Boto3, Prowler)...${NC}"
pip3 install -e . --break-system-packages --no-build-isolation 2>/dev/null || \
pip install -e . --no-build-isolation 2>/dev/null || \
pip install -e .

LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"

# 4. Verify CLI command
echo -e "\n${CYAN}[*] Verifying installation...${NC}"
if command -v cloudgate &>/dev/null; then
    echo -e "${GREEN}[✓] 'cloudgate' CLI is successfully installed and globally accessible!${NC}"
else
    ln -sf "$SCRIPT_DIR/cloudgate.py" "$LOCAL_BIN/cloudgate"
    chmod +x "$LOCAL_BIN/cloudgate"
    echo -e "${GREEN}[✓] Linked 'cloudgate' into $LOCAL_BIN/cloudgate${NC}"
fi

# Check PATH
if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
    echo -e "\n${YELLOW}[!] Note: $LOCAL_BIN is not currently in your active PATH.${NC}"
    echo -e "    Add it permanently by running:"
    echo -e "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
fi

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}  🎉 CloudGate 2.0 is Ready to Use!                         ${NC}"
echo -e "${GREEN}============================================================${NC}"
echo -e "Run anywhere in your terminal:"
echo -e "  ${CYAN}cloudgate${NC}                 # Fast pre-logout gate (~3s)"
echo -e "  ${CYAN}cloudgate --hybrid${NC}        # Fast Gate + Prowler Deep Audit"
echo -e "  ${CYAN}cloudgate -i${NC}              # Interactive security level menu"
echo -e "  ${CYAN}cloudgate --compliance cis_3.0_aws${NC} # CIS Benchmark 3.0"
echo ""
