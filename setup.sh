#!/bin/bash
# ============================================================
# SecForIT SIEM Platform - Local Setup Script
# Run this ONCE on your LOCAL machine (macOS/Linux) to
# install Ansible and dependencies before deploying.
#
# For a one-command deployment, use deploy.sh instead.
# ============================================================
set -euo pipefail

echo "╔══════════════════════════════════════════════════════╗"
echo "║  SecForIT SIEM Platform - Local Setup                ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# --- Check prerequisites ---
echo "[1/4] Checking prerequisites..."

if ! command -v ansible &> /dev/null; then
    echo "  Installing Ansible..."
    if [[ "$(uname)" == "Darwin" ]]; then
        brew install ansible
    else
        sudo apt update
        sudo apt install -y software-properties-common
        sudo add-apt-repository --yes ppa:ansible/ansible
        sudo apt update
        sudo apt install -y ansible
    fi
else
    echo "  Ansible already installed: $(ansible --version | head -1)"
fi

if ! command -v git &> /dev/null; then
    ec
    ho "  Installing git..."
    sudo apt install -y git 2>/dev/null || brew install git 2>/dev/null
fi

# --- Install Ansible collections ---
echo ""
echo "[2/4] Installing Ansible Galaxy collections and roles..."
ansible-galaxy collection install -r requirements.yml --force
ansible-galaxy role install -r requirements.yml --force

# --- Install required Python packages ---
echo ""
echo "[3/4] Installing Python dependencies..."
pip3 install --break-system-packages passlib jmespath 2>/dev/null || \
pip3 install passlib jmespath 2>/dev/null || true

# --- Validate configuration ---
echo ""
echo "[4/4] Validating Ansible configuration..."
ansible-playbook site.yml --syntax-check

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Setup complete!                                     ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  Server: 37.27.94.252 (Hetzner, 8GB RAM)            ║"
echo "║  User:   razvan                                      ║"
echo "║  SSH:    ~/.ssh/razvan                               ║"
echo "║                                                      ║"
echo "║  DNS: Create A records pointing to 37.27.94.252:     ║"
echo "║    siem.secforit.ro                                  ║"
echo "║    grafana.secforit.ro                               ║"
echo "║    prometheus.secforit.ro                             ║"
echo "║                                                      ║"
echo "║  Deploy:                                             ║"
echo "║    ./deploy.sh                                       ║"
echo "║                                                      ║"
echo "║  Or step-by-step:                                    ║"
echo "║    1. Bootstrap remote:                              ║"
echo "║       ssh razvan@37.27.94.252 'bash -s' \\            ║"
echo "║         < bootstrap-remote.sh                        ║"
echo "║    2. Deploy:                                        ║"
echo "║       ansible-playbook site.yml                      ║"
echo "║                                                      ║"
echo "╚══════════════════════════════════════════════════════╝"
