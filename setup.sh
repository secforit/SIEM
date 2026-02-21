#!/bin/bash
# ============================================================
# SecForIT SIEM Platform - Setup Script
# Run this ONCE on your control machine before deploying
# ============================================================
set -euo pipefail

echo "╔══════════════════════════════════════════════════════╗"
echo "║  SecForIT SIEM Platform - Initial Setup              ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# --- Check prerequisites ---
echo "[1/5] Checking prerequisites..."

if ! command -v ansible &> /dev/null; then
    echo "  Installing Ansible..."
    sudo apt update
    sudo apt install -y software-properties-common
    sudo add-apt-repository --yes ppa:ansible/ansible
    sudo apt update
    sudo apt install -y ansible
else
    echo "  Ansible already installed: $(ansible --version | head -1)"
fi

if ! command -v git &> /dev/null; then
    echo "  Installing git..."
    sudo apt install -y git
fi

# --- Install Ansible collections ---
echo ""
echo "[2/5] Installing Ansible Galaxy collections and roles..."
ansible-galaxy collection install -r requirements.yml --force
ansible-galaxy role install -r requirements.yml --force

# --- Install required Python packages ---
echo ""
echo "[3/5] Installing Python dependencies..."
pip3 install --break-system-packages passlib jmespath 2>/dev/null || \
pip3 install passlib jmespath 2>/dev/null || true

# --- Validate configuration ---
echo ""
echo "[4/5] Validating Ansible configuration..."
ansible-playbook site.yml --syntax-check

# --- Generate SSH key if needed ---
echo ""
echo "[5/5] Checking SSH keys..."
if [ ! -f "$HOME/.ssh/id_ed25519" ]; then
    echo "  Generating SSH key..."
    ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N ""
    echo "  Key generated at: $HOME/.ssh/id_ed25519.pub"
else
    echo "  SSH key already exists."
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Setup complete!                                     ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  BEFORE deploying, update these files:               ║"
echo "║                                                      ║"
echo "║  1. group_vars/all.yml                               ║"
echo "║     - Change ALL 'CHANGE_ME_*' passwords             ║"
echo "║     - Set your SSH allowed users                     ║"
echo "║     - Verify domain/subdomain settings               ║"
echo "║                                                      ║"
echo "║  2. inventory.yml                                    ║"
echo "║     - Set your server IP address                     ║"
echo "║     - Remove 'ansible_connection: local' for remote  ║"
echo "║                                                      ║"
echo "║  3. DNS: Create A records for:                       ║"
echo "║     - siem.secforit.ro     -> your server IP         ║"
echo "║     - grafana.secforit.ro  -> your server IP         ║"
echo "║     - prometheus.secforit.ro -> your server IP       ║"
echo "║                                                      ║"
echo "║  Then run:                                           ║"
echo "║    ansible-playbook site.yml                         ║"
echo "║                                                      ║"
echo "╚══════════════════════════════════════════════════════╝"
