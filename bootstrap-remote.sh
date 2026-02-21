#!/bin/bash
# ============================================================
# SecForIT SIEM Platform - Remote Server Bootstrap
# ============================================================
# This script runs ON the Hetzner server (37.27.94.252) to
# prepare it for Ansible deployment. It installs all
# prerequisites so Ansible can connect and manage it.
#
# Usage (from your local machine):
#   ssh razvan@37.27.94.252 'bash -s' < bootstrap-remote.sh
#
# Or copy and run directly on the server:
#   scp bootstrap-remote.sh razvan@37.27.94.252:~
#   ssh razvan@37.27.94.252 'chmod +x ~/bootstrap-remote.sh && sudo ~/bootstrap-remote.sh'
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

# Must run as root or with sudo
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &>/dev/null; then
        log "Re-running with sudo..."
        exec sudo bash "$0" "$@"
    else
        err "This script must be run as root or with sudo"
    fi
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  SecForIT SIEM - Remote Server Bootstrap             ║"
echo "║  Target: $(hostname) ($(hostname -I | awk '{print $1}'))          "
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# --- 1. System update ---
log "[1/8] Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

# --- 2. Install Python3 (required for Ansible) ---
log "[2/8] Installing Python3 and pip..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-apt \
    python3-venv \
    python3-setuptools \
    python3-passlib

# --- 3. Install essential packages ---
log "[3/8] Installing essential packages..."
apt-get install -y -qq \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    software-properties-common \
    wget \
    unzip \
    tar \
    gzip \
    jq \
    net-tools \
    acl \
    sudo \
    openssh-server \
    snapd

# --- 4. Ensure SSH is running ---
log "[4/8] Configuring SSH..."
systemctl enable ssh
systemctl start ssh

# --- 5. Configure sudo for razvan (passwordless for Ansible) ---
log "[5/8] Configuring sudo for razvan..."
if id "razvan" &>/dev/null; then
    usermod -aG sudo razvan
    # Allow passwordless sudo for Ansible
    if [ ! -f /etc/sudoers.d/razvan ]; then
        echo "razvan ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/razvan
        chmod 440 /etc/sudoers.d/razvan
        log "  Passwordless sudo configured for razvan"
    else
        warn "  /etc/sudoers.d/razvan already exists"
    fi
else
    warn "  User 'razvan' does not exist. Creating..."
    adduser --disabled-password --gecos "Razvan" razvan
    usermod -aG sudo razvan
    echo "razvan ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/razvan
    chmod 440 /etc/sudoers.d/razvan
    # Setup SSH key directory
    mkdir -p /home/razvan/.ssh
    chmod 700 /home/razvan/.ssh
    chown razvan:razvan /home/razvan/.ssh
    log "  User razvan created. Add your SSH public key to /home/razvan/.ssh/authorized_keys"
fi

# --- 6. Setup SSH authorized_keys if not present ---
log "[6/8] Checking SSH keys for razvan..."
RAZVAN_SSH="/home/razvan/.ssh/authorized_keys"
if [ ! -f "$RAZVAN_SSH" ] || [ ! -s "$RAZVAN_SSH" ]; then
    warn "  No SSH authorized_keys found for razvan!"
    warn "  After this script, run from your LOCAL machine:"
    warn "    ssh-copy-id -i ~/.ssh/razvan.pub razvan@37.27.94.252"
    # Ensure directory exists
    mkdir -p /home/razvan/.ssh
    touch "$RAZVAN_SSH"
    chmod 600 "$RAZVAN_SSH"
    chmod 700 /home/razvan/.ssh
    chown -R razvan:razvan /home/razvan/.ssh
else
    log "  SSH authorized_keys exists for razvan"
fi

# --- 7. Configure firewall basics (Ansible will manage UFW fully later) ---
log "[7/8] Pre-configuring firewall..."
if command -v ufw &>/dev/null; then
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp comment "SSH"
    ufw allow 80/tcp comment "HTTP"
    ufw allow 443/tcp comment "HTTPS"
    ufw allow 1514/tcp comment "Wazuh Agent"
    ufw allow 1515/tcp comment "Wazuh Registration"
    ufw --force enable
    log "  UFW configured and enabled"
else
    apt-get install -y -qq ufw
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 1514/tcp
    ufw allow 1515/tcp
    ufw --force enable
    log "  UFW installed and configured"
fi

# --- 8. Set vm.max_map_count for Wazuh Indexer ---
log "[8/8] Setting kernel parameters for Wazuh..."
sysctl -w vm.max_map_count=262144
if ! grep -q "vm.max_map_count" /etc/sysctl.conf; then
    echo "vm.max_map_count=262144" >> /etc/sysctl.conf
fi

# --- Summary ---
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Bootstrap Complete!                                 ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  Server: $(hostname -I | awk '{print $1}')                          "
echo "║  OS:     $(lsb_release -ds)                          "
echo "║  RAM:    $(free -h | awk '/Mem:/{print $2}')                                  "
echo "║  Python: $(python3 --version)                        "
echo "║  User:   razvan (sudo NOPASSWD)                      ║"
echo "║  SSH:    port 22 (enabled)                           ║"
echo "║  UFW:    enabled (22,80,443,1514,1515)               ║"
echo "║                                                      ║"
echo "║  Next steps:                                         ║"
echo "║  1. Copy SSH key (from local machine):               ║"
echo "║     ssh-copy-id -i ~/.ssh/razvan.pub \\               ║"
echo "║       razvan@37.27.94.252                            ║"
echo "║                                                      ║"
echo "║  2. Test Ansible connectivity (from local machine):  ║"
echo "║     ansible siem-server -m ping                      ║"
echo "║                                                      ║"
echo "║  3. Run deployment (from local machine):             ║"
echo "║     ./deploy.sh                                      ║"
echo "║                                                      ║"
echo "╚══════════════════════════════════════════════════════╝"
