#!/bin/bash
# ============================================================
# SecForIT SIEM Platform - Install & Deploy (run as root)
# ============================================================
# This single script installs everything on the Hetzner server:
#   1. Creates 'razvan' user with sudo + SSH key
#   2. Installs Ansible + all dependencies
#   3. Clones the repo
#   4. Runs the full playbook locally
#
# Usage:
#   curl -sL <raw-url> | bash
#   OR
#   bash install-and-deploy.sh
#   bash install-and-deploy.sh --tags wazuh    # single role
#   bash install-and-deploy.sh --check         # dry run
# ============================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

EXTRA_ARGS=""
for arg in "$@"; do
    case "$arg" in
        --tags|--skip-tags|--check|--diff|-v|-vv|-vvv)
            EXTRA_ARGS="$EXTRA_ARGS $arg"
            ;;
        *)
            EXTRA_ARGS="$EXTRA_ARGS $arg"
            ;;
    esac
done

# --- Must be root ---
if [ "$EUID" -ne 0 ]; then
    err "This script must be run as root. Run: sudo bash install-and-deploy.sh"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     SecForIT SIEM Platform - Full Install & Deploy       ║"
echo "║     Server: $(hostname -I | awk '{print $1}') | $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY | cut -d= -f2 | tr -d '"')  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
# PHASE 1: System prerequisites
# ============================================================
info "PHASE 1/6: Installing system prerequisites..."

apt-get update -qq
apt-get install -y -qq \
    software-properties-common \
    python3 \
    python3-pip \
    python3-apt \
    python3-venv \
    python3-setuptools \
    python3-passlib \
    python3-jmespath \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    wget \
    unzip \
    tar \
    gzip \
    jq \
    net-tools \
    acl \
    sudo \
    openssh-server \
    snapd \
    git \
    apache2-utils

log "System prerequisites installed"

# ============================================================
# PHASE 2: Create 'razvan' user
# ============================================================
info "PHASE 2/6: Setting up user 'razvan'..."

if ! id "razvan" &>/dev/null; then
    adduser --disabled-password --gecos "Razvan Lisman" razvan
    log "User 'razvan' created"
else
    log "User 'razvan' already exists"
fi

usermod -aG sudo razvan

# Passwordless sudo for Ansible
echo "razvan ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/razvan
chmod 440 /etc/sudoers.d/razvan

# Setup SSH directory
mkdir -p /home/razvan/.ssh
chmod 700 /home/razvan/.ssh
touch /home/razvan/.ssh/authorized_keys
chmod 600 /home/razvan/.ssh/authorized_keys
chown -R razvan:razvan /home/razvan/.ssh

log "User 'razvan' configured with sudo NOPASSWD"
warn "Remember to add your SSH public key to /home/razvan/.ssh/authorized_keys"

# ============================================================
# PHASE 3: Install Ansible
# ============================================================
info "PHASE 3/6: Installing Ansible..."

if ! command -v ansible &>/dev/null; then
    add-apt-repository --yes ppa:ansible/ansible
    apt-get update -qq
    apt-get install -y -qq ansible
    log "Ansible installed: $(ansible --version | head -1)"
else
    log "Ansible already installed: $(ansible --version | head -1)"
fi

# Install Python deps
pip3 install --break-system-packages passlib jmespath 2>/dev/null || \
pip3 install passlib jmespath 2>/dev/null || true

log "Python dependencies installed"

# ============================================================
# PHASE 4: Clone/update repository
# ============================================================
info "PHASE 4/6: Setting up project from GitHub..."

DEPLOY_DIR="/opt/secforit-siem"

if [ -d "$DEPLOY_DIR/.git" ]; then
    log "Repository exists, pulling latest..."
    cd "$DEPLOY_DIR"
    git pull origin main || warn "Git pull failed, using existing code"
else
    log "Cloning repository..."
    git clone https://github.com/secforit/SIEM.git "$DEPLOY_DIR" || {
        # If SSH clone fails, try HTTPS
        warn "Clone failed. If repo is private, configure git credentials."
        warn "Trying with SSH..."
        git clone git@github.com:secforit/SIEM.git "$DEPLOY_DIR" || {
            err "Cannot clone repo. Push the code to GitHub first:
  cd 'Hardening Code'
  git add -A && git commit -m 'update' && git push origin main"
        }
    }
    cd "$DEPLOY_DIR"
fi

log "Project directory: $DEPLOY_DIR"

# ============================================================
# PHASE 5: Install Ansible Galaxy dependencies
# ============================================================
info "PHASE 5/6: Installing Ansible Galaxy collections..."

cd "$DEPLOY_DIR"

ansible-galaxy collection install -r requirements.yml --force 2>&1 | tail -5
ansible-galaxy role install -r requirements.yml --force 2>&1 | tail -5

log "Ansible collections and roles installed"

# ============================================================
# PHASE 6: Run Ansible playbook
# ============================================================
info "PHASE 6/6: Running Ansible playbook..."
echo ""

cd "$DEPLOY_DIR"

# Syntax check first
ansible-playbook site.yml --syntax-check || err "Syntax check failed!"
log "Syntax check passed"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Starting full deployment... This will take 15-30 min    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Run the playbook
ANSIBLE_CMD="ansible-playbook site.yml -v $EXTRA_ARGS"
log "Running: $ANSIBLE_CMD"
echo ""

eval "$ANSIBLE_CMD"
RESULT=$?

echo ""
if [ $RESULT -eq 0 ]; then
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          SecForIT SIEM - Deployment Complete!            ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║                                                          ║"
    echo "║  Create DNS A records pointing to 37.27.94.252:          ║"
    echo "║    siem.secforit.ro      -> 37.27.94.252                 ║"
    echo "║    grafana.secforit.ro   -> 37.27.94.252                 ║"
    echo "║    prometheus.secforit.ro -> 37.27.94.252                ║"
    echo "║                                                          ║"
    echo "║  Access (after DNS propagates):                          ║"
    echo "║    https://siem.secforit.ro      (Wazuh Dashboard)       ║"
    echo "║    https://grafana.secforit.ro   (Grafana)               ║"
    echo "║    https://prometheus.secforit.ro (Prometheus)            ║"
    echo "║                                                          ║"
    echo "║  Credentials:                                            ║"
    echo "║    Wazuh:      admin / (see group_vars/all.yml)          ║"
    echo "║    Grafana:    admin / (see group_vars/all.yml)          ║"
    echo "║    Prometheus: admin / (see nginx-proxy defaults)        ║"
    echo "║                                                          ║"
    echo "║  SSH: razvan@37.27.94.252                                ║"
    echo "║  Add your pubkey: /home/razvan/.ssh/authorized_keys      ║"
    echo "║                                                          ║"
    echo "║  Project dir: /opt/secforit-siem                         ║"
    echo "║  Re-run: cd /opt/secforit-siem && bash install-and-deploy.sh ║"
    echo "║                                                          ║"
    echo "╚══════════════════════════════════════════════════════════╝"
else
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  Deployment FAILED (exit code: $RESULT)                  ║"
    echo "║  Check output above. Re-run with more verbosity:         ║"
    echo "║    bash install-and-deploy.sh -vvv                       ║"
    echo "║                                                          ║"
    echo "║  Or run a single role:                                   ║"
    echo "║    bash install-and-deploy.sh --tags hardening            ║"
    echo "║    bash install-and-deploy.sh --tags wazuh                ║"
    echo "║    bash install-and-deploy.sh --tags prometheus            ║"
    echo "║    bash install-and-deploy.sh --tags grafana               ║"
    echo "║    bash install-and-deploy.sh --tags nginx                 ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    exit $RESULT
fi
