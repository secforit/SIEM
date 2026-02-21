#!/bin/bash
# ============================================================
# SecForIT SIEM Platform - One-Command Deploy Script
# ============================================================
# Run this from your LOCAL machine (where Ansible is installed).
# It handles everything: bootstrap check, dependencies, deploy.
#
# Usage:
#   ./deploy.sh                  # Full deployment
#   ./deploy.sh --tags wazuh     # Deploy only Wazuh
#   ./deploy.sh --check          # Dry run
#   ./deploy.sh --bootstrap-only # Only bootstrap the remote
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

SERVER_IP="37.27.94.252"
SSH_USER="razvan"
SSH_KEY="$HOME/.ssh/razvan"
EXTRA_ARGS="${*}"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  SecForIT SIEM Platform - Deployment                 ║"
echo "║  Target: ${SSH_USER}@${SERVER_IP}                    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ============================================================
# PHASE 1: Local prerequisites
# ============================================================
info "Phase 1: Checking local prerequisites..."

# Check Ansible
if ! command -v ansible &>/dev/null; then
    log "Installing Ansible on local machine..."
    if [[ "$(uname)" == "Darwin" ]]; then
        brew install ansible
    elif [[ -f /etc/debian_version ]]; then
        sudo apt update
        sudo apt install -y software-properties-common
        sudo add-apt-repository --yes ppa:ansible/ansible
        sudo apt update
        sudo apt install -y ansible
    elif [[ -f /etc/redhat-release ]]; then
        sudo dnf install -y ansible
    else
        err "Cannot auto-install Ansible. Please install it manually."
    fi
fi
log "Ansible: $(ansible --version | head -1)"

# Check SSH key
if [ ! -f "$SSH_KEY" ]; then
    err "SSH key not found at $SSH_KEY. Please check the path."
fi
log "SSH key: $SSH_KEY"

# Install Ansible Galaxy dependencies
log "Installing Ansible Galaxy collections..."
ansible-galaxy collection install -r requirements.yml --force 2>/dev/null || true
ansible-galaxy role install -r requirements.yml --force 2>/dev/null || true

# Install Python deps
log "Installing Python dependencies..."
pip3 install --break-system-packages passlib jmespath 2>/dev/null || \
pip3 install passlib jmespath 2>/dev/null || true

# ============================================================
# PHASE 2: Bootstrap remote server
# ============================================================
if [[ "$EXTRA_ARGS" != *"--skip-bootstrap"* ]]; then
    info "Phase 2: Bootstrapping remote server..."

    # Test SSH connectivity first
    log "Testing SSH connectivity to ${SERVER_IP}..."
    if ssh -i "$SSH_KEY" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
        "${SSH_USER}@${SERVER_IP}" "echo 'SSH OK'" 2>/dev/null; then
        log "SSH connection successful"
    else
        err "Cannot SSH to ${SSH_USER}@${SERVER_IP}. Check your SSH key and server access."
    fi

    # Check if Python3 exists on remote (indicates bootstrap already done)
    if ssh -i "$SSH_KEY" "${SSH_USER}@${SERVER_IP}" "python3 --version" 2>/dev/null; then
        log "Remote server already bootstrapped (Python3 found)"
    else
        log "Running bootstrap script on remote server..."
        ssh -i "$SSH_KEY" "${SSH_USER}@${SERVER_IP}" 'bash -s' < bootstrap-remote.sh
        log "Bootstrap complete"
    fi

    if [[ "$EXTRA_ARGS" == *"--bootstrap-only"* ]]; then
        log "Bootstrap-only mode. Exiting."
        exit 0
    fi
fi

# ============================================================
# PHASE 3: Ansible connectivity test
# ============================================================
info "Phase 3: Testing Ansible connectivity..."
if ansible siem-server -m ping --one-line 2>/dev/null | grep -q "SUCCESS"; then
    log "Ansible ping: SUCCESS"
else
    warn "Ansible ping failed. Trying with password auth..."
    ansible siem-server -m ping --one-line --ask-pass 2>/dev/null || \
        err "Cannot reach server via Ansible. Check inventory.yml and SSH config."
fi

# ============================================================
# PHASE 4: Syntax check
# ============================================================
info "Phase 4: Validating playbook syntax..."
ansible-playbook site.yml --syntax-check
log "Syntax check passed"

# ============================================================
# PHASE 5: Deploy
# ============================================================
info "Phase 5: Deploying SecForIT SIEM Platform..."
echo ""

# Build ansible-playbook command
ANSIBLE_CMD="ansible-playbook site.yml -v"

# Pass through any extra args (--tags, --check, --diff, etc.)
for arg in $EXTRA_ARGS; do
    case "$arg" in
        --skip-bootstrap|--bootstrap-only)
            # Our custom flags, don't pass to ansible
            ;;
        *)
            ANSIBLE_CMD="$ANSIBLE_CMD $arg"
            ;;
    esac
done

log "Running: $ANSIBLE_CMD"
echo ""

# Run the playbook
eval "$ANSIBLE_CMD"

RESULT=$?

echo ""
if [ $RESULT -eq 0 ]; then
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  Deployment Successful!                              ║"
    echo "╠══════════════════════════════════════════════════════╣"
    echo "║                                                      ║"
    echo "║  DNS Records needed (point to 37.27.94.252):         ║"
    echo "║    siem.secforit.ro                                  ║"
    echo "║    grafana.secforit.ro                               ║"
    echo "║    prometheus.secforit.ro                             ║"
    echo "║                                                      ║"
    echo "║  Once DNS propagates, access:                        ║"
    echo "║    https://siem.secforit.ro                          ║"
    echo "║    https://grafana.secforit.ro                       ║"
    echo "║    https://prometheus.secforit.ro                    ║"
    echo "║                                                      ║"
    echo "╚══════════════════════════════════════════════════════╝"
else
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  Deployment FAILED (exit code: $RESULT)              ║"
    echo "║  Check the output above for errors.                  ║"
    echo "║  Re-run with: ./deploy.sh -vvv                       ║"
    echo "╚══════════════════════════════════════════════════════╝"
    exit $RESULT
fi
