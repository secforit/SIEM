#!/usr/bin/env bash
# =============================================================================
# CIS Benchmark Hardening Script for Debian-based Systems
# Targets: Debian 11/12, Ubuntu 22.04/24.04
#
# This script FIRST assesses the running system (services, configs, ports,
# architecture, PAM style, firewall, MAC framework, etc.) and then adapts
# every hardening step to exactly what it discovers.
# =============================================================================
set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
err()    { echo -e "${RED}[-]${NC} $*"; }
info()   { echo -e "${CYAN}[i]${NC} $*"; }
header() { echo -e "\n${BOLD}═══ $* ═══${NC}"; }

# --- Pre-flight ---
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
fi

if ! grep -qiE 'debian|ubuntu' /etc/os-release 2>/dev/null; then
    err "This script targets Debian-based systems only."
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# =============================================================================
# CONFIGURATION — edit these before running
# =============================================================================
SSH_USER="razvan"
SSH_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGCDu9Lzk5qZmWhCx18Eoklirj19R50tDlEU/hhrZTIE razvan@Mac"

echo ""
echo "============================================================"
echo "  CIS Benchmark Hardening — Debian/Ubuntu"
echo "  Phase 0 : System Assessment (read-only, no changes yet)"
echo "============================================================"
echo ""

# #############################################################################
#
#  PHASE 0 — FULL SYSTEM ASSESSMENT
#  Detects everything dynamically before touching a single file.
#
# #############################################################################

# ---- 0.1 : OS detection ----
header "0.1  Operating System"
DISTRO_ID=$(. /etc/os-release && echo "$ID")
DISTRO_VERSION=$(. /etc/os-release && echo "$VERSION_ID")
DISTRO_CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME:-unknown}")
DISTRO_PRETTY=$(. /etc/os-release && echo "$PRETTY_NAME")
info "Distribution : ${DISTRO_PRETTY}"
info "ID / Version : ${DISTRO_ID} ${DISTRO_VERSION} (${DISTRO_CODENAME})"

# ---- 0.2 : Architecture (needed for audit rules: b32 vs b64) ----
header "0.2  Architecture"
ARCH=$(uname -m)
if [[ "$ARCH" == "x86_64" || "$ARCH" == "aarch64" ]]; then
    AUDIT_ARCH="b64"
else
    AUDIT_ARCH="b32"
fi
info "Kernel arch   : ${ARCH}"
info "Audit arch    : ${AUDIT_ARCH}"

# ---- 0.3 : Detect SSH service name ----
header "0.3  SSH Service Detection"
SSH_SERVICE=""
SSH_PORT=""
for candidate in ssh sshd openssh-server; do
    if systemctl list-unit-files "${candidate}.service" &>/dev/null; then
        SSH_SERVICE="${candidate}"
        break
    fi
done
if [[ -z "$SSH_SERVICE" ]]; then
    # Fallback: check if any sshd binary exists
    if command -v sshd &>/dev/null; then
        SSH_SERVICE="ssh"  # Debian default
    fi
fi
if [[ -z "$SSH_SERVICE" ]]; then
    warn "No SSH service found — openssh-server will be installed."
    SSH_SERVICE="ssh"  # Will be installed later
else
    info "SSH service   : ${SSH_SERVICE}.service"
    SSH_STATE=$(systemctl is-active "${SSH_SERVICE}" 2>/dev/null || echo "inactive")
    SSH_ENABLED=$(systemctl is-enabled "${SSH_SERVICE}" 2>/dev/null || echo "disabled")
    info "SSH state     : ${SSH_STATE} / ${SSH_ENABLED}"
fi

# Detect current SSH port from running config
if [[ -f /etc/ssh/sshd_config ]]; then
    SSH_PORT=$(grep -E '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
fi
# Check drop-in overrides too
if [[ -d /etc/ssh/sshd_config.d ]]; then
    DROPIN_PORT=$(grep -rE '^\s*Port\s+' /etc/ssh/sshd_config.d/ 2>/dev/null | awk '{print $2}' | tail -1)
    [[ -n "$DROPIN_PORT" ]] && SSH_PORT="$DROPIN_PORT"
fi
SSH_PORT="${SSH_PORT:-22}"
info "SSH port      : ${SSH_PORT}"

# Check if sshd_config supports Include (OpenSSH >= 8.2)
SSH_HAS_INCLUDE="no"
if sshd -T 2>/dev/null | grep -qi 'include'; then
    SSH_HAS_INCLUDE="yes"
elif grep -q "^Include" /etc/ssh/sshd_config 2>/dev/null; then
    SSH_HAS_INCLUDE="yes"
fi
info "sshd Include  : ${SSH_HAS_INCLUDE}"

# ---- 0.4 : Detect PAM configuration style ----
header "0.4  PAM Configuration Style"
if [[ -f /etc/pam.d/common-auth ]]; then
    PAM_AUTH_FILE="/etc/pam.d/common-auth"
    PAM_PASSWD_FILE="/etc/pam.d/common-password"
    PAM_ACCOUNT_FILE="/etc/pam.d/common-account"
    PAM_SESSION_FILE="/etc/pam.d/common-session"
    PAM_STYLE="debian"
elif [[ -f /etc/pam.d/system-auth ]]; then
    PAM_AUTH_FILE="/etc/pam.d/system-auth"
    PAM_PASSWD_FILE="/etc/pam.d/system-auth"
    PAM_ACCOUNT_FILE="/etc/pam.d/system-auth"
    PAM_SESSION_FILE="/etc/pam.d/system-auth"
    PAM_STYLE="redhat"
else
    PAM_AUTH_FILE=""
    PAM_STYLE="unknown"
fi
info "PAM style     : ${PAM_STYLE}"
info "PAM auth file : ${PAM_AUTH_FILE:-not found}"

# ---- 0.5 : Detect firewall ----
header "0.5  Firewall Detection"
FW_ENGINE="none"
if command -v ufw &>/dev/null; then
    FW_ENGINE="ufw"
    UFW_STATUS=$(ufw status 2>/dev/null | head -1 || echo "unknown")
    info "UFW found     : ${UFW_STATUS}"
elif command -v nft &>/dev/null; then
    FW_ENGINE="nftables"
    info "nftables found"
elif command -v iptables &>/dev/null; then
    FW_ENGINE="iptables"
    info "iptables found"
fi
info "Firewall      : ${FW_ENGINE}"

# ---- 0.6 : Detect MAC framework (AppArmor vs SELinux) ----
header "0.6  Mandatory Access Control"
MAC_FRAMEWORK="none"
if command -v apparmor_status &>/dev/null; then
    MAC_FRAMEWORK="apparmor"
    AA_STATUS=$(apparmor_status 2>/dev/null | head -1 || echo "unknown")
    info "AppArmor      : ${AA_STATUS}"
elif command -v getenforce &>/dev/null; then
    MAC_FRAMEWORK="selinux"
    SE_STATUS=$(getenforce 2>/dev/null || echo "unknown")
    info "SELinux       : ${SE_STATUS}"
fi
info "MAC framework : ${MAC_FRAMEWORK}"

# ---- 0.7 : Detect auth log path ----
header "0.7  Auth Log Detection"
if [[ -f /var/log/auth.log ]]; then
    AUTH_LOG="/var/log/auth.log"
elif [[ -f /var/log/secure ]]; then
    AUTH_LOG="/var/log/secure"
else
    AUTH_LOG="/var/log/auth.log"  # default for Debian
fi
info "Auth log      : ${AUTH_LOG}"

# ---- 0.8 : Listening ports & running services ----
header "0.8  Listening Ports"
if command -v ss &>/dev/null; then
    LISTENING_PORTS=$(ss -tlnp 2>/dev/null)
elif command -v netstat &>/dev/null; then
    LISTENING_PORTS=$(netstat -tlnp 2>/dev/null)
else
    LISTENING_PORTS="(ss/netstat not available)"
fi
echo "${LISTENING_PORTS}" | while IFS= read -r line; do
    info "  ${line}"
done

# ---- 0.9 : Active services inventory ----
header "0.9  Active Services"
declare -A DETECTED_SERVICES
KNOWN_SERVICES=(
    ssh sshd openssh-server
    apache2 nginx lighttpd
    mysql mariadb postgresql redis-server mongodb mongod
    docker containerd
    cups avahi-daemon rpcbind nfs-server nfs-common
    vsftpd proftpd pure-ftpd
    smbd nmbd
    snmpd
    squid
    dovecot postfix exim4 sendmail
    named bind9
    xinetd
    telnet rsh-server talk tftp
    fail2ban
    ufw
    auditd
    apparmor
    cron atd
    rsyslog syslog-ng
)

ACTIVE_LIST=""
ENABLED_LIST=""
for svc in "${KNOWN_SERVICES[@]}"; do
    STATE=$(systemctl is-active "${svc}" 2>/dev/null || echo "inactive")
    ENABLED=$(systemctl is-enabled "${svc}" 2>/dev/null || echo "unknown")
    if [[ "$STATE" == "active" ]]; then
        DETECTED_SERVICES["${svc}"]="active/${ENABLED}"
        ACTIVE_LIST="${ACTIVE_LIST}  ${GREEN}●${NC} ${svc} (${ENABLED})\n"
    elif [[ "$ENABLED" == "enabled" ]]; then
        DETECTED_SERVICES["${svc}"]="inactive/${ENABLED}"
        ENABLED_LIST="${ENABLED_LIST}  ${YELLOW}○${NC} ${svc} (enabled but not running)\n"
    fi
done

if [[ -n "$ACTIVE_LIST" ]]; then
    echo -e "${ACTIVE_LIST}"
fi
if [[ -n "$ENABLED_LIST" ]]; then
    echo -e "${ENABLED_LIST}"
fi

# ---- 0.10 : Existing config files check ----
header "0.10 Existing Configuration Files"
CONFIG_FILES=(
    /etc/ssh/sshd_config
    /etc/ssh/sshd_config.d
    /etc/fail2ban/jail.local
    /etc/fail2ban/jail.conf
    /etc/ufw/ufw.conf
    /etc/security/pwquality.conf
    /etc/security/faillock.conf
    /etc/login.defs
    /etc/audit/auditd.conf
    /etc/audit/rules.d
    /etc/sudoers
    /etc/sudoers.d
    /etc/sysctl.conf
    /etc/sysctl.d
    /etc/modprobe.d
    /etc/apparmor.d
    /etc/issue.net
    /etc/pam.d/common-auth
    /etc/pam.d/system-auth
    /etc/pam.d/su
)
for cf in "${CONFIG_FILES[@]}"; do
    if [[ -e "$cf" ]]; then
        if [[ -d "$cf" ]]; then
            COUNT=$(ls -1 "$cf" 2>/dev/null | wc -l)
            info "  [dir]  ${cf}/ (${COUNT} files)"
        else
            SIZE=$(stat -c%s "$cf" 2>/dev/null || echo "?")
            info "  [file] ${cf} (${SIZE} bytes)"
        fi
    fi
done

# ---- 0.11 : Check for existing hardening ----
header "0.11 Previous Hardening Detection"
ALREADY_HARDENED=()
[[ -f /etc/ssh/sshd_config.d/00-cis-hardening.conf ]] && ALREADY_HARDENED+=("SSH drop-in")
[[ -f /etc/sysctl.d/99-cis-hardening.conf ]] && ALREADY_HARDENED+=("sysctl")
[[ -f /etc/modprobe.d/cis-hardening.conf ]] && ALREADY_HARDENED+=("modprobe")
[[ -f /etc/audit/rules.d/cis-hardening.rules ]] && ALREADY_HARDENED+=("audit rules")
[[ -f /etc/sudoers.d/cis-hardening ]] && ALREADY_HARDENED+=("sudoers")
[[ -f /etc/security/limits.d/cis-hardening.conf ]] && ALREADY_HARDENED+=("limits")

if [[ ${#ALREADY_HARDENED[@]} -gt 0 ]]; then
    warn "Previous CIS hardening detected — will overwrite:"
    for item in "${ALREADY_HARDENED[@]}"; do
        warn "  - ${item}"
    done
else
    info "No previous CIS hardening detected — clean slate."
fi

# ---- 0.12 : Build the safe-to-disable services list ----
# Only target services that are actually present AND are considered insecure / unnecessary
header "0.12 Services Marked for Disabling"
SERVICES_TO_DISABLE=()
INSECURE_CANDIDATES=(
    avahi-daemon cups rpcbind nfs-server nfs-common
    vsftpd proftpd pure-ftpd
    dovecot smbd nmbd snmpd squid
    xinetd telnet rsh-server talk tftp
)
for svc in "${INSECURE_CANDIDATES[@]}"; do
    STATE=$(systemctl is-active "${svc}" 2>/dev/null || echo "inactive")
    ENABLED=$(systemctl is-enabled "${svc}" 2>/dev/null || echo "unknown")
    if [[ "$STATE" == "active" || "$ENABLED" == "enabled" ]]; then
        SERVICES_TO_DISABLE+=("${svc}")
        warn "  Will disable: ${svc} (${STATE}/${ENABLED})"
    fi
done
if [[ ${#SERVICES_TO_DISABLE[@]} -eq 0 ]]; then
    info "  No insecure services found running — nothing to disable."
fi

# =============================================================================
# ASSESSMENT SUMMARY
# =============================================================================
header "ASSESSMENT SUMMARY"
echo ""
info "OS              : ${DISTRO_PRETTY}"
info "Architecture    : ${ARCH} (audit: ${AUDIT_ARCH})"
info "SSH service     : ${SSH_SERVICE} on port ${SSH_PORT}"
info "SSH Include     : ${SSH_HAS_INCLUDE}"
info "PAM style       : ${PAM_STYLE} (${PAM_AUTH_FILE:-n/a})"
info "Firewall        : ${FW_ENGINE}"
info "MAC framework   : ${MAC_FRAMEWORK}"
info "Auth log        : ${AUTH_LOG}"
info "Services to kill: ${#SERVICES_TO_DISABLE[@]}"
echo ""

# Prompt user before proceeding
read -rp "$(echo -e "${YELLOW}[?]${NC} Proceed with hardening based on the above assessment? [y/N]: ")" CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    info "Aborted by user. No changes were made."
    exit 0
fi

# =============================================================================
# Create backup directory
# =============================================================================
BACKUP_DIR="/root/pre-hardening-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${BACKUP_DIR}"
info "Backups saved to: ${BACKUP_DIR}"
echo ""

# #############################################################################
#
#  PHASE 1 — HARDENING (uses all detected values from Phase 0)
#
# #############################################################################

# =============================================================================
# 1. SYSTEM UPDATES & PACKAGE INSTALLATION
# =============================================================================
header "1. System Updates & Package Installation"

PACKAGES_TO_INSTALL=(
    unattended-upgrades
    apt-listchanges
    auditd
    audispd-plugins
    libpam-pwquality
    aide
    rkhunter
    acl
)

# Only install ufw if that's our firewall engine (or no firewall yet)
if [[ "$FW_ENGINE" == "ufw" || "$FW_ENGINE" == "none" ]]; then
    PACKAGES_TO_INSTALL+=(ufw)
fi

# Only install fail2ban if not already present
command -v fail2ban-client &>/dev/null || PACKAGES_TO_INSTALL+=(fail2ban)

# Only install openssh-server if SSH service was missing
if ! systemctl list-unit-files "${SSH_SERVICE}.service" &>/dev/null 2>&1; then
    PACKAGES_TO_INSTALL+=(openssh-server)
fi

# Install AppArmor if that's our MAC (or none detected)
if [[ "$MAC_FRAMEWORK" == "apparmor" || "$MAC_FRAMEWORK" == "none" ]]; then
    PACKAGES_TO_INSTALL+=(apparmor apparmor-utils)
fi

apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq "${PACKAGES_TO_INSTALL[@]}" > /dev/null 2>&1
log "Packages installed: ${PACKAGES_TO_INSTALL[*]}"

# Re-detect SSH service after potential install
if [[ -z "$SSH_SERVICE" ]] || ! systemctl list-unit-files "${SSH_SERVICE}.service" &>/dev/null 2>&1; then
    for candidate in ssh sshd openssh-server; do
        if systemctl list-unit-files "${candidate}.service" &>/dev/null 2>&1; then
            SSH_SERVICE="${candidate}"
            break
        fi
    done
fi
info "SSH service (confirmed): ${SSH_SERVICE}"

# Re-detect firewall engine after potential install
if [[ "$FW_ENGINE" == "none" ]] && command -v ufw &>/dev/null; then
    FW_ENGINE="ufw"
    info "Firewall engine (now): ufw"
fi

# Re-detect MAC framework after potential install
if [[ "$MAC_FRAMEWORK" == "none" ]] && command -v apparmor_status &>/dev/null; then
    MAC_FRAMEWORK="apparmor"
    info "MAC framework (now): apparmor"
fi

# =============================================================================
# 2. USER ACCOUNT & SSH KEY SETUP
# =============================================================================
header "2. User Account & SSH Key Setup"

if ! id "${SSH_USER}" &>/dev/null; then
    useradd -m -s /bin/bash -G sudo "${SSH_USER}"
    log "User '${SSH_USER}' created and added to sudo group."
else
    usermod -aG sudo "${SSH_USER}"
    log "User '${SSH_USER}' already exists — ensured sudo membership."
fi

USER_SSH_DIR="/home/${SSH_USER}/.ssh"
mkdir -p "${USER_SSH_DIR}"
echo "${SSH_PUBKEY}" > "${USER_SSH_DIR}/authorized_keys"
chown -R "${SSH_USER}:${SSH_USER}" "${USER_SSH_DIR}"
chmod 700 "${USER_SSH_DIR}"
chmod 600 "${USER_SSH_DIR}/authorized_keys"
log "SSH public key installed for '${SSH_USER}'."

# =============================================================================
# 3. SSH HARDENING (CIS 5.2)
# =============================================================================
header "3. SSH Hardening (CIS 5.2)"

# Backup
cp /etc/ssh/sshd_config "${BACKUP_DIR}/sshd_config.orig"
[[ -d /etc/ssh/sshd_config.d ]] && cp -r /etc/ssh/sshd_config.d "${BACKUP_DIR}/sshd_config.d.orig" || true

if [[ "$SSH_HAS_INCLUDE" == "yes" ]]; then
    # ---- FILE: /etc/ssh/sshd_config.d/00-cis-hardening.conf ----
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/00-cis-hardening.conf << EOF
# =============================================================================
# /etc/ssh/sshd_config.d/00-cis-hardening.conf
# CIS Benchmark SSH Hardening
# Detected service: ${SSH_SERVICE}  |  Port: ${SSH_PORT}
# =============================================================================

# --- Protocol (CIS 5.2.4) ---
Protocol 2

# --- Listen ---
Port ${SSH_PORT}

# --- Authentication (CIS 5.2.5-5.2.10) ---
PermitRootLogin no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes

# --- Limit auth attempts & timeouts (CIS 5.2.17-5.2.20) ---
MaxAuthTries 3
LoginGraceTime 60
MaxSessions 4
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Disable insecure features (CIS 5.2.11-5.2.12) ---
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
DisableForwarding yes
GatewayPorts no
PermitTunnel no

# --- Logging (CIS 5.2.3-5.2.4) ---
LogLevel VERBOSE
SyslogFacility AUTH

# --- Strong cryptography (CIS 5.2.13-5.2.15) ---
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# --- Restrict access to specific user ---
AllowUsers ${SSH_USER}

# --- Warning banner (CIS 1.7.1) ---
Banner /etc/issue.net
EOF
    info "  Wrote: /etc/ssh/sshd_config.d/00-cis-hardening.conf"

    # Ensure Include directive exists at top of main config
    if ! grep -q "^Include /etc/ssh/sshd_config.d/" /etc/ssh/sshd_config; then
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
    fi
else
    # No Include support — patch sshd_config directly
    warn "sshd_config does not support Include — patching main config directly."
    # Append hardened settings (they override earlier values in OpenSSH)
    cat >> /etc/ssh/sshd_config << EOF

# === CIS Benchmark SSH Hardening (appended by harden.sh) ===
Protocol 2
Port ${SSH_PORT}
PermitRootLogin no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
MaxAuthTries 3
LoginGraceTime 60
MaxSessions 4
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
GatewayPorts no
PermitTunnel no
LogLevel VERBOSE
SyslogFacility AUTH
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
AllowUsers ${SSH_USER}
Banner /etc/issue.net
EOF
    info "  Updated: /etc/ssh/sshd_config (appended)"
fi

# ---- FILE: /etc/issue.net ----
cat > /etc/issue.net << 'EOF'
***************************************************************************
                       AUTHORIZED ACCESS ONLY
  This system is for authorized users only. All activity is monitored
  and logged. Unauthorized access is prohibited and will be prosecuted
  to the fullest extent of the law.
***************************************************************************
EOF
cp /etc/issue.net /etc/issue
info "  Wrote: /etc/issue.net"
info "  Wrote: /etc/issue"

# Fix SSH file permissions (CIS 5.2.1-5.2.3)
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
find /etc/ssh -name 'ssh_host_*_key' -exec chmod 600 {} \; 2>/dev/null || true
find /etc/ssh -name 'ssh_host_*_key.pub' -exec chmod 644 {} \; 2>/dev/null || true

# Validate & restart
if sshd -t 2>/dev/null; then
    systemctl restart "${SSH_SERVICE}"
    log "SSH daemon hardened and restarted (service: ${SSH_SERVICE})."
else
    err "SSH config validation FAILED."
    err "Restoring backup..."
    cp "${BACKUP_DIR}/sshd_config.orig" /etc/ssh/sshd_config
    if [[ -d "${BACKUP_DIR}/sshd_config.d.orig" ]]; then
        rm -rf /etc/ssh/sshd_config.d
        cp -r "${BACKUP_DIR}/sshd_config.d.orig" /etc/ssh/sshd_config.d
    fi
    systemctl restart "${SSH_SERVICE}"
    err "SSH restored to previous config. Fix issues and re-run."
    exit 1
fi

# =============================================================================
# 4. FIREWALL (CIS 3.5)
# =============================================================================
header "4. Firewall (CIS 3.5) — engine: ${FW_ENGINE}"

if [[ "$FW_ENGINE" == "ufw" ]]; then
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed
    ufw allow "${SSH_PORT}/tcp" comment 'SSH'
    ufw limit "${SSH_PORT}/tcp" comment 'SSH rate-limit'

    # If any web servers are detected running, open their ports
    for websvc in apache2 nginx lighttpd; do
        if [[ "${DETECTED_SERVICES[$websvc]+_}" ]] && [[ "${DETECTED_SERVICES[$websvc]}" == active/* ]]; then
            ufw allow 80/tcp comment "${websvc} HTTP"
            ufw allow 443/tcp comment "${websvc} HTTPS"
            warn "  Opened ports 80/443 for detected service: ${websvc}"
        fi
    done

    ufw --force enable
    ufw reload
    log "UFW firewall configured — SSH (port ${SSH_PORT}) allowed + rate-limited."

elif [[ "$FW_ENGINE" == "nftables" ]]; then
    warn "nftables detected — skipping UFW. Ensure nftables rules restrict inbound."
    warn "Minimum: allow SSH (${SSH_PORT}/tcp), deny everything else inbound."

elif [[ "$FW_ENGINE" == "iptables" ]]; then
    warn "iptables detected — skipping UFW. Ensure iptables rules restrict inbound."
    warn "Minimum: allow SSH (${SSH_PORT}/tcp), deny everything else inbound."
fi

# =============================================================================
# 5. FAIL2BAN — Brute-force Protection
# =============================================================================
header "5. Fail2Ban Configuration"

[[ -f /etc/fail2ban/jail.local ]] && cp /etc/fail2ban/jail.local "${BACKUP_DIR}/jail.local.orig" || true

# ---- FILE: /etc/fail2ban/jail.local ----
cat > /etc/fail2ban/jail.local << EOF
# =============================================================================
# /etc/fail2ban/jail.local
# Fail2Ban — SSH brute-force protection
# Detected: service=${SSH_SERVICE}, port=${SSH_PORT}, log=${AUTH_LOG}
# =============================================================================

[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
banaction = ${FW_ENGINE}
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = ${AUTH_LOG}
maxretry = 3
bantime  = 3600
EOF
info "  Wrote: /etc/fail2ban/jail.local"
info "  (using banaction=${FW_ENGINE}, logpath=${AUTH_LOG})"

systemctl enable fail2ban --now > /dev/null 2>&1
systemctl restart fail2ban
log "Fail2Ban enabled."

# =============================================================================
# 6. KERNEL / NETWORK HARDENING (CIS 3.1-3.3)
# =============================================================================
header "6. Kernel & Network Hardening (CIS 3.1-3.3)"

# ---- FILE: /etc/sysctl.d/99-cis-hardening.conf ----
cat > /etc/sysctl.d/99-cis-hardening.conf << 'EOF'
# =============================================================================
# /etc/sysctl.d/99-cis-hardening.conf
# CIS Benchmark — Kernel & Network Hardening
# =============================================================================

# --- Disable IP forwarding (CIS 3.1.1) ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# --- Disable source routing (CIS 3.2.1) ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- Disable ICMP redirects (CIS 3.2.2-3.2.3) ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# --- Log martian packets (CIS 3.2.4) ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Ignore ICMP broadcast requests (CIS 3.2.5) ---
net.ipv4.icmp_echo_ignore_broadcasts = 1

# --- Ignore bogus ICMP errors (CIS 3.2.6) ---
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Reverse path filtering (CIS 3.2.7) ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- TCP SYN cookies (CIS 3.2.8) ---
net.ipv4.tcp_syncookies = 1

# --- Disable IPv6 router advertisements (CIS 3.2.9) ---
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- Restrict dmesg (CIS 1.5.2) ---
kernel.dmesg_restrict = 1

# --- Hide kernel pointers (CIS 1.5.3) ---
kernel.kptr_restrict = 2

# --- ASLR full randomization (CIS 1.5.1) ---
kernel.randomize_va_space = 2

# --- Restrict ptrace (CIS 1.5.4) ---
kernel.yama.ptrace_scope = 2

# --- Disable SUID core dumps (CIS 1.5.5) ---
fs.suid_dumpable = 0

# --- Restrict unprivileged BPF ---
kernel.unprivileged_bpf_disabled = 1

# --- Restrict unprivileged user namespaces ---
kernel.unprivileged_userns_clone = 0

# --- Restrict perf_event ---
kernel.perf_event_paranoid = 3
EOF
info "  Wrote: /etc/sysctl.d/99-cis-hardening.conf"

# Check if Docker is running — if so, warn about ip_forward
if [[ "${DETECTED_SERVICES[docker]+_}" ]] && [[ "${DETECTED_SERVICES[docker]}" == active/* ]]; then
    warn "Docker is running — ip_forward=0 will break container networking!"
    warn "Overriding: net.ipv4.ip_forward will remain at 1 for Docker."
    sed -i 's/^net.ipv4.ip_forward = 0/# net.ipv4.ip_forward = 0  # SKIPPED — Docker detected/' /etc/sysctl.d/99-cis-hardening.conf
fi

sysctl --system > /dev/null 2>&1
log "Kernel and network parameters applied."

# =============================================================================
# 7. DISABLE UNNECESSARY SERVICES (CIS 2.1-2.2)
# =============================================================================
header "7. Disable Unnecessary Services (CIS 2.1-2.2)"

if [[ ${#SERVICES_TO_DISABLE[@]} -gt 0 ]]; then
    for svc in "${SERVICES_TO_DISABLE[@]}"; do
        systemctl stop "${svc}" 2>/dev/null || true
        systemctl disable "${svc}" 2>/dev/null || true
        systemctl mask "${svc}" 2>/dev/null || true
        warn "  Stopped, disabled, masked: ${svc}"
    done
    log "Disabled ${#SERVICES_TO_DISABLE[@]} unnecessary service(s)."
else
    info "No unnecessary services to disable."
fi

# ---- FILE: /etc/modprobe.d/cis-hardening.conf ----
cat > /etc/modprobe.d/cis-hardening.conf << 'EOF'
# =============================================================================
# /etc/modprobe.d/cis-hardening.conf
# CIS Benchmark — Disable uncommon protocols & filesystems (CIS 3.4, 1.1.1)
# =============================================================================

# --- Uncommon network protocols (CIS 3.4) ---
install dccp /bin/true
blacklist dccp
install sctp /bin/true
blacklist sctp
install rds /bin/true
blacklist rds
install tipc /bin/true
blacklist tipc

# --- Uncommon filesystems (CIS 1.1.1) ---
install cramfs /bin/true
blacklist cramfs
install freevxfs /bin/true
blacklist freevxfs
install hfs /bin/true
blacklist hfs
install hfsplus /bin/true
blacklist hfsplus
install jffs2 /bin/true
blacklist jffs2
install squashfs /bin/true
blacklist squashfs
install udf /bin/true
blacklist udf
EOF
info "  Wrote: /etc/modprobe.d/cis-hardening.conf"

# ---- FILE: /etc/modprobe.d/usb-storage.conf ----
cat > /etc/modprobe.d/usb-storage.conf << 'EOF'
# =============================================================================
# /etc/modprobe.d/usb-storage.conf
# Disable USB mass storage
# =============================================================================
blacklist usb-storage
install usb-storage /bin/true
EOF
info "  Wrote: /etc/modprobe.d/usb-storage.conf"

log "Kernel modules blacklisted."

# =============================================================================
# 8. FILESYSTEM HARDENING (CIS 1.1)
# =============================================================================
header "8. Filesystem Hardening (CIS 1.1)"

cp /etc/fstab "${BACKUP_DIR}/fstab.orig" 2>/dev/null || true

for mp in /tmp /var/tmp /dev/shm; do
    if findmnt "$mp" > /dev/null 2>&1; then
        FSTAB_LINE=$(grep " ${mp} " /etc/fstab 2>/dev/null || true)
        if [[ -n "$FSTAB_LINE" ]] && ! echo "$FSTAB_LINE" | grep -q 'noexec'; then
            sed -i "s|\(.*\s${mp}\s.*defaults\)|\1,nodev,nosuid,noexec|" /etc/fstab
            warn "  Updated ${mp} mount options (nodev,nosuid,noexec)."
        else
            info "  ${mp} — already hardened or not in fstab."
        fi
    else
        info "  ${mp} — not a separate mount."
    fi
done

# Sticky bit on world-writable directories (CIS 1.1.21)
df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | while read -r dir; do
    find "${dir}" -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -exec chmod a+t {} \; 2>/dev/null || true
done

log "Filesystem hardened."

# =============================================================================
# 9. PASSWORD & AUTH POLICIES (CIS 5.3-5.4)
# =============================================================================
header "9. Password & Authentication Policies (CIS 5.3-5.4)"

[[ -f /etc/security/pwquality.conf ]] && cp /etc/security/pwquality.conf "${BACKUP_DIR}/pwquality.conf.orig"
cp /etc/login.defs "${BACKUP_DIR}/login.defs.orig"

# ---- FILE: /etc/security/pwquality.conf ----
cat > /etc/security/pwquality.conf << 'EOF'
# =============================================================================
# /etc/security/pwquality.conf
# CIS Benchmark — Password Quality Policy (CIS 5.3.1)
# =============================================================================
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
maxclassrepeat = 3
gecoscheck = 1
enforce_for_root
EOF
info "  Wrote: /etc/security/pwquality.conf"

# /etc/login.defs (CIS 5.4.1)
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   3/' /etc/login.defs
sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   60/' /etc/login.defs
info "  Updated: /etc/login.defs"

useradd -D -f 30 2>/dev/null || true
log "Password policies configured."

# =============================================================================
# 10. PAM HARDENING (CIS 5.3)
# =============================================================================
header "10. PAM Hardening (CIS 5.3) — style: ${PAM_STYLE}"

if [[ -n "$PAM_AUTH_FILE" && -f "$PAM_AUTH_FILE" ]]; then
    cp "${PAM_AUTH_FILE}" "${BACKUP_DIR}/$(basename ${PAM_AUTH_FILE}).orig"
    [[ -f "$PAM_PASSWD_FILE" ]] && cp "${PAM_PASSWD_FILE}" "${BACKUP_DIR}/$(basename ${PAM_PASSWD_FILE}).passwd.orig"

    # ---- FILE: /etc/security/faillock.conf ----
    cat > /etc/security/faillock.conf << 'EOF'
# =============================================================================
# /etc/security/faillock.conf
# CIS Benchmark — Account lockout (CIS 5.3.2)
# =============================================================================
deny = 5
fail_interval = 900
unlock_time = 600
even_deny_root
root_unlock_time = 60
audit
EOF
    info "  Wrote: /etc/security/faillock.conf"

    # Add pam_faillock to auth stack (only if not already present)
    if ! grep -q 'pam_faillock' "${PAM_AUTH_FILE}" 2>/dev/null; then
        sed -i '/^auth.*pam_unix.so/i auth    required    pam_faillock.so preauth' "${PAM_AUTH_FILE}"
        sed -i '/^auth.*pam_unix.so/a auth    [default=die] pam_faillock.so authfail' "${PAM_AUTH_FILE}"
        info "  Updated: ${PAM_AUTH_FILE} (pam_faillock)"
    else
        info "  pam_faillock already in ${PAM_AUTH_FILE} — skipped."
    fi

    # Add pam_pwquality to password stack
    if [[ -f "$PAM_PASSWD_FILE" ]] && ! grep -q 'pam_pwquality' "${PAM_PASSWD_FILE}" 2>/dev/null; then
        sed -i '/^password.*pam_unix.so/i password    requisite    pam_pwquality.so retry=3' "${PAM_PASSWD_FILE}"
        info "  Updated: ${PAM_PASSWD_FILE} (pam_pwquality)"
    else
        info "  pam_pwquality already in ${PAM_PASSWD_FILE:-n/a} — skipped."
    fi
else
    warn "PAM auth file not found — skipping PAM hardening."
fi

log "PAM configuration hardened."

# =============================================================================
# 11. AUDIT FRAMEWORK (CIS 4.1)
# =============================================================================
header "11. Audit Framework (CIS 4.1) — arch: ${AUDIT_ARCH}"

# ---- FILE: /etc/audit/rules.d/cis-hardening.rules ----
cat > /etc/audit/rules.d/cis-hardening.rules << EOF
# =============================================================================
# /etc/audit/rules.d/cis-hardening.rules
# CIS Benchmark — Audit Rules (arch: ${AUDIT_ARCH})
# =============================================================================

-D
-b 8192
-f 1

# --- Time changes (CIS 4.1.3) ---
-a always,exit -F arch=${AUDIT_ARCH} -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=${AUDIT_ARCH} -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# --- User/group changes (CIS 4.1.4) ---
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# --- Network config changes (CIS 4.1.5) ---
-a always,exit -F arch=${AUDIT_ARCH} -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# --- MAC policy changes (CIS 4.1.6) ---
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# --- Login/logout events (CIS 4.1.7) ---
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# --- Session initiation (CIS 4.1.8) ---
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# --- Permission changes (CIS 4.1.9) ---
-a always,exit -F arch=${AUDIT_ARCH} -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=${AUDIT_ARCH} -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=${AUDIT_ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# --- Unauthorized file access (CIS 4.1.10) ---
-a always,exit -F arch=${AUDIT_ARCH} -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=${AUDIT_ARCH} -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# --- File deletion (CIS 4.1.12) ---
-a always,exit -F arch=${AUDIT_ARCH} -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# --- Sudoers changes (CIS 4.1.13) ---
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# --- Sudo log (CIS 4.1.14) ---
-w /var/log/sudo.log -p wa -k actions

# --- Kernel module loading (CIS 4.1.15) ---
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=${AUDIT_ARCH} -S init_module -S delete_module -k modules

# --- SSH config changes ---
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# --- Firewall config changes ---
-w /etc/ufw/ -p wa -k firewall

# --- Cron changes ---
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron

# --- Immutable (MUST be last) ---
-e 2
EOF
info "  Wrote: /etc/audit/rules.d/cis-hardening.rules"

# Generate SUID/SGID rules (CIS 4.1.11)
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | while read -r prog; do
    echo "-a always,exit -F path=${prog} -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"
done >> /etc/audit/rules.d/cis-hardening.rules

# ---- Patch /etc/audit/auditd.conf ----
if [[ -f /etc/audit/auditd.conf ]]; then
    cp /etc/audit/auditd.conf "${BACKUP_DIR}/auditd.conf.orig"
    sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
    sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
    sed -i 's/^action_mail_acct.*/action_mail_acct = root/' /etc/audit/auditd.conf
    sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf
    info "  Updated: /etc/audit/auditd.conf"
fi

systemctl enable auditd --now > /dev/null 2>&1
augenrules --load > /dev/null 2>&1 || true
log "Audit rules loaded."

# =============================================================================
# 12. SUDO HARDENING (CIS 5.2)
# =============================================================================
header "12. Sudo Hardening"

# ---- FILE: /etc/sudoers.d/cis-hardening ----
cat > /etc/sudoers.d/cis-hardening << 'EOF'
# =============================================================================
# /etc/sudoers.d/cis-hardening
# CIS Benchmark — Sudo Hardening
# =============================================================================
Defaults    use_pty
Defaults    logfile="/var/log/sudo.log"
Defaults    log_input, log_output
Defaults    passwd_timeout=1
Defaults    timestamp_timeout=5
Defaults    env_reset
Defaults    mail_badpass
EOF
chmod 440 /etc/sudoers.d/cis-hardening
info "  Wrote: /etc/sudoers.d/cis-hardening"

if visudo -c > /dev/null 2>&1; then
    log "Sudo configuration validated."
else
    err "Sudoers validation FAILED — removing custom config."
    rm -f /etc/sudoers.d/cis-hardening
fi

# =============================================================================
# 13. FILE PERMISSIONS (CIS 6.1)
# =============================================================================
header "13. Critical File Permissions (CIS 6.1)"

chown root:root /etc/passwd   && chmod 644 /etc/passwd
chown root:root /etc/group    && chmod 644 /etc/group
chown root:shadow /etc/shadow  && chmod 640 /etc/shadow
chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow
chown root:root /etc/passwd-  && chmod 600 /etc/passwd-  2>/dev/null || true
chown root:root /etc/group-   && chmod 600 /etc/group-   2>/dev/null || true
chown root:shadow /etc/shadow-  && chmod 600 /etc/shadow-  2>/dev/null || true
chown root:shadow /etc/gshadow- && chmod 600 /etc/gshadow- 2>/dev/null || true

for f in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    [[ -e "$f" ]] && chown root:root "$f" && chmod og-rwx "$f"
done

# ---- FILE: /etc/cron.allow ----
echo "root" > /etc/cron.allow && chmod 640 /etc/cron.allow
info "  Wrote: /etc/cron.allow"

# ---- FILE: /etc/at.allow ----
echo "root" > /etc/at.allow && chmod 640 /etc/at.allow
info "  Wrote: /etc/at.allow"

rm -f /etc/cron.deny /etc/at.deny
log "File permissions set."

# =============================================================================
# 14. AUTOMATIC SECURITY UPDATES (CIS 1.9)
# =============================================================================
header "14. Automatic Security Updates (CIS 1.9)"

# ---- FILE: /etc/apt/apt.conf.d/50unattended-upgrades ----
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// =============================================================================
// /etc/apt/apt.conf.d/50unattended-upgrades
// CIS Benchmark — Automatic Security Updates
// =============================================================================
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
info "  Wrote: /etc/apt/apt.conf.d/50unattended-upgrades"

# ---- FILE: /etc/apt/apt.conf.d/20auto-upgrades ----
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
// =============================================================================
// /etc/apt/apt.conf.d/20auto-upgrades
// =============================================================================
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
info "  Wrote: /etc/apt/apt.conf.d/20auto-upgrades"

log "Automatic security updates enabled."

# =============================================================================
# 15. MANDATORY ACCESS CONTROL (CIS 1.6)
# =============================================================================
header "15. Mandatory Access Control (CIS 1.6) — ${MAC_FRAMEWORK}"

if [[ "$MAC_FRAMEWORK" == "apparmor" ]]; then
    systemctl enable apparmor --now > /dev/null 2>&1 || true
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    log "AppArmor enabled and profiles enforced."
elif [[ "$MAC_FRAMEWORK" == "selinux" ]]; then
    info "SELinux detected — ensure it is in Enforcing mode."
    info "Current mode: $(getenforce 2>/dev/null || echo 'unknown')"
else
    warn "No MAC framework detected — AppArmor was installed above."
    systemctl enable apparmor --now > /dev/null 2>&1 || true
    log "AppArmor freshly enabled."
fi

# =============================================================================
# 16. AIDE — FILE INTEGRITY MONITORING (CIS 1.3)
# =============================================================================
header "16. AIDE File Integrity Monitoring (CIS 1.3)"

if command -v aide &>/dev/null; then
    aideinit > /dev/null 2>&1 || aide --init > /dev/null 2>&1 || true
    [[ -f /var/lib/aide/aide.db.new ]] && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

    # ---- FILE: /etc/cron.daily/aide-check ----
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
# =============================================================================
# /etc/cron.daily/aide-check
# Daily AIDE file integrity check
# =============================================================================
LOGFILE="/var/log/aide/aide-check-$(date +%Y%m%d).log"
mkdir -p /var/log/aide
/usr/bin/aide --check > "${LOGFILE}" 2>&1
if [[ $? -ne 0 ]]; then
    echo "AIDE detected changes — see ${LOGFILE}" | \
        /usr/bin/mail -s "AIDE ALERT - $(hostname) - $(date +%F)" root 2>/dev/null || true
fi
EOF
    chmod 700 /etc/cron.daily/aide-check
    info "  Wrote: /etc/cron.daily/aide-check"
    log "AIDE initialized."
else
    warn "AIDE binary not found — skipping."
fi

# =============================================================================
# 17. MISCELLANEOUS HARDENING
# =============================================================================
header "17. Miscellaneous Hardening"

# ---- FILE: /etc/security/limits.d/cis-hardening.conf ----
cat > /etc/security/limits.d/cis-hardening.conf << 'EOF'
# =============================================================================
# /etc/security/limits.d/cis-hardening.conf
# CIS Benchmark — Disable core dumps (CIS 1.5)
# =============================================================================
*    hard    core    0
*    soft    core    0
EOF
info "  Wrote: /etc/security/limits.d/cis-hardening.conf"

# ---- FILE: /etc/sysctl.d/99-coredump.conf ----
cat > /etc/sysctl.d/99-coredump.conf << 'EOF'
fs.suid_dumpable = 0
EOF
sysctl -w fs.suid_dumpable=0 > /dev/null 2>&1
info "  Wrote: /etc/sysctl.d/99-coredump.conf"

# Restrict su to sudo group (CIS 5.6)
if [[ -f /etc/pam.d/su ]]; then
    cp /etc/pam.d/su "${BACKUP_DIR}/pam.d-su.orig"
    if ! grep -q 'pam_wheel.so.*use_uid.*group=sudo' /etc/pam.d/su 2>/dev/null; then
        sed -i '/pam_rootok.so/a auth required pam_wheel.so use_uid group=sudo' /etc/pam.d/su
        info "  Updated: /etc/pam.d/su (restricted to sudo group)"
    fi
fi

# Lock accounts with empty passwords
awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | while read -r user; do
    [[ -n "$user" ]] && passwd -l "$user" 2>/dev/null && warn "  Locked empty-password account: ${user}"
done

# ---- FILE: /etc/securetty ----
cat > /etc/securetty << 'EOF'
# =============================================================================
# /etc/securetty — Restrict root to physical console
# =============================================================================
console
tty1
EOF
info "  Wrote: /etc/securetty"

# ---- FILE: /etc/profile.d/cis-timeout.sh ----
cat > /etc/profile.d/cis-timeout.sh << 'EOF'
# Auto-logout idle shell sessions (15 min)
readonly TMOUT=900
export TMOUT
EOF
info "  Wrote: /etc/profile.d/cis-timeout.sh"

# ---- FILE: /etc/profile.d/cis-umask.sh ----
cat > /etc/profile.d/cis-umask.sh << 'EOF'
# Enforce default umask (CIS 5.4.4)
umask 027
EOF
info "  Wrote: /etc/profile.d/cis-umask.sh"

log "Miscellaneous hardening applied."

# =============================================================================
# 18. LOCK DOWN ROOT
# =============================================================================
header "18. Lock Down Root Account"
passwd -l root 2>/dev/null || true
log "Root password locked — use 'sudo' from '${SSH_USER}'."

# =============================================================================
# 19. VERIFY SSH SERVICE
# =============================================================================
header "19. Final SSH Service Verification"
systemctl enable "${SSH_SERVICE}" > /dev/null 2>&1
if systemctl is-active --quiet "${SSH_SERVICE}"; then
    log "Service '${SSH_SERVICE}' is ACTIVE and ENABLED."
else
    err "Service '${SSH_SERVICE}' is NOT RUNNING — investigate immediately!"
fi

# =============================================================================
# FINAL SUMMARY
# =============================================================================
echo ""
echo "============================================================"
echo "  HARDENING COMPLETE"
echo "============================================================"
echo ""
info "System assessed:"
echo "  OS              : ${DISTRO_PRETTY}"
echo "  Architecture    : ${ARCH} (${AUDIT_ARCH})"
echo "  SSH service     : ${SSH_SERVICE} (port ${SSH_PORT})"
echo "  PAM style       : ${PAM_STYLE}"
echo "  Firewall        : ${FW_ENGINE}"
echo "  MAC framework   : ${MAC_FRAMEWORK}"
echo "  Auth log        : ${AUTH_LOG}"
echo ""
info "Configuration files created/updated:"
echo ""
echo "  SSH:"
if [[ "$SSH_HAS_INCLUDE" == "yes" ]]; then
echo "    /etc/ssh/sshd_config.d/00-cis-hardening.conf  [CREATED]"
else
echo "    /etc/ssh/sshd_config                          [PATCHED]"
fi
echo "    /etc/issue.net                                [CREATED]"
echo "    /etc/issue                                    [CREATED]"
echo ""
echo "  Firewall & Intrusion Prevention:"
echo "    /etc/fail2ban/jail.local                      [CREATED]"
echo "    UFW rules                                     [APPLIED]"
echo ""
echo "  Kernel & Network:"
echo "    /etc/sysctl.d/99-cis-hardening.conf           [CREATED]"
echo "    /etc/sysctl.d/99-coredump.conf                [CREATED]"
echo "    /etc/modprobe.d/cis-hardening.conf            [CREATED]"
echo "    /etc/modprobe.d/usb-storage.conf              [CREATED]"
echo ""
echo "  Authentication & Passwords:"
echo "    /etc/security/pwquality.conf                  [CREATED]"
echo "    /etc/security/faillock.conf                   [CREATED]"
echo "    /etc/login.defs                               [PATCHED]"
echo "    ${PAM_AUTH_FILE:-/etc/pam.d/common-auth}      [PATCHED]"
echo "    ${PAM_PASSWD_FILE:-/etc/pam.d/common-password}[PATCHED]"
echo "    /etc/pam.d/su                                 [PATCHED]"
echo ""
echo "  Audit:"
echo "    /etc/audit/rules.d/cis-hardening.rules        [CREATED]"
echo "    /etc/audit/auditd.conf                        [PATCHED]"
echo ""
echo "  Sudo:"
echo "    /etc/sudoers.d/cis-hardening                  [CREATED]"
echo ""
echo "  Automatic Updates:"
echo "    /etc/apt/apt.conf.d/50unattended-upgrades     [CREATED]"
echo "    /etc/apt/apt.conf.d/20auto-upgrades           [CREATED]"
echo ""
echo "  Access Control:"
echo "    /etc/cron.allow                               [CREATED]"
echo "    /etc/at.allow                                 [CREATED]"
echo "    /etc/securetty                                [CREATED]"
echo ""
echo "  Shell Profiles:"
echo "    /etc/profile.d/cis-timeout.sh                 [CREATED]"
echo "    /etc/profile.d/cis-umask.sh                   [CREATED]"
echo ""
echo "  Integrity Monitoring:"
echo "    /etc/cron.daily/aide-check                    [CREATED]"
echo ""
echo "  Backups:"
echo "    ${BACKUP_DIR}/"
echo ""
warn "════════════════════ CRITICAL ════════════════════"
warn "DO NOT close this session until you verify access!"
echo ""
echo "  1. Open a NEW terminal:"
echo "     ssh ${SSH_USER}@<server-ip> -p ${SSH_PORT}"
echo ""
echo "  2. Verify sudo:"
echo "     sudo whoami    (should print: root)"
echo ""
echo "  3. If it fails, use THIS session to fix it."
warn "══════════════════════════════════════════════════"
echo ""
warn "Reboot recommended to apply all kernel parameters."