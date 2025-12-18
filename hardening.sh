#!/bin/bash

# ==============================================================================
# LINUX HARDENING CHECKLIST SCRIPT
# STIG and Security Hardening Compliance Checker
# Supports: Ubuntu, Debian, RHEL, CentOS, and general Linux distributions
# ==============================================================================

# --- COLOR SETTINGS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- SETTINGS ---
REPORT_FILE="./hardening-report-$(date +%Y%m%d-%H%M%S).txt"
CHECK_COUNT=0
PASSED_COUNT=0
FAILED_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0

# Detect OS - Safe method without sourcing
detect_os() {
    OS_NAME="unknown"
    OS_VERSION="unknown"
    
    if [ -f /etc/os-release ]; then
        if [ -r /etc/os-release ]; then
            OS_NAME=$(grep "^ID=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' | head -1)
            OS_VERSION=$(grep "^VERSION_ID=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' | head -1)
            if [ -z "$OS_NAME" ]; then
                OS_NAME="unknown"
            fi
            if [ -z "$OS_VERSION" ]; then
                OS_VERSION="unknown"
            fi
        fi
    elif [ -f /etc/redhat-release ]; then
        OS_NAME="rhel"
        OS_VERSION=$(grep -oE '[0-9]+' /etc/redhat-release 2>/dev/null | head -1)
        if [ -z "$OS_VERSION" ]; then
            OS_VERSION="unknown"
        fi
    elif [ -f /etc/debian_version ]; then
        OS_NAME="debian"
        OS_VERSION=$(cat /etc/debian_version 2>/dev/null | head -1)
    fi
}

# Log result
log_result() {
    local status=$1
    local category=$2
    local check_name=$3
    local details=$4
    local recommendation=$5
    
    CHECK_COUNT=$((CHECK_COUNT + 1))
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $status in
        PASS)
            PASSED_COUNT=$((PASSED_COUNT + 1))
            echo -e "${GREEN}[✓] PASS${NC} - $check_name"
            echo "[$timestamp] [PASS] [$category] $check_name - $details" >> "$REPORT_FILE"
            ;;
        FAIL)
            FAILED_COUNT=$((FAILED_COUNT + 1))
            echo -e "${RED}[✗] FAIL${NC} - $check_name"
            echo -e "${RED}    Details: $details${NC}"
            if [ -n "$recommendation" ]; then
                echo -e "${YELLOW}    Recommendation: $recommendation${NC}"
            fi
            echo "[$timestamp] [FAIL] [$category] $check_name - $details | Recommendation: $recommendation" >> "$REPORT_FILE"
            ;;
        WARN)
            WARNING_COUNT=$((WARNING_COUNT + 1))
            echo -e "${YELLOW}[⚠] WARN${NC} - $check_name"
            echo -e "${YELLOW}    Details: $details${NC}"
            if [ -n "$recommendation" ]; then
                echo -e "${CYAN}    Recommendation: $recommendation${NC}"
            fi
            echo "[$timestamp] [WARN] [$category] $check_name - $details | Recommendation: $recommendation" >> "$REPORT_FILE"
            ;;
        INFO)
            INFO_COUNT=$((INFO_COUNT + 1))
            echo -e "${BLUE}[ℹ] INFO${NC} - $check_name"
            echo -e "${BLUE}    Details: $details${NC}"
            echo "[$timestamp] [INFO] [$category] $check_name - $details" >> "$REPORT_FILE"
            ;;
    esac
}

# Print section header
print_section() {
    echo -e "\n${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC} ${WHITE}$1${NC} ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
}

# Start
clear
echo -e "${RED}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║${NC} ${WHITE}LINUX HARDENING CHECKLIST - STIG COMPLIANCE CHECKER${NC} ${RED}║${NC}"
echo -e "${RED}║${NC} ${WHITE}Comprehensive Security Hardening Assessment${NC} ${RED}║${NC}"
echo -e "${RED}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"

detect_os
echo -e "${CYAN}Detected OS: $OS_NAME $OS_VERSION${NC}"
echo -e "${CYAN}Report File: $REPORT_FILE${NC}"
echo ""

# Initialize report
echo "=== LINUX HARDENING CHECKLIST REPORT ===" > "$REPORT_FILE"
echo "Date: $(date)" >> "$REPORT_FILE"
echo "OS: $OS_NAME $OS_VERSION" >> "$REPORT_FILE"
echo "Hostname: $(hostname)" >> "$REPORT_FILE"
echo "Kernel: $(uname -r)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

sleep 2

# ==============================================================================
# SECTION 1: SYSTEM INFORMATION
# ==============================================================================
print_section "SECTION 1: SYSTEM INFORMATION"

log_result "INFO" "System" "OS Distribution" "$OS_NAME $OS_VERSION" ""
log_result "INFO" "System" "Kernel Version" "$(uname -r)" ""
log_result "INFO" "System" "Hostname" "$(hostname)" ""
log_result "INFO" "System" "Uptime" "$(uptime -p 2>/dev/null || uptime)" ""

# ==============================================================================
# SECTION 2: FILE PERMISSIONS AND OWNERSHIP
# ==============================================================================
print_section "SECTION 2: FILE PERMISSIONS AND OWNERSHIP"

# Check /etc/passwd permissions
if [ -f /etc/passwd ]; then
    PASSWD_PERMS=$(stat -c "%a" /etc/passwd 2>/dev/null || stat -f "%OLp" /etc/passwd 2>/dev/null)
    if [ "$PASSWD_PERMS" = "644" ]; then
        log_result "PASS" "File Permissions" "/etc/passwd permissions" "Correct (644)" ""
    else
        log_result "FAIL" "File Permissions" "/etc/passwd permissions" "Current: $PASSWD_PERMS (should be 644)" "chmod 644 /etc/passwd"
    fi
fi

# Check /etc/shadow permissions
if [ -f /etc/shadow ]; then
    SHADOW_PERMS=$(stat -c "%a" /etc/shadow 2>/dev/null || stat -f "%OLp" /etc/shadow 2>/dev/null)
    if [ "$SHADOW_PERMS" = "640" ] || [ "$SHADOW_PERMS" = "600" ]; then
        log_result "PASS" "File Permissions" "/etc/shadow permissions" "Correct ($SHADOW_PERMS)" ""
    else
        log_result "FAIL" "File Permissions" "/etc/shadow permissions" "Current: $SHADOW_PERMS (should be 640 or 600)" "chmod 640 /etc/shadow"
    fi
fi

# Check /etc/group permissions
if [ -f /etc/group ]; then
    GROUP_PERMS=$(stat -c "%a" /etc/group 2>/dev/null || stat -f "%OLp" /etc/group 2>/dev/null)
    if [ "$GROUP_PERMS" = "644" ]; then
        log_result "PASS" "File Permissions" "/etc/group permissions" "Correct (644)" ""
    else
        log_result "FAIL" "File Permissions" "/etc/group permissions" "Current: $GROUP_PERMS (should be 644)" "chmod 644 /etc/group"
    fi
fi

# Check /etc/gshadow permissions
if [ -f /etc/gshadow ]; then
    GSHADOW_PERMS=$(stat -c "%a" /etc/gshadow 2>/dev/null || stat -f "%OLp" /etc/gshadow 2>/dev/null)
    if [ "$GSHADOW_PERMS" = "640" ] || [ "$GSHADOW_PERMS" = "600" ]; then
        log_result "PASS" "File Permissions" "/etc/gshadow permissions" "Correct ($GSHADOW_PERMS)" ""
    else
        log_result "FAIL" "File Permissions" "/etc/gshadow permissions" "Current: $GSHADOW_PERMS (should be 640 or 600)" "chmod 640 /etc/gshadow"
    fi
fi

# Check for world-writable files
WW_FILES=$(find /etc /usr /var -type f -perm -002 2>/dev/null | head -10)
if [ -z "$WW_FILES" ]; then
    log_result "PASS" "File Permissions" "World-writable files in system directories" "No world-writable files found" ""
else
    log_result "FAIL" "File Permissions" "World-writable files in system directories" "Found world-writable files" "Review and fix permissions: find /etc /usr /var -type f -perm -002 -exec chmod o-w {} \\;"
fi

# Check for files with no owner
NOOWNER_FILES=$(find / -nouser 2>/dev/null | head -5)
if [ -z "$NOOWNER_FILES" ]; then
    log_result "PASS" "File Permissions" "Files with no owner" "No orphaned files found" ""
else
    log_result "WARN" "File Permissions" "Files with no owner" "Found orphaned files" "Review and assign proper ownership"
fi

# Check for files with no group
NOGROUP_FILES=$(find / -nogroup 2>/dev/null | head -5)
if [ -z "$NOGROUP_FILES" ]; then
    log_result "PASS" "File Permissions" "Files with no group" "No orphaned group files found" ""
else
    log_result "WARN" "File Permissions" "Files with no group" "Found orphaned group files" "Review and assign proper group"
fi

# ==============================================================================
# SECTION 3: USER ACCOUNTS AND PASSWORDS
# ==============================================================================
print_section "SECTION 3: USER ACCOUNTS AND PASSWORDS"

# Check for accounts with UID 0 (should only be root)
if [ -f /etc/passwd ]; then
    UID0_COUNT=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | wc -l)
    if [ "$UID0_COUNT" -eq 1 ]; then
        log_result "PASS" "User Accounts" "UID 0 accounts" "Only root has UID 0" ""
    else
        UID0_USERS=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
        log_result "FAIL" "User Accounts" "UID 0 accounts" "Multiple UID 0 accounts: $UID0_USERS" "Review and remove unauthorized UID 0 accounts"
    fi
fi

# Check for empty password accounts
if [ -f /etc/shadow ]; then
    EMPTY_PASS=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
    if [ -z "$EMPTY_PASS" ]; then
        log_result "PASS" "User Accounts" "Accounts with empty passwords" "No accounts with empty passwords" ""
    else
        log_result "FAIL" "User Accounts" "Accounts with empty passwords" "Found: $EMPTY_PASS" "Set passwords for all accounts: passwd <username>"
    fi
fi

# Check password aging
if [ -f /etc/login.defs ]; then
    PASS_MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ -n "$PASS_MAX_DAYS" ] && [ "$PASS_MAX_DAYS" -le 90 ] 2>/dev/null; then
        log_result "PASS" "Password Policy" "Password maximum age" "Set to $PASS_MAX_DAYS days (≤90)" ""
    else
        log_result "FAIL" "Password Policy" "Password maximum age" "Current: ${PASS_MAX_DAYS:-not set} (should be ≤90)" "Set PASS_MAX_DAYS 90 in /etc/login.defs"
    fi
    
    PASS_MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ -n "$PASS_MIN_DAYS" ] && [ "$PASS_MIN_DAYS" -ge 1 ] 2>/dev/null; then
        log_result "PASS" "Password Policy" "Password minimum age" "Set to $PASS_MIN_DAYS days (≥1)" ""
    else
        log_result "FAIL" "Password Policy" "Password minimum age" "Current: ${PASS_MIN_DAYS:-not set} (should be ≥1)" "Set PASS_MIN_DAYS 1 in /etc/login.defs"
    fi
    
    PASS_WARN_AGE=$(grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ -n "$PASS_WARN_AGE" ] && [ "$PASS_WARN_AGE" -ge 7 ] 2>/dev/null; then
        log_result "PASS" "Password Policy" "Password warning age" "Set to $PASS_WARN_AGE days (≥7)" ""
    else
        log_result "FAIL" "Password Policy" "Password warning age" "Current: ${PASS_WARN_AGE:-not set} (should be ≥7)" "Set PASS_WARN_AGE 7 in /etc/login.defs"
    fi
fi

# Check for default accounts
if [ -f /etc/passwd ]; then
    DEFAULT_ACCOUNTS=$(grep -E "^(root|admin|guest|test|demo):" /etc/passwd 2>/dev/null)
    if [ -z "$DEFAULT_ACCOUNTS" ] || echo "$DEFAULT_ACCOUNTS" | grep -q "^root:"; then
        log_result "PASS" "User Accounts" "Default accounts" "No unauthorized default accounts" ""
    else
        log_result "WARN" "User Accounts" "Default accounts" "Found default accounts" "Review and disable/remove if not needed"
    fi
fi

# Check for locked accounts
if [ -f /etc/shadow ]; then
    LOCKED_COUNT=$(awk -F: '($2 ~ /^!|^[*]/) {print $1}' /etc/shadow 2>/dev/null | wc -l)
    log_result "INFO" "User Accounts" "Locked accounts" "$LOCKED_COUNT accounts are locked" ""
fi

# ==============================================================================
# SECTION 4: SSH CONFIGURATION
# ==============================================================================
print_section "SECTION 4: SSH CONFIGURATION"

if [ -f /etc/ssh/sshd_config ]; then
    # Check PermitRootLogin
    ROOT_LOGIN=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}' | tr -d ' ' | head -1)
    if [ "$ROOT_LOGIN" = "no" ]; then
        log_result "PASS" "SSH" "PermitRootLogin" "Disabled (no)" ""
    else
        log_result "FAIL" "SSH" "PermitRootLogin" "Current: $ROOT_LOGIN (should be no)" "Set PermitRootLogin no in /etc/ssh/sshd_config"
    fi
    
    # Check PasswordAuthentication
    PASS_AUTH=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}' | tr -d ' ' | head -1)
    if [ "$PASS_AUTH" = "no" ]; then
        log_result "PASS" "SSH" "PasswordAuthentication" "Disabled (no) - using keys only" ""
    elif [ "$PASS_AUTH" = "yes" ]; then
        log_result "WARN" "SSH" "PasswordAuthentication" "Enabled (yes)" "Consider disabling and using key-based authentication only"
    else
        log_result "INFO" "SSH" "PasswordAuthentication" "Not explicitly set (default: yes)" "Set PasswordAuthentication no if using keys"
    fi
    
    # Check PubkeyAuthentication
    PUBKEY_AUTH=$(grep -i "^PubkeyAuthentication" /etc/ssh/sshd_config | awk '{print $2}' | tr -d ' ' | head -1)
    if [ "$PUBKEY_AUTH" = "yes" ] || [ -z "$PUBKEY_AUTH" ]; then
        log_result "PASS" "SSH" "PubkeyAuthentication" "Enabled" ""
    else
        log_result "FAIL" "SSH" "PubkeyAuthentication" "Disabled" "Set PubkeyAuthentication yes in /etc/ssh/sshd_config"
    fi
    
    # Check Protocol version
    SSH_PROTO=$(grep -i "^Protocol" /etc/ssh/sshd_config | awk '{print $2}' | tr -d ' ' | head -1)
    if [ "$SSH_PROTO" = "2" ]; then
        log_result "PASS" "SSH" "SSH Protocol" "Using Protocol 2 only" ""
    else
        log_result "FAIL" "SSH" "SSH Protocol" "Current: $SSH_PROTO (should be 2)" "Set Protocol 2 in /etc/ssh/sshd_config"
    fi
    
    # Check X11Forwarding
    X11_FWD=$(grep -i "^X11Forwarding" /etc/ssh/sshd_config | awk '{print $2}' | tr -d ' ' | head -1)
    if [ "$X11_FWD" = "no" ]; then
        log_result "PASS" "SSH" "X11Forwarding" "Disabled (no)" ""
    else
        log_result "WARN" "SSH" "X11Forwarding" "Current: $X11_FWD" "Set X11Forwarding no if not needed"
    fi
    
    # Check MaxAuthTries
    MAX_AUTH=$(grep -i "^MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}' | tr -d ' ' | head -1)
    if [ -n "$MAX_AUTH" ] && [ "$MAX_AUTH" -le 4 ] 2>/dev/null; then
        log_result "PASS" "SSH" "MaxAuthTries" "Set to $MAX_AUTH (≤4)" ""
    else
        log_result "WARN" "SSH" "MaxAuthTries" "Current: ${MAX_AUTH:-default 6} (should be ≤4)" "Set MaxAuthTries 4 in /etc/ssh/sshd_config"
    fi
    
    # Check ClientAliveInterval
    ALIVE_INT=$(grep -i "^ClientAliveInterval" /etc/ssh/sshd_config | awk '{print $2}' | tr -d ' ' | head -1)
    if [ -n "$ALIVE_INT" ] && [ "$ALIVE_INT" -le 600 ] 2>/dev/null; then
        log_result "PASS" "SSH" "ClientAliveInterval" "Set to $ALIVE_INT seconds (≤600)" ""
    else
        log_result "WARN" "SSH" "ClientAliveInterval" "Current: ${ALIVE_INT:-not set} (should be ≤600)" "Set ClientAliveInterval 600 in /etc/ssh/sshd_config"
    fi
    
    # Check PermitEmptyPasswords
    EMPTY_PASS_SSH=$(grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config | awk '{print $2}' | tr -d ' ' | head -1)
    if [ "$EMPTY_PASS_SSH" = "no" ]; then
        log_result "PASS" "SSH" "PermitEmptyPasswords" "Disabled (no)" ""
    else
        log_result "FAIL" "SSH" "PermitEmptyPasswords" "Current: $EMPTY_PASS_SSH (should be no)" "Set PermitEmptyPasswords no in /etc/ssh/sshd_config"
    fi
else
    log_result "INFO" "SSH" "SSH Configuration" "SSH not installed or config file not found" ""
fi

# ==============================================================================
# SECTION 5: FIREWALL CONFIGURATION
# ==============================================================================
print_section "SECTION 5: FIREWALL CONFIGURATION"

# Check UFW (Ubuntu/Debian)
if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    if echo "$UFW_STATUS" | grep -q "Status: active"; then
        log_result "PASS" "Firewall" "UFW Status" "Firewall is active" ""
    else
        log_result "FAIL" "Firewall" "UFW Status" "Firewall is not active" "Enable UFW: ufw enable"
    fi
    
    UFW_DEFAULT=$(ufw status verbose 2>/dev/null | grep "Default:")
    log_result "INFO" "Firewall" "UFW Default Policy" "$UFW_DEFAULT" ""
fi

# Check firewalld (RHEL/CentOS)
if command -v firewall-cmd >/dev/null 2>&1; then
    FIREWALLD_STATUS=$(firewall-cmd --state 2>/dev/null)
    if [ "$FIREWALLD_STATUS" = "running" ]; then
        log_result "PASS" "Firewall" "firewalld Status" "Firewall is running" ""
    else
        log_result "FAIL" "Firewall" "firewalld Status" "Firewall is not running" "Start firewalld: systemctl start firewalld && systemctl enable firewalld"
    fi
fi

# Check iptables
if command -v iptables >/dev/null 2>&1; then
    IPTABLES_RULES=$(iptables -L -n 2>/dev/null | grep -v "^Chain" | grep -v "^target" | grep -v "^$" | wc -l)
    if [ "$IPTABLES_RULES" -gt 0 ]; then
        log_result "PASS" "Firewall" "iptables Rules" "$IPTABLES_RULES rules configured" ""
    else
        log_result "WARN" "Firewall" "iptables Rules" "No iptables rules found" "Configure iptables rules"
    fi
fi

# Check for listening services
LISTENING_SERVICES=$(ss -tlnp 2>/dev/null | grep LISTEN | wc -l)
log_result "INFO" "Network" "Listening Services" "$LISTENING_SERVICES services listening" "Review and disable unnecessary services"

# ==============================================================================
# SECTION 6: KERNEL PARAMETERS
# ==============================================================================
print_section "SECTION 6: KERNEL PARAMETERS"

# Check IP forwarding
IP_FORWARD=$(sysctl net.ipv4.ip_forward 2>/dev/null | awk '{print $3}')
if [ "$IP_FORWARD" = "0" ]; then
    log_result "PASS" "Kernel" "IP Forwarding" "Disabled (0)" ""
else
    log_result "WARN" "Kernel" "IP Forwarding" "Enabled ($IP_FORWARD)" "Disable if not needed: sysctl -w net.ipv4.ip_forward=0"
fi

# Check ICMP redirects
ICMP_REDIRECT=$(sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | awk '{print $3}')
if [ "$ICMP_REDIRECT" = "0" ]; then
    log_result "PASS" "Kernel" "ICMP Redirects" "Disabled (0)" ""
else
    log_result "FAIL" "Kernel" "ICMP Redirects" "Enabled ($ICMP_REDIRECT)" "Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0"
fi

# Check ICMP ping broadcasts
ICMP_PING=$(sysctl net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null | awk '{print $3}')
if [ "$ICMP_PING" = "1" ]; then
    log_result "PASS" "Kernel" "ICMP Broadcast Ping" "Ignored (1)" ""
else
    log_result "FAIL" "Kernel" "ICMP Broadcast Ping" "Current: ${ICMP_PING:-0} (should be 1)" "Set: sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
fi

# Check source routing
SRC_ROUTE=$(sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null | awk '{print $3}')
if [ "$SRC_ROUTE" = "0" ]; then
    log_result "PASS" "Kernel" "Source Routing" "Disabled (0)" ""
else
    log_result "FAIL" "Kernel" "Source Routing" "Enabled ($SRC_ROUTE)" "Disable: sysctl -w net.ipv4.conf.all.accept_source_route=0"
fi

# Check SYN flood protection
SYN_COOKIES=$(sysctl net.ipv4.tcp_syncookies 2>/dev/null | awk '{print $3}')
if [ "$SYN_COOKIES" = "1" ]; then
    log_result "PASS" "Kernel" "SYN Flood Protection" "Enabled (1)" ""
else
    log_result "FAIL" "Kernel" "SYN Flood Protection" "Current: ${SYN_COOKIES:-0} (should be 1)" "Enable: sysctl -w net.ipv4.tcp_syncookies=1"
fi

# Check log martians
LOG_MARTIANS=$(sysctl net.ipv4.conf.all.log_martians 2>/dev/null | awk '{print $3}')
if [ "$LOG_MARTIANS" = "1" ]; then
    log_result "PASS" "Kernel" "Log Martians" "Enabled (1)" ""
else
    log_result "WARN" "Kernel" "Log Martians" "Current: ${LOG_MARTIANS:-0} (should be 1)" "Enable: sysctl -w net.ipv4.conf.all.log_martians=1"
fi

# Check ASLR
ASLR=$(sysctl kernel.randomize_va_space 2>/dev/null | awk '{print $3}')
if [ "$ASLR" = "2" ]; then
    log_result "PASS" "Kernel" "ASLR (Address Space Layout Randomization)" "Full randomization (2)" ""
elif [ "$ASLR" = "1" ]; then
    log_result "WARN" "Kernel" "ASLR" "Partial randomization (1)" "Enable full ASLR: sysctl -w kernel.randomize_va_space=2"
else
    log_result "FAIL" "Kernel" "ASLR" "Disabled ($ASLR)" "Enable: sysctl -w kernel.randomize_va_space=2"
fi

# ==============================================================================
# SECTION 7: SERVICES AND DAEMONS
# ==============================================================================
print_section "SECTION 7: SERVICES AND DAEMONS"

# Check for unnecessary services
UNNECESSARY_SERVICES=("telnet" "rsh" "rlogin" "rexec" "ftp" "tftp" "xinetd" "inetd")
for service in "${UNNECESSARY_SERVICES[@]}"; do
    if systemctl is-enabled "$service" >/dev/null 2>&1 || service "$service" status >/dev/null 2>&1; then
        log_result "FAIL" "Services" "Unnecessary Service: $service" "Service is enabled/running" "Disable service: systemctl disable $service && systemctl stop $service"
    else
        log_result "PASS" "Services" "Unnecessary Service: $service" "Service is disabled/not installed" ""
    fi
done

# Check for running services
RUNNING_SERVICES=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -v "loaded active running" | wc -l)
log_result "INFO" "Services" "Running Services" "$RUNNING_SERVICES services running" "Review and disable unnecessary services"

# Check for enabled services at boot
ENABLED_SERVICES=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -v "UNIT\|listed" | wc -l)
log_result "INFO" "Services" "Enabled Services" "$ENABLED_SERVICES services enabled at boot" "Review and disable unnecessary services"

# ==============================================================================
# SECTION 8: LOGGING AND AUDITING
# ==============================================================================
print_section "SECTION 8: LOGGING AND AUDITING"

# Check rsyslog
if systemctl is-active rsyslog >/dev/null 2>&1 || systemctl is-active syslog-ng >/dev/null 2>&1; then
    log_result "PASS" "Logging" "System Logging" "rsyslog/syslog-ng is active" ""
else
    log_result "FAIL" "Logging" "System Logging" "System logging is not active" "Enable: systemctl enable rsyslog && systemctl start rsyslog"
fi

# Check auditd
if systemctl is-active auditd >/dev/null 2>&1; then
    log_result "PASS" "Auditing" "auditd Status" "auditd is active" ""
    
    # Check auditd rules
    AUDIT_RULES=$(auditctl -l 2>/dev/null | wc -l)
    if [ "$AUDIT_RULES" -gt 0 ]; then
        log_result "PASS" "Auditing" "auditd Rules" "$AUDIT_RULES rules configured" ""
    else
        log_result "WARN" "Auditing" "auditd Rules" "No audit rules configured" "Configure audit rules in /etc/audit/rules.d/"
    fi
else
    log_result "FAIL" "Auditing" "auditd Status" "auditd is not active" "Install and enable auditd"
fi

# Check log rotation
if [ -f /etc/logrotate.conf ]; then
    log_result "PASS" "Logging" "Log Rotation" "logrotate is configured" ""
else
    log_result "WARN" "Logging" "Log Rotation" "logrotate not configured" "Configure log rotation"
fi

# Check for log files
LOG_DIRS=("/var/log" "/var/log/audit")
for log_dir in "${LOG_DIRS[@]}"; do
    if [ -d "$log_dir" ]; then
        LOG_COUNT=$(find "$log_dir" -type f 2>/dev/null | wc -l)
        log_result "INFO" "Logging" "Log Files in $log_dir" "$LOG_COUNT log files" ""
    fi
done

# ==============================================================================
# SECTION 9: NETWORK CONFIGURATION
# ==============================================================================
print_section "SECTION 9: NETWORK CONFIGURATION"

# Check for unnecessary network protocols
if lsmod | grep -q "dccp\|sctp\|rds\|tipc"; then
    log_result "WARN" "Network" "Unnecessary Protocols" "Unnecessary protocols loaded" "Unload if not needed: modprobe -r <protocol>"
else
    log_result "PASS" "Network" "Unnecessary Protocols" "No unnecessary protocols loaded" ""
fi

# Check for IP forwarding in sysctl.conf
if [ -f /etc/sysctl.conf ]; then
    if grep -q "^net.ipv4.ip_forward=0" /etc/sysctl.conf 2>/dev/null; then
        log_result "PASS" "Network" "IP Forwarding in sysctl.conf" "Permanently disabled" ""
    else
        log_result "WARN" "Network" "IP Forwarding in sysctl.conf" "Not permanently disabled" "Add net.ipv4.ip_forward=0 to /etc/sysctl.conf"
    fi
fi

# Check hostname
HOSTNAME=$(hostname)
if [ -n "$HOSTNAME" ] && [ "$HOSTNAME" != "localhost" ]; then
    log_result "PASS" "Network" "Hostname" "Set to $HOSTNAME" ""
else
    log_result "WARN" "Network" "Hostname" "Using default hostname" "Set proper hostname"
fi

# ==============================================================================
# SECTION 10: FILE SYSTEM SECURITY
# ==============================================================================
print_section "SECTION 10: FILE SYSTEM SECURITY"

# Check for separate /tmp partition
TMP_PARTITION=$(mount | grep -E "\s/tmp\s")
if [ -n "$TMP_PARTITION" ]; then
    TMP_NOSUID=$(echo "$TMP_PARTITION" | grep -o "nosuid")
    TMP_NOEXEC=$(echo "$TMP_PARTITION" | grep -o "noexec")
    if [ -n "$TMP_NOSUID" ] && [ -n "$TMP_NOEXEC" ]; then
        log_result "PASS" "File System" "/tmp partition" "Mounted with nosuid,noexec" ""
    else
        log_result "WARN" "File System" "/tmp partition" "Missing nosuid or noexec" "Remount with: mount -o remount,nosuid,noexec /tmp"
    fi
else
    log_result "WARN" "File System" "/tmp partition" "Not on separate partition" "Consider mounting /tmp on separate partition with nosuid,noexec"
fi

# Check for separate /var partition
VAR_PARTITION=$(mount | grep -E "\s/var\s")
if [ -n "$VAR_PARTITION" ]; then
    log_result "PASS" "File System" "/var partition" "On separate partition" ""
else
    log_result "INFO" "File System" "/var partition" "Not on separate partition" "Consider separate /var partition for security"
fi

# Check for separate /home partition
HOME_PARTITION=$(mount | grep -E "\s/home\s")
if [ -n "$HOME_PARTITION" ]; then
    log_result "PASS" "File System" "/home partition" "On separate partition" ""
else
    log_result "INFO" "File System" "/home partition" "Not on separate partition" "Consider separate /home partition"
fi

# Check for nodev on /tmp
if mount | grep -E "\s/tmp\s" | grep -q "nodev"; then
    log_result "PASS" "File System" "/tmp nodev" "nodev option set" ""
else
    log_result "WARN" "File System" "/tmp nodev" "nodev option not set" "Add nodev option to /tmp mount"
fi

# ==============================================================================
# SECTION 11: PACKAGE MANAGEMENT
# ==============================================================================
print_section "SECTION 11: PACKAGE MANAGEMENT"

# Check for package updates
if command -v apt >/dev/null 2>&1; then
    UPDATE_COUNT=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")
    if [ "$UPDATE_COUNT" -eq 0 ]; then
        log_result "PASS" "Packages" "System Updates" "System is up to date" ""
    else
        log_result "WARN" "Packages" "System Updates" "$UPDATE_COUNT packages need updates" "Run: apt update && apt upgrade"
    fi
elif command -v yum >/dev/null 2>&1; then
    UPDATE_COUNT=$(yum check-update --quiet 2>/dev/null | grep -c "\.el" || echo "0")
    if [ "$UPDATE_COUNT" -eq 0 ]; then
        log_result "PASS" "Packages" "System Updates" "System is up to date" ""
    else
        log_result "WARN" "Packages" "System Updates" "$UPDATE_COUNT packages need updates" "Run: yum update"
    fi
fi

# Check for automatic updates
if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ] || [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    log_result "PASS" "Packages" "Automatic Updates" "Automatic updates configured" ""
else
    log_result "WARN" "Packages" "Automatic Updates" "Automatic updates not configured" "Configure automatic security updates"
fi

# Check for unnecessary packages
UNNECESSARY_PACKAGES=("telnet" "rsh-client" "rsh-redone-client" "nis" "ypbind")
for pkg in "${UNNECESSARY_PACKAGES[@]}"; do
    if command -v dpkg >/dev/null 2>&1; then
        if dpkg -l 2>/dev/null | grep -q "^ii.*$pkg"; then
            log_result "WARN" "Packages" "Unnecessary Package: $pkg" "Package is installed" "Remove: apt remove $pkg"
        fi
    elif command -v rpm >/dev/null 2>&1; then
        if rpm -q "$pkg" >/dev/null 2>&1; then
            log_result "WARN" "Packages" "Unnecessary Package: $pkg" "Package is installed" "Remove: yum remove $pkg"
        fi
    fi
done

# ==============================================================================
# SECTION 12: BOOT SECURITY
# ==============================================================================
print_section "SECTION 12: BOOT SECURITY"

# Check GRUB password
if [ -f /boot/grub/grub.cfg ] || [ -f /boot/grub2/grub.cfg ]; then
    if grep -q "password" /boot/grub/grub.cfg 2>/dev/null || grep -q "password" /boot/grub2/grub.cfg 2>/dev/null; then
        log_result "PASS" "Boot" "GRUB Password" "GRUB password is set" ""
    else
        log_result "WARN" "Boot" "GRUB Password" "GRUB password not set" "Set GRUB password to prevent unauthorized boot modifications"
    fi
fi

# Check boot loader permissions
if [ -f /boot/grub/grub.cfg ]; then
    GRUB_PERMS=$(stat -c "%a" /boot/grub/grub.cfg 2>/dev/null || stat -f "%OLp" /boot/grub/grub.cfg 2>/dev/null)
    if [ "$GRUB_PERMS" = "600" ] || [ "$GRUB_PERMS" = "400" ]; then
        log_result "PASS" "Boot" "GRUB Config Permissions" "Correct ($GRUB_PERMS)" ""
    else
        log_result "WARN" "Boot" "GRUB Config Permissions" "Current: $GRUB_PERMS (should be 600 or 400)" "chmod 600 /boot/grub/grub.cfg"
    fi
fi

# Check for single user mode protection
if [ -f /etc/inittab ]; then
    if grep -q "^~~:S:wait:/sbin/sulogin" /etc/inittab 2>/dev/null; then
        log_result "PASS" "Boot" "Single User Mode" "Password required for single user mode" ""
    else
        log_result "WARN" "Boot" "Single User Mode" "Password not required" "Configure sulogin for single user mode"
    fi
fi

# ==============================================================================
# SECTION 13: CRON AND SCHEDULED TASKS
# ==============================================================================
print_section "SECTION 13: CRON AND SCHEDULED TASKS"

# Check cron service
if systemctl is-active cron >/dev/null 2>&1 || systemctl is-active crond >/dev/null 2>&1; then
    log_result "PASS" "Cron" "Cron Service" "Cron service is active" ""
else
    log_result "WARN" "Cron" "Cron Service" "Cron service is not active" "Enable cron if needed"
fi

# Check cron permissions
CRON_DIRS=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.monthly" "/etc/cron.weekly")
for cron_dir in "${CRON_DIRS[@]}"; do
    if [ -d "$cron_dir" ]; then
        CRON_PERMS=$(stat -c "%a" "$cron_dir" 2>/dev/null || stat -f "%OLp" "$cron_dir" 2>/dev/null)
        if [ "$CRON_PERMS" = "700" ] || [ "$CRON_PERMS" = "755" ]; then
            log_result "PASS" "Cron" "Cron Directory: $cron_dir" "Correct permissions ($CRON_PERMS)" ""
        else
            log_result "WARN" "Cron" "Cron Directory: $cron_dir" "Current: $CRON_PERMS" "Review permissions"
        fi
    fi
done

# Check for world-writable cron files
WW_CRON=$(find /etc/cron* -type f -perm -002 2>/dev/null)
if [ -z "$WW_CRON" ]; then
    log_result "PASS" "Cron" "World-writable Cron Files" "No world-writable cron files" ""
else
    log_result "FAIL" "Cron" "World-writable Cron Files" "Found world-writable cron files" "Fix permissions: chmod o-w <file>"
fi

# ==============================================================================
# SECTION 14: ENVIRONMENT VARIABLES
# ==============================================================================
print_section "SECTION 14: ENVIRONMENT VARIABLES"

# Check PATH variable
PATH_VAR=$(echo $PATH)
if echo "$PATH_VAR" | grep -q "::"; then
    log_result "FAIL" "Environment" "PATH Variable" "Contains empty directory (::)" "Remove empty directories from PATH"
else
    log_result "PASS" "Environment" "PATH Variable" "No empty directories" ""
fi

if echo "$PATH_VAR" | grep -qE "(^|:)(\.|/tmp|/var/tmp)(:|$)"; then
    log_result "FAIL" "Environment" "PATH Variable" "Contains current directory or /tmp" "Remove . and /tmp from PATH"
else
    log_result "PASS" "Environment" "PATH Variable" "No insecure directories" ""
fi

# Check umask
UMASK_VAL=$(umask)
if [ "$UMASK_VAL" = "0027" ] || [ "$UMASK_VAL" = "027" ] || [ "$UMASK_VAL" = "0077" ] || [ "$UMASK_VAL" = "077" ]; then
    log_result "PASS" "Environment" "umask" "Set to $UMASK_VAL (restrictive)" ""
else
    log_result "WARN" "Environment" "umask" "Current: $UMASK_VAL (should be 027 or 077)" "Set umask 027 in /etc/profile or /etc/bash.bashrc"
fi

# ==============================================================================
# SECTION 15: SELINUX/APPARMOR
# ==============================================================================
print_section "SECTION 15: SELINUX/APPARMOR"

# Check SELinux (RHEL/CentOS)
if command -v getenforce >/dev/null 2>&1; then
    SELINUX_STATUS=$(getenforce 2>/dev/null)
    if [ "$SELINUX_STATUS" = "Enforcing" ]; then
        log_result "PASS" "SELinux" "SELinux Status" "Enforcing mode" ""
    elif [ "$SELINUX_STATUS" = "Permissive" ]; then
        log_result "WARN" "SELinux" "SELinux Status" "Permissive mode" "Set to Enforcing: setenforce 1"
    else
        log_result "FAIL" "SELinux" "SELinux Status" "Disabled" "Enable SELinux: setenforce 1"
    fi
fi

# Check AppArmor (Ubuntu/Debian)
if command -v aa-status >/dev/null 2>&1; then
    APPARMOR_STATUS=$(aa-status 2>/dev/null | head -1)
    if echo "$APPARMOR_STATUS" | grep -q "apparmor module is loaded"; then
        log_result "PASS" "AppArmor" "AppArmor Status" "AppArmor is loaded" ""
        PROFILES=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}')
        log_result "INFO" "AppArmor" "AppArmor Profiles" "$PROFILES profiles loaded" ""
    else
        log_result "WARN" "AppArmor" "AppArmor Status" "AppArmor not loaded" "Enable AppArmor: systemctl enable apparmor && systemctl start apparmor"
    fi
fi

# ==============================================================================
# SECTION 16: SUID/SGID FILES
# ==============================================================================
print_section "SECTION 16: SUID/SGID FILES"

# Check for unexpected SUID files
SUID_FILES=$(find /usr /bin /sbin -type f -perm -4000 2>/dev/null | wc -l)
log_result "INFO" "File Permissions" "SUID Files" "$SUID_FILES SUID files in system directories" "Review for unexpected SUID files"

# Check for unexpected SGID files
SGID_FILES=$(find /usr /bin /sbin -type f -perm -2000 2>/dev/null | wc -l)
log_result "INFO" "File Permissions" "SGID Files" "$SGID_FILES SGID files in system directories" "Review for unexpected SGID files"

# Check for SUID files in /tmp
TMP_SUID=$(find /tmp /var/tmp -type f -perm -4000 2>/dev/null)
if [ -z "$TMP_SUID" ]; then
    log_result "PASS" "File Permissions" "SUID Files in /tmp" "No SUID files in /tmp" ""
else
    log_result "FAIL" "File Permissions" "SUID Files in /tmp" "Found SUID files in /tmp" "Remove SUID bit: chmod u-s <file>"
fi

# ==============================================================================
# SECTION 17: NETWORK SERVICES
# ==============================================================================
print_section "SECTION 17: NETWORK SERVICES"

# Check for listening services on all interfaces
LISTEN_ALL=$(ss -tlnp 2>/dev/null | grep "0.0.0.0:" | wc -l)
if [ "$LISTEN_ALL" -gt 0 ]; then
    log_result "INFO" "Network" "Services Listening on All Interfaces" "$LISTEN_ALL services" "Review and bind to specific interfaces if possible"
fi

# Check for services listening on localhost only
LISTEN_LOCAL=$(ss -tlnp 2>/dev/null | grep "127.0.0.1:" | wc -l)
log_result "INFO" "Network" "Services Listening on Localhost" "$LISTEN_LOCAL services" ""

# ==============================================================================
# SECTION 18: DNS CONFIGURATION
# ==============================================================================
print_section "SECTION 18: DNS CONFIGURATION"

# Check DNS servers
if [ -f /etc/resolv.conf ]; then
    DNS_SERVERS=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | wc -l)
    if [ "$DNS_SERVERS" -gt 0 ]; then
        log_result "PASS" "DNS" "DNS Servers" "$DNS_SERVERS DNS servers configured" ""
    else
        log_result "WARN" "DNS" "DNS Servers" "No DNS servers configured" "Configure DNS servers"
    fi
fi

# ==============================================================================
# SECTION 19: TIME SYNCHRONIZATION
# ==============================================================================
print_section "SECTION 19: TIME SYNCHRONIZATION"

# Check NTP/Chrony
if systemctl is-active chronyd >/dev/null 2>&1 || systemctl is-active ntpd >/dev/null 2>&1 || systemctl is-active systemd-timesyncd >/dev/null 2>&1; then
    log_result "PASS" "Time" "Time Synchronization" "Time sync service is active" ""
else
    log_result "FAIL" "Time" "Time Synchronization" "Time sync service is not active" "Enable NTP/Chrony: systemctl enable chronyd && systemctl start chronyd"
fi

# ==============================================================================
# SECTION 20: SECURITY UPDATES
# ==============================================================================
print_section "SECTION 20: SECURITY UPDATES"

# Check last update
if [ -f /var/log/apt/history.log ]; then
    LAST_UPDATE=$(grep "Start-Date" /var/log/apt/history.log | tail -1 | awk '{print $2, $3}')
    log_result "INFO" "Security" "Last Update" "$LAST_UPDATE" ""
fi

# Check for security advisories
if command -v unattended-upgrades >/dev/null 2>&1; then
    log_result "PASS" "Security" "Unattended Upgrades" "Unattended upgrades installed" ""
else
    log_result "WARN" "Security" "Unattended Upgrades" "Unattended upgrades not installed" "Install: apt install unattended-upgrades"
fi

# ==============================================================================
# FINAL REPORT
# ==============================================================================
print_section "FINAL REPORT"

echo "" >> "$REPORT_FILE"
echo "=== SUMMARY ===" >> "$REPORT_FILE"
echo "Total Checks: $CHECK_COUNT" >> "$REPORT_FILE"
echo "Passed: $PASSED_COUNT" >> "$REPORT_FILE"
echo "Failed: $FAILED_COUNT" >> "$REPORT_FILE"
echo "Warnings: $WARNING_COUNT" >> "$REPORT_FILE"
echo "Info: $INFO_COUNT" >> "$REPORT_FILE"

# Calculate compliance percentage
if [ $CHECK_COUNT -gt 0 ]; then
    COMPLIANCE=$((PASSED_COUNT * 100 / CHECK_COUNT))
else
    COMPLIANCE=0
fi

echo -e "\n${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║${NC} ${WHITE}HARDENING CHECK SUMMARY${NC} ${BOLD}${CYAN}║${NC}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"

echo -e "${YELLOW}Total Checks:${NC} $CHECK_COUNT"
echo -e "${GREEN}Passed:${NC} $PASSED_COUNT"
echo -e "${RED}Failed:${NC} $FAILED_COUNT"
echo -e "${YELLOW}Warnings:${NC} $WARNING_COUNT"
echo -e "${BLUE}Info:${NC} $INFO_COUNT"
echo -e "${BOLD}${MAGENTA}Compliance Score:${NC} $COMPLIANCE%"

if [ $COMPLIANCE -ge 80 ]; then
    echo -e "${GREEN}Status: GOOD - System is well hardened${NC}"
elif [ $COMPLIANCE -ge 60 ]; then
    echo -e "${YELLOW}Status: FAIR - Some improvements needed${NC}"
else
    echo -e "${RED}Status: POOR - Significant hardening required${NC}"
fi

echo ""
echo -e "${CYAN}Detailed report saved to: $REPORT_FILE${NC}"
echo ""
echo -e "${BLUE}Press Enter to exit...${NC}"
read

