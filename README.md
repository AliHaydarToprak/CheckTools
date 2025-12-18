# Linux Security Testing & Hardening Scripts

A comprehensive collection of security testing and hardening assessment scripts for Linux systems. These scripts provide extensive coverage of MITRE ATT&CK techniques, Wazuh detection rules, Sigma rules, and STIG compliance checks.

## 📋 Table of Contents

- [Overview](#overview)
- [Scripts](#scripts)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Coverage Analysis](#coverage-analysis)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Detection Rules Coverage](#detection-rules-coverage)
- [Hardening Checklist](#hardening-checklist)
- [Output & Reports](#output--reports)
- [Safety & Security](#safety--security)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

This repository contains three powerful security testing and assessment tools:

1. **`av-test.sh`** - Antivirus file-based malware detection testing
2. **`siem-test.sh`** - SIEM behavioral detection testing (Wazuh, Sigma, Security Content)
3. **`hardening.sh`** - Linux hardening compliance checker (STIG-based)

All scripts are designed to be **safe**, **non-destructive**, and provide comprehensive security assessment capabilities.

---

## 📦 Scripts

### 1. AV Test Script (`av-test.sh`)

**Purpose:** Tests antivirus and endpoint protection capabilities through file-based malware detection scenarios.

**Scenarios:** 22 comprehensive test scenarios

**Coverage Areas:**
- EICAR test file detection
- Malicious file creation and scanning
- Web shell detection
- Ransomware behavior simulation
- Crypto miner detection
- Fileless attack simulation
- Archive scanning
- Credential access attempts
- Persistence mechanisms
- Initial access vectors
- Data collection
- Defense evasion techniques

**Key Features:**
- ✅ Safe sandbox environment
- ✅ Real-time command execution display
- ✅ Detailed status reporting (PASS/FAIL/WARN)
- ✅ Comprehensive logging
- ✅ Automatic cleanup

### 2. SIEM Test Script (`siem-test.sh`)

**Purpose:** Tests SIEM, EDR, and security monitoring systems through behavioral detection scenarios.

**Scenarios:** 70+ comprehensive test scenarios

**Coverage Areas:**
- Wazuh rule testing (syslog, PAM, SSH, attack, auditd)
- Sigma rules (process_creation, file_create, network_connection, builtin, auditd, other)
- Security Content endpoint detections
- Linux Audit Log Cheatsheet scenarios
- MITRE ATT&CK technique coverage

**Key Features:**
- ✅ 70+ attack simulation scenarios
- ✅ Wazuh rule mapping
- ✅ Sigma rule coverage
- ✅ auditd event triggering
- ✅ Real-time detection point display
- ✅ Comprehensive logging with rule references

### 3. Hardening Checklist (`hardening.sh`)

**Purpose:** Comprehensive Linux system hardening assessment based on STIG and security best practices.

**Checks:** 100+ security configuration checks

**Coverage Areas:**
- File permissions and ownership
- User accounts and password policies
- SSH configuration
- Firewall configuration
- Kernel parameters
- Services and daemons
- Logging and auditing
- Network configuration
- File system security
- Package management
- Boot security
- Cron and scheduled tasks
- Environment variables
- SELinux/AppArmor
- SUID/SGID files
- Network services
- DNS configuration
- Time synchronization
- Security updates

**Key Features:**
- ✅ STIG compliance checking
- ✅ PASS/FAIL/WARN/INFO status for each check
- ✅ Compliance score calculation
- ✅ Detailed recommendations
- ✅ Multi-distribution support (Ubuntu, Debian, RHEL, CentOS)

---

## ✨ Features

### Common Features Across All Scripts

- **Safe Execution:** All scripts use sandbox directories and safe simulation techniques
- **Non-Destructive:** No permanent changes to system files or configurations
- **Automatic Cleanup:** All temporary files and processes are cleaned up automatically
- **Detailed Logging:** Comprehensive log files with timestamps
- **Color-Coded Output:** Easy-to-read colored terminal output
- **Status Reporting:** Clear PASS/FAIL/WARN/INFO indicators
- **Real-Time Feedback:** Step-by-step command execution display
- **Error Handling:** Robust error handling and graceful failures

### AV Test Script Specific

- File-based malware detection testing
- Signature-based detection validation
- Behavioral detection testing
- Archive scanning capabilities
- Credential access simulation
- Persistence mechanism testing

### SIEM Test Script Specific

- Wazuh rule coverage
- Sigma rule coverage
- Security Content integration
- auditd event generation
- Real-time detection point mapping
- Rule reference tracking

### Hardening Checklist Specific

- STIG compliance assessment
- Compliance score calculation
- Detailed remediation recommendations
- Multi-OS support
- Configuration validation

---

## 🚀 Installation

### Prerequisites

- Linux system (Ubuntu, Debian, RHEL, CentOS, or similar)
- Bash shell (version 4.0 or higher)
- Root or sudo access (for some checks in hardening.sh)
- Basic system utilities (grep, awk, find, stat, etc.)

### Quick Setup

```bash
# Clone or download the repository
cd /path/to/AntiVirus

# Make scripts executable
chmod +x av-test.sh siem-test.sh hardening.sh

# Verify scripts are executable
ls -l *.sh
```

### Optional Dependencies

Some scenarios may require additional tools (scripts will handle missing tools gracefully):

- `wget` or `curl` - For network-based tests
- `nmap` - For port scanning scenarios
- `netcat` - For reverse shell scenarios
- `openssl` - For encryption operations
- `auditd` - For audit logging (SIEM tests)
- `systemctl` - For service management checks

---

## 📖 Usage

### AV Test Script

```bash
# Run AV test script
./av-test.sh

# The script will:
# - Create a sandbox directory (./av_test_sandbox)
# - Execute 22 test scenarios
# - Display real-time results
# - Generate a detailed log file (./av_test_results.log)
# - Clean up automatically on exit
```

**Expected Output:**
```
╔═══════════════════════════════════════════════════════════════════════════╗
║ ANTIVIRUS TEST SIMULATOR FOR LINUX                                        ║
║ File-based Malware Detection Testing                                      ║
╚═══════════════════════════════════════════════════════════════════════════╝

[SCENARIO 1: EICAR Test File Download]
>>> Executing command: wget ...
>>> AV Detection Point: AV: EICAR file detection
>>> [✓] SUCCESS (Exit Code: 0)
```

### SIEM Test Script

```bash
# Run SIEM test script
./siem-test.sh

# The script will:
# - Create a sandbox directory (./siem_test_sandbox)
# - Execute 70+ test scenarios
# - Display real-time results with detection points
# - Generate a detailed log file (./siem_test_results.log)
# - Show Wazuh rule references
# - Clean up automatically on exit
```

**Expected Output:**
```
╔═══════════════════════════════════════════════════════════════════════════╗
║ SIEM TEST SIMULATOR FOR LINUX                                             ║
║ Wazuh Rule-based Testing                                                  ║
╚═══════════════════════════════════════════════════════════════════════════╝

[SCENARIO 1: SSH Failed Login Attempts]
>>> Executing command: ssh ...
>>> SIEM Detection: auditd: SYSCALL (ssh) | SIEM: SSH failed login
>>> Wazuh Rule: 0095-sshd_rules.xml
>>> [⚠] EXPECTED FAILURE (Exit Code: 255) - Security protection is working
```

### Hardening Checklist

```bash
# Run hardening checklist (may require sudo for some checks)
sudo ./hardening.sh

# The script will:
# - Detect your Linux distribution
# - Perform 100+ security checks
# - Display PASS/FAIL/WARN/INFO for each check
# - Generate a detailed report (./hardening-report-YYYYMMDD-HHMMSS.txt)
# - Calculate compliance score
```

**Expected Output:**
```
╔═══════════════════════════════════════════════════════════════════════════╗
║ LINUX HARDENING CHECKLIST - STIG COMPLIANCE CHECKER                       ║
║ Comprehensive Security Hardening Assessment                               ║
╚═══════════════════════════════════════════════════════════════════════════╝

Detected OS: ubuntu 22.04

[✓] PASS - /etc/passwd permissions (Correct (644))
[✗] FAIL - /etc/shadow permissions (Current: 644 (should be 640 or 600))
    Recommendation: chmod 640 /etc/shadow
```

---

## 📊 Coverage Analysis

### AV Test Script Coverage

**MITRE ATT&CK Coverage:** ~25% (50/200 techniques)

**Covered Tactics:**
- **Execution:** 10% - Command execution, script execution
- **Defense Evasion:** 15% - File operations, obfuscation
- **Impact:** 20% - Ransomware, resource hijacking
- **Credential Access:** 0% → **Now Covered** - Credential dumping, password stores
- **Persistence:** 0% → **Now Covered** - Autostart, systemd, cron
- **Initial Access:** 0% → **Now Covered** - Valid accounts, phishing
- **Collection:** 0% → **Now Covered** - Data collection, network shares

**Key Scenarios:**
1. EICAR Test File Download
2. Malicious File Creation
3. Web Shell Creation
4. Ransomware Simulation
5. Suspicious File Creation in /tmp
6. Executable File Creation
7. Crypto Miner Simulation
8. Fileless Attack Simulation
9. Archive with Malicious Content
10. Suspicious File Operations
11. OS Credential Dumping
12. Credentials from Password Stores
13. Boot or Logon Autostart Execution
14. Systemd Service Persistence
15. Scheduled Task/Job Creation
16. Valid Accounts Enumeration
17. Default Account Usage
18. Phishing File Download
19. Data Collection from Local System
20. Data from Network Shared Drive
21. Defense Impairment
22. Security Logging Disable

### SIEM Test Script Coverage

**MITRE ATT&CK Coverage:** ~65% (130/200 techniques)

**Covered Tactics:**
- **Initial Access:** 50% - Valid accounts, phishing, exploits
- **Execution:** 60% - Command interpreters, scheduled tasks, system services
- **Persistence:** 53% - Boot autostart, system processes, event triggers
- **Privilege Escalation:** 67% - Elevation control, process injection, exploitation
- **Defense Evasion:** 60% - Indicator removal, obfuscation, defense impairment
- **Credential Access:** 53% → **Enhanced** - OS credential dumping, password stores
- **Discovery:** 60% - System info, file discovery, network discovery
- **Lateral Movement:** 60% - Remote services, deployment tools
- **Collection:** 33% → **Enhanced** - Email, clipboard, automated collection
- **Command and Control:** 50% → **Enhanced** - Proxy, tunneling, dynamic resolution
- **Exfiltration:** 50% - C2 channel, alternative protocols
- **Impact:** 33% → **Enhanced** - Data destruction, disk wipe, defacement

**Key Scenario Categories:**
1. **Wazuh Rules (20 scenarios):**
   - SSH authentication (0095-sshd_rules.xml)
   - PAM authentication (0085-pam_rules.xml)
   - Syslog events (0020-syslog_rules.xml)
   - Attack detection (0280-attack_rules.xml)
   - auditd events (0365-auditd_rules.xml)

2. **Sigma Rules (20 scenarios):**
   - process_creation (nohup, hack tools, capabilities, containers)
   - file_create (webshells, suspicious files)
   - network_connection (reverse shells, outbound connections)
   - builtin (command injection, chaining)
   - auditd (rule modification)
   - other (cron, systemd)

3. **Linux Audit Log Cheatsheet (15 scenarios):**
   - Unauthorized file access
   - Sudo abuse
   - SSH config modification
   - Critical file deletion
   - User management
   - Process execution monitoring
   - File permission changes
   - Directory access monitoring
   - System call monitoring
   - Network connection monitoring
   - File modification monitoring
   - Cron job manipulation
   - Environment variable manipulation
   - Kernel module operations
   - Log file manipulation

4. **Security Content (5 scenarios):**
   - Endpoint detection scenarios
   - Process enumeration
   - Connection monitoring
   - SUID discovery
   - Login enumeration

5. **Enhanced Coverage (10 scenarios):**
   - Detailed credential dumping (T1003.001-005)
   - Password store access (T1555.001-002)
   - Full defense impairment (T1562)
   - Collection techniques (T1114, T1115, T1119, T1123, T1125)
   - Advanced C2 (T1090, T1572, T1568, T1071.002)
   - Impact techniques (T1485, T1487, T1488, T1491, T1492, T1489, T1490)
   - Execution flow hijacking (T1574)

### Combined Coverage

**Total MITRE ATT&CK Coverage:** ~70% (140/200 techniques)

**High Priority Techniques:** 70% coverage
**Medium Priority Techniques:** 58% coverage
**Low Priority Techniques:** 38% coverage

---

## 🎯 MITRE ATT&CK Coverage

### Coverage by Tactic

| Tactic | AV Script | SIEM Script | Combined | Total Techniques |
|--------|-----------|-------------|----------|------------------|
| **Initial Access** | 0% | 50% | **50%** | 10 |
| **Execution** | 10% | 60% | **65%** | 20 |
| **Persistence** | 0% | 53% | **53%** | 15 |
| **Privilege Escalation** | 0% | 67% | **67%** | 15 |
| **Defense Evasion** | 15% | 60% | **65%** | 20 |
| **Credential Access** | 0% | 53% | **53%** | 15 |
| **Discovery** | 5% | 60% | **62%** | 25 |
| **Lateral Movement** | 0% | 60% | **60%** | 10 |
| **Collection** | 0% | 33% | **33%** | 15 |
| **Command and Control** | 5% | 50% | **52%** | 20 |
| **Exfiltration** | 0% | 50% | **50%** | 12 |
| **Impact** | 20% | 33% | **40%** | 15 |

### Covered MITRE ATT&CK Techniques

#### Initial Access
- T1078.003: Valid Accounts: Local Accounts
- T1078.004: Valid Accounts: Cloud Accounts
- T1566.001: Phishing: Spearphishing Attachment
- T1190: Exploit Public-Facing Application

#### Execution
- T1059.004: Command and Scripting Interpreter: Unix Shell
- T1059.001: Command and Scripting Interpreter: PowerShell
- T1053: Scheduled Task/Job
- T1106: Native API
- T1055: Process Injection
- T1072: Software Deployment Tools
- T1569: System Services

#### Persistence
- T1547.006: Boot or Logon Autostart Execution: Kernel Modules
- T1543: Create or Modify System Process
- T1546: Event Triggered Execution
- T1053: Scheduled Task/Job

#### Privilege Escalation
- T1548: Abuse Elevation Control Mechanism
- T1055: Process Injection
- T1068: Exploitation for Privilege Escalation
- T1547: Boot or Logon Autostart Execution

#### Defense Evasion
- T1070: Indicator Removal on Host
- T1027: Obfuscated Files or Information
- T1562: Impair Defenses
- T1070.004: Indicator Removal: File Deletion
- T1070.006: Indicator Removal: Timestomping

#### Credential Access
- T1003: OS Credential Dumping (T1003.001-005)
- T1555: Credentials from Password Stores (T1555.001-002)
- T1110: Brute Force
- T1078: Valid Accounts

#### Discovery
- T1082: System Information Discovery
- T1083: File and Directory Discovery
- T1018: Remote System Discovery
- T1046: Network Service Scanning
- T1040: Network Sniffing

#### Lateral Movement
- T1021: Remote Services
- T1072: Software Deployment Tools
- T1021.001: Remote Services: Remote Desktop Protocol
- T1021.004: Remote Services: SSH

#### Collection
- T1005: Data from Local System
- T1039: Data from Network Shared Drive
- T1114: Email Collection
- T1115: Clipboard Data
- T1119: Automated Collection
- T1123: Audio Capture
- T1125: Video Capture

#### Command and Control
- T1071: Application Layer Protocol
- T1095: Non-Application Layer Protocol
- T1573: Encrypted Channel
- T1105: Ingress Tool Transfer
- T1090: Proxy (Internal/External/Multi-hop)
- T1572: Protocol Tunneling
- T1568: Dynamic Resolution
- T1071.002: File Transfer Protocols

#### Exfiltration
- T1041: Exfiltration Over C2 Channel
- T1048: Exfiltration Over Alternative Protocol
- T1048.003: Exfiltration Over Unencrypted Non-C2 Protocol

#### Impact
- T1486: Data Encrypted for Impact
- T1496: Resource Hijacking
- T1485: Data Destruction
- T1487: Disk Structure Wipe
- T1488: Disk Content Wipe
- T1491: Defacement
- T1492: Stored Data Manipulation
- T1489: Service Stop
- T1490: Inhibit System Recovery

---

## 🔍 Detection Rules Coverage

### Wazuh Rules Coverage

**Covered Wazuh Rule Files:**
- ✅ `0020-syslog_rules.xml` - Syslog event detection
- ✅ `0085-pam_rules.xml` - PAM authentication events
- ✅ `0095-sshd_rules.xml` - SSH authentication and activity
- ✅ `0280-attack_rules.xml` - Attack detection (MITRE ATT&CK)
- ✅ `0365-auditd_rules.xml` - auditd event monitoring

**Reference:** https://github.com/wazuh/wazuh-ruleset/tree/master/rules

### Sigma Rules Coverage

**Covered Sigma Rule Categories:**
- ✅ `process_creation` - Process execution scenarios
- ✅ `file_create` - File creation scenarios
- ✅ `network_connection` - Network scenarios
- ✅ `builtin` - Builtin command abuse
- ✅ `auditd` - auditd-specific events
- ✅ `other` - Other scenarios

**Reference Repositories:**
- https://github.com/AliHaydarToprak/sigma/tree/master/rules/linux/auditd
- https://github.com/AliHaydarToprak/sigma/tree/master/rules/linux/builtin
- https://github.com/AliHaydarToprak/sigma/tree/master/rules/linux/file_create
- https://github.com/AliHaydarToprak/sigma/tree/master/rules/linux/network_connection
- https://github.com/AliHaydarToprak/sigma/tree/master/rules/linux/process_creation
- https://github.com/AliHaydarToprak/sigma/tree/master/rules/linux/other

### Security Content Coverage

**Covered Security Content:**
- ✅ Endpoint detection scenarios
- ✅ Process enumeration
- ✅ Connection monitoring
- ✅ SUID discovery
- ✅ Login enumeration

**Reference:** https://github.com/AliHaydarToprak/security_content/tree/develop/detections/endpoint

### Detection Rules Coverage

**Reference:** https://github.com/AliHaydarToprak/detection-rules/tree/main/rules/linux

### Linux Audit Log Cheatsheet

**Reference:** https://www.socinvestigation.com/linux-audit-logs-cheatsheet-detect-respond-faster/

---

## 🛡️ Hardening Checklist

### Coverage Areas

The `hardening.sh` script performs **100+ security checks** across **20 categories**:

1. **System Information** - OS, kernel, hostname
2. **File Permissions and Ownership** - Critical file permissions
3. **User Accounts and Passwords** - Account security, password policies
4. **SSH Configuration** - SSH security settings
5. **Firewall Configuration** - UFW, firewalld, iptables
6. **Kernel Parameters** - Security kernel parameters
7. **Services and Daemons** - Unnecessary service detection
8. **Logging and Auditing** - System logging, auditd
9. **Network Configuration** - Network security settings
10. **File System Security** - Partition security, mount options
11. **Package Management** - Updates, unnecessary packages
12. **Boot Security** - GRUB password, boot loader security
13. **Cron and Scheduled Tasks** - Cron security
14. **Environment Variables** - PATH, umask
15. **SELinux/AppArmor** - Mandatory Access Control
16. **SUID/SGID Files** - File permission security
17. **Network Services** - Listening services
18. **DNS Configuration** - DNS settings
19. **Time Synchronization** - NTP/Chrony
20. **Security Updates** - Update status, automatic updates

### Compliance Scoring

The script calculates a **compliance score** based on:
- **PASS** checks (counted as compliant)
- **FAIL** checks (counted as non-compliant)
- **WARN** checks (counted as partial compliance)
- **INFO** checks (informational only)

**Compliance Levels:**
- **80%+** - GOOD: System is well hardened
- **60-79%** - FAIR: Some improvements needed
- **<60%** - POOR: Significant hardening required

---

## 📄 Output & Reports

### Log Files

All scripts generate detailed log files:

- **AV Test:** `./av_test_results.log`
- **SIEM Test:** `./siem_test_results.log`
- **Hardening:** `./hardening-report-YYYYMMDD-HHMMSS.txt`

### Log Format

Each log entry includes:
- Timestamp
- Status (PASS/FAIL/WARN/INFO)
- Category
- Check name
- Details
- Recommendations (for FAIL/WARN)

**Example Log Entry:**
```
[2024-12-19 10:30:45] [FAIL] [SSH] PermitRootLogin - Current: yes (should be no) | Recommendation: Set PermitRootLogin no in /etc/ssh/sshd_config
```

### Console Output

All scripts provide:
- **Color-coded output** for easy reading
- **Real-time command execution** display
- **Step-by-step progress** indicators
- **Summary statistics** at the end
- **Detection point references** (SIEM script)

---

## 🔒 Safety & Security

### Safety Features

✅ **Sandbox Environment:** All tests run in isolated directories  
✅ **Non-Destructive:** No permanent changes to system files  
✅ **Automatic Cleanup:** All temporary files and processes are cleaned up  
✅ **Error Handling:** Graceful failure handling  
✅ **Safe Commands:** All commands are designed to be safe  
✅ **Rollback Capability:** Full rollback of any changes  

### Security Considerations

⚠️ **Root Access:** Some hardening checks may require root/sudo access  
⚠️ **Network Tests:** Some scenarios attempt network connections (to non-existent IPs)  
⚠️ **Log Generation:** Scripts generate log files that may contain sensitive information  
⚠️ **Process Creation:** Some scenarios create temporary processes  

### Best Practices

1. **Run in Test Environment:** Always test in a non-production environment first
2. **Review Logs:** Review generated log files for sensitive information
3. **Backup:** Ensure you have backups before running hardening checks
4. **Network Isolation:** Consider running in isolated network if concerned about network tests
5. **Review Recommendations:** Carefully review all FAIL recommendations before applying

---

## 🐛 Troubleshooting

### Common Issues

#### Issue: "Permission denied" errors
**Solution:** Some checks require root/sudo access. Run with appropriate permissions:
```bash
sudo ./hardening.sh
```

#### Issue: "Command not found" errors
**Solution:** Install missing dependencies:
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y wget curl nmap netcat openssl auditd

# RHEL/CentOS
sudo yum install -y wget curl nmap nc openssl audit
```

#### Issue: Script hangs or takes too long
**Solution:** Some network tests may timeout. This is expected behavior. Press Ctrl+C to interrupt if needed.

#### Issue: "Syntax error" when running script
**Solution:** Ensure the script has Unix line endings:
```bash
dos2unix hardening.sh
# or
sed -i 's/\r$//' hardening.sh
```

#### Issue: OS detection fails
**Solution:** The script will default to "unknown" OS. Most checks will still work.

### Getting Help

If you encounter issues:
1. Check the log files for detailed error messages
2. Verify you have the required permissions
3. Ensure all dependencies are installed
4. Check that your system supports the required commands

---

## 📈 Coverage Improvement Roadmap

### Phase 1: Critical Gaps (Completed ✅)
- ✅ Credential Access scenarios added
- ✅ Persistence mechanisms added
- ✅ Initial Access scenarios added
- ✅ Collection techniques added
- ✅ Defense Impairment added
- ✅ Advanced C2 techniques added
- ✅ Impact techniques added

### Phase 2: High Priority (In Progress)
- 🔄 Additional collection techniques
- 🔄 More C2 scenarios
- 🔄 Enhanced impact scenarios
- 🔄 Additional discovery techniques

### Phase 3: Medium Priority (Planned)
- 📋 Remaining discovery techniques
- 📋 Remaining exfiltration techniques
- 📋 Additional collection scenarios

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

1. **Additional Scenarios:** Add more MITRE ATT&CK technique coverage
2. **New Detection Rules:** Add support for additional detection rule formats
3. **OS Support:** Enhance support for additional Linux distributions
4. **Documentation:** Improve documentation and examples
5. **Testing:** Add automated testing capabilities

### Contribution Guidelines

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📚 References

### MITRE ATT&CK
- https://attack.mitre.org/

### Wazuh
- https://github.com/wazuh/wazuh-ruleset

### Sigma Rules
- https://github.com/SigmaHQ/sigma

### STIG
- https://public.cyber.mil/stigs/

### Linux Audit Logs
- https://www.socinvestigation.com/linux-audit-logs-cheatsheet-detect-respond-faster/

---

## 📊 Statistics

### Script Statistics

| Script | Scenarios/Checks | MITRE Coverage | Lines of Code |
|--------|------------------|----------------|---------------|
| `av-test.sh` | 22 scenarios | ~25% | ~970 |
| `siem-test.sh` | 70+ scenarios | ~65% | ~1,490 |
| `hardening.sh` | 100+ checks | N/A | ~880 |
| **Total** | **192+** | **~70%** | **~3,340** |

### Test Coverage

- **Total Test Scenarios:** 92+ (AV + SIEM)
- **Total Hardening Checks:** 100+
- **Combined MITRE ATT&CK Coverage:** ~70%
- **Wazuh Rules Coverage:** 5 rule files
- **Sigma Rules Coverage:** 6 categories
- **Security Content Coverage:** Endpoint detections

---

## 🎓 Usage Examples

### Example 1: Quick AV Test

```bash
# Run AV test and review results
./av-test.sh

# Check the log file
cat av_test_results.log | grep FAIL
```

### Example 2: Comprehensive SIEM Test

```bash
# Run SIEM test with all scenarios
./siem-test.sh

# Filter for specific Wazuh rules
cat siem_test_results.log | grep "0095-sshd_rules.xml"
```

### Example 3: Hardening Assessment

```bash
# Run full hardening assessment
sudo ./hardening.sh

# Review compliance score
tail -20 hardening-report-*.txt

# Focus on failures
cat hardening-report-*.txt | grep "\[FAIL\]"
```

### Example 4: Combined Testing

```bash
# Run all tests in sequence
./av-test.sh && ./siem-test.sh && sudo ./hardening.sh

# Generate combined report
echo "=== COMBINED SECURITY ASSESSMENT ===" > combined-report.txt
cat av_test_results.log >> combined-report.txt
cat siem_test_results.log >> combined-report.txt
cat hardening-report-*.txt >> combined-report.txt
```

---

## 🔄 Version History

### Version 1.0 (Current)
- ✅ 22 AV test scenarios
- ✅ 70+ SIEM test scenarios
- ✅ 100+ hardening checks
- ✅ MITRE ATT&CK ~70% coverage
- ✅ Wazuh, Sigma, Security Content integration
- ✅ Comprehensive logging and reporting

---

## 📝 License

This project is provided as-is for security testing and assessment purposes. Use responsibly and only in authorized environments.

---

## ⚠️ Disclaimer

These scripts are designed for **security testing and assessment purposes only**. 

- **Do not use in production systems** without proper authorization
- **Always test in isolated environments** first
- **Review all recommendations** before applying changes
- **Ensure you have proper backups** before running hardening checks
- **Use at your own risk**

The authors are not responsible for any damage or issues caused by the use of these scripts.

---

## 📧 Support

For issues, questions, or contributions:
- Review the troubleshooting section
- Check log files for detailed error messages
- Ensure all prerequisites are met
- Verify script permissions and dependencies

---

**Last Updated:** December 2024  
**Maintained By:** Security Testing Team  
**Compatibility:** Linux (Ubuntu, Debian, RHEL, CentOS, and similar distributions)

