#!/bin/bash
set -o pipefail

# ===============================================
# Project: Lightning Remote Scanner
# Module: Cyber Security – Network Research
# -----------------------------------------------
# Student Name: [yonatan avitan]
# Student ID: [s25]
# Class Code: [7736/39]
# Lecturer: [Tzah Azulis]
# ===============================================

REMOTE_USER="student"
REMOTE_HOST="35.222.109.227"
# NOTE: Using sshpass for automation purposes.
REMOTE_PASSWORD="12345678a" 
LOG_BASE_DIR="recon_output"
IP_CHECK_URL="https://ipapi.co/json"
SSH_TIMEOUT=20
SSH_MAX_ATTEMPTS=3
TOR_CHECK_ATTEMPTS=5
TOR_RETRY_DELAY=5
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_DIR="${LOG_BASE_DIR}/scan_${TIMESTAMP}"
LOGS_DIR="${LOG_DIR}/logs"
TARGET=""
SSH_AVAILABLE=false
CONFIG_FILE="recon.conf"
START_TIME=$(date +%s)
MODULE_STATUS=()


TOR_ENABLED=true
MODULE_WHOIS=true
MODULE_NMAP=true
MODULE_DNS=true
MODULE_REVERSE_DNS=true
MODULE_TRACEROUTE=true
MODULE_OS_DETECT=true

NMAP_OPTS="-Pn -sV -sC --top-ports 200 -T4 --min-rate 2000"

COLOR_BLUE="\033[94m"
COLOR_GREEN="\033[92m"
COLOR_YELLOW="\033[93m"
COLOR_RED="\033[91m"
COLOR_PURPLE="\033[95m"
COLOR_CYAN="\033[96m"
COLOR_GOLD="\033[93m"
COLOR_RESET="\033[0m"

show_disclaimer() {
    echo -e "${COLOR_GOLD}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║          Lightning Remote Scanner — Professional Reconnaissance Tool           ║"
    echo "║                            DISCLAIMER — READ BEFORE USE:                     ║"
    echo "║ This tool is provided solely for controlled, authorized, and isolated        ║"
    echo "║ cybersecurity training environments (VM-based labs). It is designed          ║"
    echo "║ exclusively for academic research, skill development, and lawful security    ║"
    echo "║ assessment conducted with explicit written permission.                       ║"
    echo "║                                                                              ║"
    echo "║ Unauthorized use of this tool against real networks, external systems,       ║"
    echo "║ production infrastructure, or any target without formal authorization is     ║"
    echo "║ strictly prohibited and may constitute a criminal offense under local and    ║"
    echo "║ international law.                                                           ║"
    echo "║                                                                              ║"
    echo "║ The author assumes NO responsibility and bears ZERO liability for any        ║"
    echo "║ misuse, damage, disruption, legal consequences, or unethical activities      ║"
    echo "║ performed by users of this tool.                                             ║"
    echo "║                                                                              ║"
    echo "║ By running this tool, the user acknowledges that THEY ALONE are fully and    ║"
    echo "║ legally responsible for their actions and outcomes arising from its use.     ║"
    echo "║                                                                              ║"
    echo "║ If you are not operating inside an approved lab environment with explicit    ║"
    echo "║ consent — DO NOT USE THIS TOOL.                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_RESET}\n"
    sleep 3
}

show_banner() {
    echo -e "\033[91m"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║                                                              ║"
    echo "  ║   ██╗     ██╗ ██████╗ ██╗  ██╗████████╗███╗   ██╗██╗███╗   ██╗ ██████╗     ║"
    echo "  ║   ██║     ██║██╔════╝ ██║  ██║╚══██╔══╝████╗  ██║██║████╗  ██║██╔════╝     ║"
    echo "  ║   ██║     ██║██║  ███╗███████║    ██║   ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗   ║"
    echo "  ║   ██║     ██║██║  ██║██╔══██║     ██║   ██║╚██╗██║██║██║╚██╗██║██║  ██║    ║"
    echo "  ║   ███████╗██║╚██████╔╝██║  ██║     ██║   ██║ ╚████║██║██║ ╚████║╚██████╔╝    ║"
    echo "  ║   ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝     ╚═╝   ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝     ║"
    echo "  ║                                                              ║"
    echo "  ║      ██████╗ ███████╗███╗   ███╗ ██████╗ ████████╗███████╗       ║"
    echo "  ║      ██╔══██╗██╔════╝████╗ ████║██╔═══██╗╚══██╔══╝██╔════╝       ║"
    echo "  ║      ██████╔╝█████╗  ██╔████╔██║██║   ██║    ██║   █████╗        ║"
    echo "  ║      ██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║    ██║   ██╔══╝        ║"
    echo "  ║      ██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝    ██║   ███████╗      ║"
    echo "  ║      ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝     ╚═╝   ╚══════╝      ║"
    echo "  ║                                                              ║"
    echo "  ║       ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗  ║"
    echo "  ║       ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗ ║"
    echo "  ║       ███████╗██║      ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝ ║"
    echo "  ║       ╚════██║██║      ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗ ║"
    echo "  ║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║ ║"
    echo "  ║       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ║"
    echo "  ║                                                              ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "\033[0m\n"
}

load_config() {
    [[ ! -f "$CONFIG_FILE" ]] && return 0
    echo -e "${COLOR_BLUE}[CONFIG] Loading configuration from $CONFIG_FILE${COLOR_RESET}"
    while IFS='=' read -r key value; do
        key=$(echo "$key" | tr -d ' ')
        value=$(echo "$value" | tr -d ' "'"'"'')
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        case "$key" in
            REMOTE_USER|REMOTE_HOST|REMOTE_PASSWORD) 
                
                eval "$key='$value'" ;;
            TOR_ENABLED|MODULE_WHOIS|MODULE_NMAP|MODULE_DNS|MODULE_REVERSE_DNS|MODULE_TRACEROUTE|MODULE_OS_DETECT)
                if [[ "$value" == "true" ]]; then
                    
                    eval "$key=true"
                else
                    
                    eval "$key=false"
                fi ;;
        esac
    done < "$CONFIG_FILE"
    echo -e "${COLOR_GREEN}[CONFIG] Configuration loaded successfully${COLOR_RESET}"
}

init_logging() {
    mkdir -p "$LOGS_DIR"
    LOG_FILE="${LOG_DIR}/framework.log"
    touch "$LOG_FILE" "${LOGS_DIR}"/{ssh,tor,recon,report,system}.log
}

log_to_file() {
    local module="$1" 
    local message="$2" 
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    case "$module" in
        SSH) echo "[$timestamp] $message" >> "${LOGS_DIR}/ssh.log" ;;
        TOR) echo "[$timestamp] $message" >> "${LOGS_DIR}/tor.log" ;;
        RECON) echo "[$timestamp] $message" >> "${LOGS_DIR}/recon.log" ;;
        REPORT) echo "[$timestamp] $message" >> "${LOGS_DIR}/report.log" ;;
        *) echo "[$timestamp] $message" >> "${LOGS_DIR}/system.log" ;;
    esac
}

log_message() {
    local level="$1" 
    local module="$2" 
    local message="$3" 
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local log_line="[$timestamp] [$level] [$module] $message" 
    local color=""
    case "$level" in
        INFO) color="$COLOR_BLUE" ;;
        SUCCESS) color="$COLOR_GREEN" ;;
        WARN) color="$COLOR_YELLOW" ;;
        ERROR) color="$COLOR_RED" ;;
    esac
    case "$module" in
        TOR) color="$COLOR_PURPLE" ;;
        SSH) color="$COLOR_CYAN" ;;
        RECON) color="$COLOR_GOLD" ;;
    esac
    echo "$log_line" >> "$LOG_FILE"
    log_to_file "$module" "$message"
    echo -e "${color}${log_line}${COLOR_RESET}"
}

log_info() { log_message "INFO" "$1" "$2"; }
log_warn() { log_message "WARN" "$1" "$2"; }
log_error() { log_message "ERROR" "$1" "$2"; }
log_success() { log_message "SUCCESS" "$1" "$2"; }

show_progress() {
    local message="$1" 
    local duration="${2:-3}"
    echo -ne "${COLOR_YELLOW}$message"
    
    
    for _ in $(seq 1 "$duration"); do 
        echo -n "."
        sleep 1
    done
    echo -e " done${COLOR_RESET}"
}

track_module_status() { MODULE_STATUS+=("$1:$2"); }

cleanup() {
    echo -e "${COLOR_YELLOW}[CLEANUP] Initiating cleanup procedures${COLOR_RESET}" | tee -a "$LOG_FILE"
    [[ -n "$REMOTE_PASSWORD" ]] && unset REMOTE_PASSWORD
    if systemctl is-active --quiet tor 2>/dev/null; then
        echo -e "${COLOR_YELLOW}[CLEANUP] Stopping Tor service${COLOR_RESET}" | tee -a "$LOG_FILE"
        sudo systemctl stop tor 2>/dev/null || true
    fi
    echo -e "${COLOR_GREEN}[CLEANUP] Cleanup completed${COLOR_RESET}" | tee -a "$LOG_FILE"
}
trap cleanup EXIT

check_root() {
    log_info "INIT" "Verifying root privileges"
    if [[ $EUID -ne 0 ]]; then
        log_error "INIT" "Root privileges required"
        echo -e "${COLOR_RED}ERROR: This script must be run as root\nUsage: sudo $0${COLOR_RESET}"
        exit 1
    fi
    log_success "INIT" "Root privileges verified"
}

check_dependency() {
    local package="$1"
    if ! command -v "$package" &>/dev/null; then
        log_warn "INIT" "Missing dependency: $package"
        echo -e "${COLOR_YELLOW}Installing $package...${COLOR_RESET}"
        if sudo apt-get install -y "$package" >/dev/null 2>&1; then
             log_success "INIT" "Installed $package"
        else
             log_error "INIT" "Failed to install $package"
             return 1
        fi
    else
        log_info "INIT" "Dependency present: $package"
    fi
    return 0
}

install_dependencies() {
    log_info "INIT" "Checking system dependencies"
    sudo apt-get update -y >/dev/null 2>&1
    local deps=(nmap whois curl tor torsocks jq sshpass pandoc texlive-xetex texlive-fonts-recommended) 
    local failed=0
    for dep in "${deps[@]}"; do 
        check_dependency "$dep" || failed=$((failed + 1))
    done
    
    if [[ $failed -gt 0 ]]; then
        log_warn "INIT" "$failed dependencies failed to install"
    else
        log_success "INIT" "All dependencies satisfied"
    fi
}

validate_config() {
    log_info "INIT" "Validating configuration"
    [[ -z "$REMOTE_PASSWORD" ]] && { log_error "INIT" "REMOTE_PASSWORD not configured"; exit 1; }
    [[ -z "$REMOTE_HOST" ]] && { log_error "INIT" "REMOTE_HOST not configured"; exit 1; }
    log_success "INIT" "Configuration validated"
}

start_tor() {
    [[ "$TOR_ENABLED" != true ]] && { log_info "TOR" "Tor disabled in configuration - skipping"; return 0; }
    log_info "TOR" "Starting Tor service"
    
    if ! systemctl is-active --quiet tor; then
        sudo systemctl start tor >/dev/null 2>&1
        show_progress "$(echo -e "${COLOR_PURPLE}[TOR] Waiting for Tor to initialize${COLOR_RESET}")" 3
    fi

    if systemctl is-active --quiet tor; then
        log_success "TOR" "Tor service active"
        return 0
    else
        log_warn "TOR" "Tor service failed to start (non-fatal)"
        return 1
    fi
}

verify_tor_anonymity() {
    [[ "$TOR_ENABLED" != true ]] && return 0
    log_info "TOR" "Verifying Tor anonymity"
    local original_ip
    original_ip=$(curl -s "$IP_CHECK_URL" --max-time 10 | jq -r '.ip' 2>/dev/null)
    
    [[ -z "$original_ip" || "$original_ip" == "null" ]] && { log_warn "TOR" "Could not determine original IP"; }
    
    log_info "TOR" "Original IP: $original_ip"
    local attempt=1
    
    while [[ $attempt -le $TOR_CHECK_ATTEMPTS ]]; do
        log_info "TOR" "Checking Tor IP (attempt $attempt)"
        
        local tor_response
        tor_response=$(torsocks curl -s "$IP_CHECK_URL" --max-time 15 2>/dev/null)
        local tor_ip
        tor_ip=$(echo "$tor_response" | jq -r '.ip' 2>/dev/null)
        local tor_country
        tor_country=$(echo "$tor_response" | jq -r '.country_name' 2>/dev/null) 
        
        if [[ -n "$tor_ip" && "$tor_ip" != "$original_ip" && "$tor_ip" != "null" ]]; then
            log_success "TOR" "Anonymity verified - Tor IP: $tor_ip (Country: $tor_country)" 
            echo -e "${COLOR_GREEN}✅ Connection is anonymous via $tor_country (IP: $tor_ip)${COLOR_RESET}" 
            return 0
        fi
        attempt=$((attempt + 1))
        [[ $attempt -le $TOR_CHECK_ATTEMPTS ]] && sleep $TOR_RETRY_DELAY
    done
    
    log_error "TOR" "Tor anonymity verification failed after $TOR_CHECK_ATTEMPTS attempts."
    return 1 
}

execute_remote_command() {
    [[ "$SSH_AVAILABLE" != true ]] && { log_error "SSH" "SSH not available - command skipped"; return 1; }
    local result 
    local exit_code
    result=$(sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT" -o LogLevel=ERROR "${REMOTE_USER}@${REMOTE_HOST}" "$1" 2>&1)
    exit_code=$?
    [[ $exit_code -ne 0 ]] && { log_error "SSH" "Remote command failed (exit: $exit_code)"; return 1; }
    echo "$result"
    return 0
}

establish_ssh_connection() {
    log_info "SSH" "Establishing SSH connection to ${REMOTE_USER}@${REMOTE_HOST}"
    local attempt=1
    while [[ $attempt -le $SSH_MAX_ATTEMPTS ]]; do
        log_info "SSH" "Connection attempt $attempt of $SSH_MAX_ATTEMPTS"
        
        local check_output
        check_output=$(sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$SSH_TIMEOUT" -o LogLevel=ERROR "${REMOTE_USER}@${REMOTE_HOST}" "echo SSH_TEST_OK" 2>/dev/null)
        
        if echo "$check_output" | grep -q "SSH_TEST_OK"; then 
            log_success "SSH" "Connection established successfully"
            SSH_AVAILABLE=true
            track_module_status "SSH_Connection" "SUCCESS"
            return 0
        fi
        
        attempt=$((attempt + 1))
        [[ $attempt -le $SSH_MAX_ATTEMPTS ]] && sleep 5
    done
    
    log_error "SSH" "Failed to establish connection after $SSH_MAX_ATTEMPTS attempts"
    log_warn "SSH" "Entering limited mode - local scans only"
    SSH_AVAILABLE=false
    track_module_status "SSH_Connection" "FAILED"
    return 1
}

fetch_jump_host_stats() {
    log_info "SSH" "Retrieving jump host information"
    [[ "$SSH_AVAILABLE" != true ]] && { log_warn "SSH" "SSH unavailable - skipping remote info"; return 1; }
    local remote_ip
    local remote_country
    local remote_uptime
    remote_ip=$(execute_remote_command "curl -s https://api.ipify.org 2>/dev/null")
    remote_country=$(execute_remote_command "curl -s https://ipapi.co/country_name 2>/dev/null")
    remote_uptime=$(execute_remote_command "uptime -p 2>/dev/null")
    if [[ -n "$remote_ip" ]]; then
        log_info "SSH" "Jump host IP: $remote_ip"
        log_info "SSH" "Jump host country: $remote_country"
        log_info "SSH" "Jump host uptime: $remote_uptime"
        echo "$remote_ip" > "${LOG_DIR}/jumphost_ip.txt"
        echo "$remote_country" > "${LOG_DIR}/jumphost_country.txt"
        echo "$remote_uptime" > "${LOG_DIR}/jumphost_uptime.txt"
        return 0
    fi
    log_warn "SSH" "Could not retrieve remote information"
    return 1
}

prompt_target() {
    log_info "INPUT" "Prompting for target address"
    while true; do
        echo -e -n "${COLOR_CYAN}Enter target address (IP or domain): ${COLOR_RESET}"
        read -r TARGET
        [[ -z "$TARGET" ]] && { echo -e "${COLOR_RED}ERROR: Target cannot be empty${COLOR_RESET}"; continue; }
        TARGET=$(echo "$TARGET" | tr -d '[:space:]' | tr -cd '[:alnum:]._-')
        [[ -n "$TARGET" ]] && { log_success "INPUT" "Target set: $TARGET"; echo "$TARGET" > "${LOG_DIR}/target.txt"; break; }
    done
}

run_recon_module() {
    local module_flag="$1" 
    local module_name="$2" 
    local log_msg="$3" 
    local progress_msg="$4" 
    local duration="$5" 
    local output_file="${LOG_DIR}/$6" 
    local cmd="$7"
    
    if [[ "${!module_flag}" != true ]]; then
        log_info "RECON" "$module_name module disabled - skipping"
        return 0
    fi
    
    log_info "RECON" "$log_msg"
    show_progress "$(echo -e "${COLOR_GOLD}[RECON] $progress_msg${COLOR_RESET}")" "$duration"
    
    if [[ "$SSH_AVAILABLE" == true ]]; then
        if execute_remote_command "$cmd" > "$output_file"; then
             log_success "RECON" "$module_name completed (remote)"
             track_module_status "$module_name" "SUCCESS"
             return 0
        fi
        
        if [[ "$cmd" =~ nmap ]]; then
            if execute_remote_command "sudo $cmd" > "$output_file"; then
                log_success "RECON" "$module_name completed (remote with sudo)"
                track_module_status "$module_name" "SUCCESS"
                return 0
            fi
        fi
    fi
    
    log_info "RECON" "Running $module_name locally"
    
    eval "$cmd" > "$output_file" 2>&1 && { log_success "RECON" "$module_name completed (local)"; track_module_status "$module_name" "SUCCESS"; return 0; }
    log_error "RECON" "$module_name failed"
    track_module_status "$module_name" "FAILED"
    return 1
}

run_whois() { run_recon_module "MODULE_WHOIS" "WHOIS" "Running WHOIS scan on $TARGET" "Executing WHOIS query" 2 "whois_${TARGET}.txt" "whois $TARGET"; }
perform_port_scan() { run_recon_module "MODULE_NMAP" "Nmap" "Running Nmap scan on $TARGET" "Executing Nmap port scan" 5 "nmap_${TARGET}.txt" "nmap $NMAP_OPTS $TARGET"; } 
run_dns_lookup() { run_recon_module "MODULE_DNS" "DNS_Lookup" "Running DNS lookup on $TARGET" "Performing DNS resolution" 2 "dns_${TARGET}.txt" "nslookup $TARGET"; }
run_reverse_lookup() { run_recon_module "MODULE_REVERSE_DNS" "Reverse_DNS" "Running reverse DNS lookup on $TARGET" "Performing reverse DNS" 2 "reverse_dns_${TARGET}.txt" "host $TARGET"; }
run_traceroute() { run_recon_module "MODULE_TRACEROUTE" "Traceroute" "Running traceroute to $TARGET" "Tracing network route" 3 "traceroute_${TARGET}.txt" "traceroute -m 15 $TARGET"; }

run_os_detection() {
    [[ "$MODULE_OS_DETECT" != true ]] && { log_info "RECON" "OS detection module disabled - skipping"; return 0; }
    log_info "RECON" "Running OS detection on $TARGET"
    show_progress "$(echo -e "${COLOR_GOLD}[RECON] Detecting operating system${COLOR_RESET}")" 4
    local output_file="${LOG_DIR}/os_detection_${TARGET}.txt"
    
    if [[ "$SSH_AVAILABLE" == true ]]; then
         if execute_remote_command "sudo nmap -O $TARGET" > "$output_file"; then
             log_success "RECON" "OS detection completed (remote)"
             track_module_status "OS_Detection" "SUCCESS"
             return 0
         fi
    fi
    
    log_info "RECON" "Running OS detection locally"
    
    if nmap -O "$TARGET" > "$output_file" 2>&1; then
        log_success "RECON" "OS detection completed (local)"
        track_module_status "OS_Detection" "SUCCESS"
        return 0
    fi
    
    log_warn "RECON" "OS detection failed"
    track_module_status "OS_Detection" "FAILED"
    return 1
}

generate_markdown_report() {
    log_info "REPORT" "Generating Markdown report"
    local report_file="${LOG_DIR}/report.md"
    cat > "$report_file" <<EOF
# Network Reconnaissance Report

## Scan Information

- **Target:** $TARGET
- **Timestamp:** $(date +"%Y-%m-%d %H:%M:%S")
- **Log Directory:** $LOG_DIR
- **SSH Mode:** $([ "$SSH_AVAILABLE" = true ] && echo "Remote via $REMOTE_HOST" || echo "Local only")

---

## Jump Host Information

EOF
    if [[ -f "${LOG_DIR}/jumphost_ip.txt" ]]; then
        cat >> "$report_file" <<EOF
- **IP Address:** $(cat "${LOG_DIR}/jumphost_ip.txt")
- **Country:** $(cat "${LOG_DIR}/jumphost_country.txt")
- **Uptime:** $(cat "${LOG_DIR}/jumphost_uptime.txt")

EOF
    else
        echo -e "- Jump host information unavailable\n" >> "$report_file"
    fi
    for section in "WHOIS Results:whois" "Nmap Scan Results:nmap" "DNS Lookup:dns" "Reverse DNS Lookup:reverse_dns" "Traceroute:traceroute" "OS Detection:os_detection"; do
        local title="${section%:*}" 
        local file="${section#*:}"
        cat >> "$report_file" <<EOF
---

## $title

\`\`\`
$(cat "${LOG_DIR}/${file}_${TARGET}.txt" 2>/dev/null || echo "$title unavailable")
\`\`\`

EOF
    done
    cat >> "$report_file" <<EOF
---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Open Ports | $(grep -c "open" "${LOG_DIR}/nmap_${TARGET}.txt" 2>/dev/null || echo "0") |
| Scan Files | $(find "$LOG_DIR" -maxdepth 1 -type f | wc -l) |
| Total Size | $(du -sh "$LOG_DIR" | cut -f1) |

---

## Notes

- All scans performed under authorized conditions
- Data collected for security assessment purposes only
- Report generated automatically by reconnaissance framework

EOF
    log_success "REPORT" "Markdown report created: $report_file"
    track_module_status "Report_Markdown" "SUCCESS"
}

generate_html_report() {
    log_info "REPORT" "Generating HTML report"
    local html_file="${LOG_DIR}/report.html"
    cat > "$html_file" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Network Reconnaissance Report</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;line-height:1.6}.container{max-width:1200px;margin:0 auto;background:#161b22;border-radius:8px;padding:30px;box-shadow:0 4px 6px rgba(0,0,0,0.3)}h1{color:#58a6ff;border-bottom:2px solid #21262d;padding-bottom:10px;margin-bottom:20px}h2{color:#58a6ff;margin-top:30px;margin-bottom:15px;border-left:4px solid #58a6ff;padding-left:10px}pre{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:15px;overflow-x:auto;font-size:14px;line-height:1.4}table{width:100%;border-collapse:collapse;margin:20px 0}th,td{padding:12px;text-align:left;border-bottom:1px solid #21262d}th{background:#0d1117;color:#58a6ff;font-weight:600}.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:15px;margin:20px 0}.info-card{background:#0d1117;padding:15px;border-radius:6px;border-left:3px solid #58a6ff}.info-label{color:#8b949e;font-size:12px;text-transform:uppercase;margin-bottom:5px}.info-value{color:#c9d1d9;font-size:16px;font-weight:500}hr{border:none;border-top:1px solid #21262d;margin:30px 0}</style></head><body><div class="container"><h1>Network Reconnaissance Report</h1>
EOF
    cat >> "$html_file" <<EOF
<h2>Scan Information</h2><div class="info-grid"><div class="info-card"><div class="info-label">Target</div><div class="info-value">$TARGET</div></div><div class="info-card"><div class="info-label">Timestamp</div><div class="info-value">$(date +"%Y-%m-%d %H:%M:%S")</div></div><div class="info-card"><div class="info-label">Mode</div><div class="info-value">$([ "$SSH_AVAILABLE" = true ] && echo "Remote" || echo "Local")</div></div></div><hr>
EOF
    for section in "WHOIS Results:whois" "Nmap Scan Results:nmap" "DNS Lookup:dns" "Reverse DNS Lookup:reverse_dns" "Traceroute:traceroute" "OS Detection:os_detection"; do
        local title="${section%:*}" 
        local file="${section#*:}"
        
        
        {
            echo "<h2>$title</h2><pre>"
            cat "${LOG_DIR}/${file}_${TARGET}.txt" 2>/dev/null || echo "$title unavailable"
            echo "</pre><hr>"
        } >> "$html_file"
    done
    cat >> "$html_file" <<EOF
<h2>Summary Statistics</h2><table><tr><th>Metric</th><th>Value</th></tr><tr><td>Open Ports</td><td>$(grep -c "open" "${LOG_DIR}/nmap_${TARGET}.txt" 2>/dev/null || echo "0")</td></tr><tr><td>Scan Files</td><td>$(find "$LOG_DIR" -maxdepth 1 -type f | wc -l)</td></tr><tr><td>Total Size</td><td>$(du -sh "$LOG_DIR" | cut -f1)</td></tr></table></div></body></html>
EOF
    log_success "REPORT" "HTML report created: $html_file"
    track_module_status "Report_HTML" "SUCCESS"
}

generate_pdf_report() {
    log_info "REPORT" "Generating PDF report"
    if command -v pandoc &>/dev/null && command -v xelatex &>/dev/null; then
        if pandoc "${LOG_DIR}/report.md" --from markdown --pdf-engine=xelatex --toc -V colorlinks=true -V linkcolor=blue -V mainfont="DejaVu Sans" -o "${LOG_DIR}/report.pdf" 2>/dev/null; then
             log_success "REPORT" "PDF report created: ${LOG_DIR}/report.pdf"
             track_module_status "Report_PDF" "SUCCESS"
             return 0
        else
             log_error "REPORT" "PDF generation failed"
             track_module_status "Report_PDF" "FAILED"
             return 1
        fi
    else
        log_warn "REPORT" "Pandoc or XeLaTeX not available - PDF generation skipped"
        track_module_status "Report_PDF" "SKIPPED"
        return 1
    fi
}

generate_json_summary() {
    log_info "REPORT" "Generating JSON summary"
    local json_file="${LOG_DIR}/scan_summary.json" 
    local end_time
    end_time=$(date +%s) 
    local execution_time=$((end_time - START_TIME))
    cat > "$json_file" <<EOF
{"scan_metadata":{"target":"$TARGET","start_time":"$(date -d @"$START_TIME" +"%Y-%m-%d %H:%M:%S")","end_time":"$(date -d @"$end_time" +"%Y-%m-%d %H:%M:%S")","execution_time_seconds":$execution_time,"scan_mode":"$([ "$SSH_AVAILABLE" = true ] && echo "remote" || echo "local")","log_directory":"$LOG_DIR"},"configuration":{"remote_host":"$REMOTE_HOST","remote_user":"$REMOTE_USER","tor_enabled":$([[ "$TOR_ENABLED" == true ]] && echo "true" || echo "false")},"module_status":{
EOF
    local first=true
    for status_entry in "${MODULE_STATUS[@]}"; do
        [[ "$first" == true ]] && first=false || echo "," >> "$json_file"
        echo -n "\"${status_entry%:*}\":\"${status_entry#*:}\"" >> "$json_file"
    done
    cat >> "$json_file" <<EOF
},"statistics":{"open_ports":$(grep -c "open" "${LOG_DIR}/nmap_${TARGET}.txt" 2>/dev/null || echo "0"),"total_files":$(find "$LOG_DIR" -maxdepth 1 -type f | wc -l),"total_size_bytes":$(du -sb "$LOG_DIR" 2>/dev/null | cut -f1)}}
EOF
    log_success "REPORT" "JSON summary created: $json_file"
    track_module_status "Report_JSON" "SUCCESS"
}

open_html_report() {
    local html_file="${LOG_DIR}/report.html"
    [[ ! -f "$html_file" ]] && { log_warn "REPORT" "HTML report not found - cannot open"; return 1; }
    log_info "REPORT" "Opening HTML report in browser"
    for browser in xdg-open firefox chromium google-chrome; do
        if command -v "$browser" &>/dev/null; then
            "$browser" "$html_file" &>/dev/null &
            log_success "REPORT" "HTML report opened with $browser"
            return 0
        fi
    done
    log_warn "REPORT" "No suitable browser found to open HTML report"
    echo -e "${COLOR_YELLOW}Please open manually: $html_file${COLOR_RESET}"
}

print_section() { echo -e "\n${1}==========================================${COLOR_RESET}\n${1} $2${COLOR_RESET}\n${1}==========================================${COLOR_RESET}\n"; }

main() {
    show_disclaimer
    show_banner
    load_config
    init_logging
    log_info "MAIN" "Framework execution started"
    check_root
    validate_config
    install_dependencies
    
    print_section "$COLOR_PURPLE" "Tor Anonymity Layer"
    start_tor
    
    if [[ "$TOR_ENABLED" == true ]]; then
        if ! verify_tor_anonymity; then 
            log_error "MAIN" "Tor anonymity could not be verified - aborting scan for security reasons (Required by project)"
            echo -e "${COLOR_RED}[FATAL] Cannot proceed without verified anonymity. Exiting.${COLOR_RESET}"
            exit 1
        fi
    fi

    print_section "$COLOR_CYAN" "SSH Connection"
    establish_ssh_connection
    fetch_jump_host_stats 
    
    print_section "$COLOR_BLUE" "Target Configuration"
    prompt_target
    
    print_section "$COLOR_GOLD" "Reconnaissance Operations"
    run_whois
    perform_port_scan 
    run_dns_lookup
    run_reverse_lookup
    run_traceroute
    run_os_detection
    
    print_section "$COLOR_BLUE" "Report Generation"
    generate_markdown_report
    generate_html_report
    generate_pdf_report
    generate_json_summary
    
    print_section "$COLOR_GREEN" "Scan Complete"
    echo -e "${COLOR_GREEN}Results saved to: $LOG_DIR${COLOR_RESET}"
    echo -e "${COLOR_GREEN}Execution time: $(($(date +%s) - START_TIME)) seconds${COLOR_RESET}\n"
    log_success "MAIN" "All operations completed successfully"
    open_html_report
}

main "$@"
