#!/bin/bash
################################################################################
# TITAN VULNERABILITY SCANNER
# Student: S25 | Class: 7736-39 | Lecturer: Tzach Azoulis | Project: zx301
# Version: 2.0.0
################################################################################

set -uo pipefail

# ── Constants ──────────────────────────────────────────────────────────────────
readonly VERSION="2.0.0"
readonly STUDENT_ID="S25"
readonly CLASS_ID="7736-39"
readonly PROJECT_ID="zx301"

readonly BOLD="\033[1m"
readonly RED="\033[1;31m"
readonly GRN="\033[1;32m"
readonly YLW="\033[1;33m"
readonly CYN="\033[1;36m"
readonly MAG="\033[1;35m"
readonly NC="\033[0m"

readonly NMAP_RETRIES=1
readonly ATTACK_TIMEOUT=300
DRY_RUN="${DRY_RUN:-0}"

# Globals set during input collection
TARGET=""
OUTDIR=""
MODE=""
PASSFILE=""
CORES=1          # set by calculate_optimal_threads
NMAP_RATE=2000   # overridden after thread calculation
HYDRA_TASKS=4    # -t  connections per host
HYDRA_SERVERS=1  # -T  parallel hosts

# ── Signal handling – Ctrl+C exits immediately ────────────────────────────────
TMPDIR_TITAN=""
cleanup() {
    [[ -n "$TMPDIR_TITAN" && -d "$TMPDIR_TITAN" ]] && rm -rf "$TMPDIR_TITAN"
}
abort() {
    echo ""
    echo -e "${RED}[!] Interrupted – exiting cleanly.${NC}"
    cleanup
    exit 130
}
trap abort  INT TERM
trap cleanup EXIT

# ── Logging ────────────────────────────────────────────────────────────────────
info()  { echo -e "${CYN}[*]${NC} $*"; }
ok()    { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*" >&2; }
die()   { err "$*"; exit 1; }
phase() {
    echo ""
    echo -e "${MAG}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${MAG}${BOLD}  $*${NC}"
    echo -e "${MAG}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ── Root check ─────────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root.  →  sudo $0"
    fi
    ok "Running as root"
}

# ── Calculate optimal threads from available CPU cores ────────────────────────
calculate_optimal_threads() {
    local cpu_cores
    cpu_cores=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 2)

    local load=0
    if command -v uptime &>/dev/null; then
        load=$(uptime | awk -F'load average:' '{print $2}' | awk '{printf "%d", $1}' 2>/dev/null || echo 0)
    fi

    local free_cores=$(( cpu_cores - load ))
    [[ $free_cores -lt 1 ]] && free_cores=1

    CORES=$free_cores

    # Scale scan speed and hydra parallelism from cores
    NMAP_RATE=$(( 1000 + CORES * 500 ))        # e.g. 4 cores → 3000 pkt/s
    HYDRA_TASKS=$(( CORES * 4 ))               # connections per host
    HYDRA_SERVERS=$(( CORES ))                 # parallel hosts
    [[ $HYDRA_TASKS -lt 4  ]] && HYDRA_TASKS=4
    [[ $HYDRA_SERVERS -lt 1 ]] && HYDRA_SERVERS=1

    ok "System: $cpu_cores CPU core(s) | Free: $CORES | nmap rate: $NMAP_RATE pkt/s | hydra tasks: $HYDRA_TASKS | hydra hosts: $HYDRA_SERVERS"
}

# ── Requirements ───────────────────────────────────────────────────────────────
check_requirements() {
    info "Checking requirements..."
    local missing=()
    for t in nmap hydra zip grep awk; do
        command -v "$t" &>/dev/null || missing+=("$t")
    done
    [[ ${#missing[@]} -gt 0 ]] && die "Missing tools: ${missing[*]}  →  apt install ${missing[*]}"
    command -v searchsploit &>/dev/null || warn "searchsploit not found – exploit search will be skipped"
    ok "Required tools found"
}

# ── Banner ─────────────────────────────────────────────────────────────────────
banner() {
    clear
    echo -e "${MAG}"
    echo "  ████████╗██╗████████╗ █████╗ ███╗   ██╗"
    echo "  ╚══██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║"
    echo "     ██║   ██║   ██║   ███████║██╔██╗ ██║"
    echo "     ██║   ██║   ██║   ██╔══██║██║╚██╗██║"
    echo "     ██║   ██║   ██║   ██║  ██║██║ ╚████║"
    echo "     ╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝"
    echo -e "${NC}"
    echo -e "${CYN}  Vulnerability Scanner v${VERSION}${NC}"
    echo -e "${YLW}  Student: ${STUDENT_ID} | Class: ${CLASS_ID} | Lecturer: Tzach Azoulis${NC}"
    echo ""
}

# ── Ethics check ───────────────────────────────────────────────────────────────
ethics_check() {
    echo ""
    echo -e "${RED}${BOLD}  ⚠  LEGAL WARNING  ⚠${NC}"
    echo -e "${YLW}  Unauthorized scanning is illegal.${NC}"
    echo -e "${YLW}  You must have written authorization before proceeding.${NC}"
    echo ""
    read -rp "  Do you have written authorization? [yes/no]: " ans
    [[ "$ans" == "yes" ]] || die "Authorization not confirmed. Exiting."
    ok "Authorization confirmed"
}

# ── Validation ─────────────────────────────────────────────────────────────────
validate_cidr() {
    local in="$1"
    [[ $in =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]] || return 1
    local ip="${in%/*}"
    IFS='.' read -ra O <<< "$ip"
    for o in "${O[@]}"; do [[ $o -gt 255 ]] && return 1; done
    return 0
}

# ── User inputs ────────────────────────────────────────────────────────────────
get_inputs() {
    # Target
    while true; do
        echo ""
        read -rp "$(echo -e "${BOLD}Target IP/CIDR (e.g. 192.168.1.0/24): ${NC}")" TARGET
        validate_cidr "$TARGET" && { ok "Target: $TARGET"; break; }
        err "Invalid IP/CIDR format"
    done

    # Output directory
    while true; do
        echo ""
        read -rp "$(echo -e "${BOLD}Output directory name: ${NC}")" dname
        [[ "$dname" =~ ^[a-zA-Z0-9_-]+$ ]] || { err "Use only a-z A-Z 0-9 - _"; continue; }
        OUTDIR="${dname}_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$OUTDIR"/{scans,credentials,logs,exploits} && { ok "Workspace: $OUTDIR"; break; }
        err "Cannot create directory – check permissions"
    done

    # Scan mode  (criteria 1.3.1 / 1.3.2)
    echo ""
    echo -e "${BOLD}Scan Mode:${NC}"
    echo -e "  ${CYN}1)${NC} Basic – TCP + UDP, service versions, weak passwords"
    echo -e "  ${CYN}2)${NC} Full  – Basic + NSE vulnerability scripts + Searchsploit"
    while true; do
        read -rp "$(echo -e "${BOLD}Choice [1/2]: ${NC}")" ch
        case "$ch" in
            1) MODE="Basic"; info "Mode: BASIC"; break ;;
            2) MODE="Full";  info "Mode: FULL";  break ;;
            *) err "Enter 1 or 2" ;;
        esac
    done

    # Password list  (criteria 2.1.1 built-in / 2.1.2 custom)
    echo ""
    read -rp "$(echo -e "${BOLD}Use custom password list? [y/n]: ${NC}")" cpw
    if [[ "$cpw" =~ ^[Yy]$ ]]; then
        while true; do
            read -rp "$(echo -e "${BOLD}Path to password list: ${NC}")" ppath
            [[ -f "$ppath" && -r "$ppath" ]] && { PASSFILE="$ppath"; ok "Password list: $ppath"; break; }
            err "File not found or not readable: $ppath"
        done
    else
        PASSFILE="$(mktemp -t titan_pass.XXXXXX)"
        chmod 600 "$PASSFILE"
        cat > "$PASSFILE" <<'PWEOF'
admin
123456
password
root
toor
Administrator
1234
admin123
qwerty
letmein
welcome
monkey
dragon
master
login
pass
test
guest
oracle
changeme
PWEOF
        ok "Using built-in password list (20 entries)"
    fi
}

# ── Phase 1 – Network scan ─────────────────────────────────────────────────────
run_nmap() {
    phase "PHASE 1 · Network Discovery & Service Enumeration"

    local base="$OUTDIR/scans/nmap_scan"
    local nse_opt=""
    [[ "$MODE" == "Full" ]] && nse_opt="-O --script vuln,exploit"

    info "Using nmap rate: $NMAP_RATE pkt/s | retries: $NMAP_RETRIES"

    # ── TCP scan (SYN + version, both modes) ──
    info "Starting TCP scan..."
    if [[ $DRY_RUN -eq 1 ]]; then
        warn "DRY RUN: nmap -sS -sV $nse_opt --open -T4 --min-rate $NMAP_RATE -oA ${base}_tcp $TARGET"
        touch "${base}_tcp.gnmap" "${base}_tcp.xml" "${base}_tcp.nmap"
    else
        nmap -sS -sV $nse_opt --open -T4 \
            --min-rate "$NMAP_RATE" \
            --max-retries "$NMAP_RETRIES" \
            --min-parallelism "$CORES" \
            -oA "${base}_tcp" \
            -oX "${base}_tcp.xml" \
            "$TARGET" 2>&1 | tee -a "$OUTDIR/logs/scan.log" \
            || warn "TCP scan ended (may be partial)"
    fi

    # ── UDP scan top-100 (criteria 1.3.1 – Basic must include UDP) ──
    info "Starting UDP scan (top 100 ports)..."
    if [[ $DRY_RUN -eq 1 ]]; then
        warn "DRY RUN: nmap -sU --top-ports 100 -sV --open -T4 --min-rate $NMAP_RATE -oA ${base}_udp $TARGET"
        touch "${base}_udp.gnmap" "${base}_udp.nmap"
    else
        nmap -sU --top-ports 100 -sV --open -T4 \
            --min-rate "$NMAP_RATE" \
            --max-retries "$NMAP_RETRIES" \
            --min-parallelism "$CORES" \
            -oA "${base}_udp" \
            "$TARGET" 2>&1 | tee -a "$OUTDIR/logs/scan.log" \
            || warn "UDP scan ended (may be partial)"
    fi

    # Merge outputs – downstream always reads nmap_scan.gnmap
    cat "${base}_tcp.gnmap" "${base}_udp.gnmap" 2>/dev/null > "${base}.gnmap" || true
    cat "${base}_tcp.nmap"  "${base}_udp.nmap"  2>/dev/null > "${base}.nmap"  || true
    cp  "${base}_tcp.xml"                          "${base}.xml" 2>/dev/null   || true

    ok "Nmap phase complete"
}

# ── Phase 2 – Credential testing ──────────────────────────────────────────────
# Criteria 2.1 / 2.2: SSH (22), FTP (21), RDP (3389), TELNET (23)

# Count lines safely – grep -c exits 1 on zero matches which breaks || logic
count_lines() { grep -c "" "$1" 2>/dev/null || true; }

extract_hosts() {
    local gnmap="$1" port="$2" out="$3"
    if [[ -f "$gnmap" ]]; then
        grep "Ports:" "$gnmap" | grep "${port}/open" | awk '{print $2}' | sort -u > "$out"
    else
        touch "$out"
    fi
    # wc -l always exits 0 – no double-count bug
    local n; n=$(wc -l < "$out" 2>/dev/null || echo 0)
    n="${n// /}"   # trim whitespace
    info "  Port $port – $n host(s) found"
}

attack_service() {
    local svc="$1" hosts="$2" user="$3"
    local out="$OUTDIR/credentials/${svc}_cracked.txt"
    local log="$OUTDIR/logs/${svc}_hydra.log"

    if [[ ! -s "$hosts" ]]; then
        info "  [$svc] No targets – skipping"
        return
    fi

    local count; count=$(wc -l < "$hosts"); count="${count// /}"
    info "  [$svc] $count host(s) | tasks/host: $HYDRA_TASKS | parallel hosts: $HYDRA_SERVERS | user: $user"

    if [[ $DRY_RUN -eq 1 ]]; then
        warn "  DRY RUN: hydra -M $hosts -l $user -P $PASSFILE -t $HYDRA_TASKS -T $HYDRA_SERVERS $svc"
        echo "[DRY RUN] $svc sample" > "$out"
        return
    fi

    timeout "$ATTACK_TIMEOUT" hydra \
        -M  "$hosts"         \
        -l  "$user"          \
        -P  "$PASSFILE"      \
        -t  "$HYDRA_TASKS"   \
        -T  "$HYDRA_SERVERS" \
        -I                   \
        -o  "$out"           \
        "$svc" >> "$log" 2>&1

    local rc=$?
    if   [[ $rc -eq 124 ]]; then warn "  [$svc] Timed out after ${ATTACK_TIMEOUT}s"
    elif [[ -s "$out"   ]]; then warn "  [$svc] ⚠  WEAK CREDENTIALS FOUND!"; cat "$out"
    else                         ok   "  [$svc] No weak credentials found"
    fi
}

run_credential_attacks() {
    phase "PHASE 2 · Weak Credential Discovery (SSH · FTP · RDP · TELNET)"

    TMPDIR_TITAN="$(mktemp -d -t titan.XXXXXX)"
    local gnmap="$OUTDIR/scans/nmap_scan.gnmap"

    info "Extracting targets per service..."
    extract_hosts "$gnmap" 22   "$TMPDIR_TITAN/ssh_hosts.txt"
    extract_hosts "$gnmap" 21   "$TMPDIR_TITAN/ftp_hosts.txt"
    extract_hosts "$gnmap" 3389 "$TMPDIR_TITAN/rdp_hosts.txt"
    extract_hosts "$gnmap" 23   "$TMPDIR_TITAN/telnet_hosts.txt"

    info "Launching parallel Hydra attacks (using $CORES core(s))..."
    attack_service ssh    "$TMPDIR_TITAN/ssh_hosts.txt"    root          &
    attack_service ftp    "$TMPDIR_TITAN/ftp_hosts.txt"    admin         &
    attack_service rdp    "$TMPDIR_TITAN/rdp_hosts.txt"    Administrator &
    attack_service telnet "$TMPDIR_TITAN/telnet_hosts.txt" admin         &
    wait

    ok "All credential tests complete"
}

# ── Phase 3 – Exploit search (Full mode only) ─────────────────────────────────
# Criteria 3.1 / 3.2: NSE runs during nmap (Phase 1); Searchsploit here
run_exploit_search() {
    [[ "$MODE" == "Full" ]] || return 0
    phase "PHASE 3 · Vulnerability & Exploit Search (Searchsploit)"

    local xml="$OUTDIR/scans/nmap_scan.xml"
    local out="$OUTDIR/exploits/searchsploit.txt"

    if ! command -v searchsploit &>/dev/null; then
        warn "searchsploit not installed – skipping"
        echo "searchsploit not available" > "$out"
        return
    fi

    if [[ ! -f "$xml" ]]; then
        warn "Nmap XML missing – cannot run searchsploit"
        return
    fi

    info "Searching exploit-db against discovered services..."

    if [[ $DRY_RUN -eq 1 ]]; then
        warn "DRY RUN: searchsploit --nmap $xml"
        echo "[DRY RUN] exploits" > "$out"
        return
    fi

    searchsploit --nmap "$xml" 2>/dev/null | tee "$out" || true

    # wc -l avoids grep -c exit-1 arithmetic bug
    local cnt; cnt=$(grep "Exploit" "$out" 2>/dev/null | wc -l); cnt="${cnt// /}"
    [[ "$cnt" -gt 0 ]] && warn "Found $cnt potential exploit(s)!" || ok "No known exploits found"
}

# ── Phase 4 – Display results ──────────────────────────────────────────────────
# Criteria 4.1 / 4.2: display each stage, show found information
display_results() {
    phase "PHASE 4 · Results Summary"

    local gnmap="$OUTDIR/scans/nmap_scan.gnmap"

    # wc -l never exits non-zero – fixes the double-zero display bug
    local hosts=0 ports=0
    if [[ -f "$gnmap" ]]; then
        hosts=$(grep "^Host:" "$gnmap" 2>/dev/null | wc -l); hosts="${hosts// /}"
        ports=$(grep -o "[0-9]*/open" "$gnmap" 2>/dev/null | wc -l); ports="${ports// /}"
    fi

    echo -e "  ${CYN}Hosts discovered :${NC} $hosts"
    echo -e "  ${CYN}Open ports       :${NC} $ports  (TCP + UDP)"
    echo ""

    # Services table
    if [[ -f "$gnmap" && -s "$gnmap" ]]; then
        info "Open services:"
        printf "  ${BOLD}%-18s %-10s %-8s %-15s${NC}\n" "IP" "PORT" "PROTO" "SERVICE"
        echo   "  ──────────────────────────────────────────────────"
        grep "Ports:" "$gnmap" 2>/dev/null | while IFS= read -r line; do
            local ip; ip=$(echo "$line" | awk '{print $2}')
            local psec; psec=$(echo "$line" | sed 's/.*Ports: //' | sed 's/\tIgnored.*//')
            IFS=',' read -ra PA <<< "$psec"
            for pd in "${PA[@]}"; do
                pd=$(echo "$pd" | xargs)
                IFS='/' read -ra P <<< "$pd"
                [[ "${P[1]:-}" == "open" ]] || continue
                printf "  %-18s %-10s %-8s %-15s\n" \
                    "$ip" "${P[0]}" "${P[2]:-tcp}" "${P[4]:-unknown}"
            done
        done
    else
        warn "No open services to display"
    fi

    # Credential results
    echo ""
    info "Credential results (SSH / FTP / RDP / TELNET):"
    local found_creds=0
    for svc in ssh ftp rdp telnet; do
        local cf="$OUTDIR/credentials/${svc}_cracked.txt"
        if [[ -f "$cf" && -s "$cf" ]]; then
            echo -e "  ${RED}⚠  ${svc^^} – WEAK CREDENTIALS:${NC}"
            sed 's/^/    /' "$cf"
            (( found_creds++ )) || true
        else
            echo -e "  ${GRN}✔  ${svc^^} – no weak credentials${NC}"
        fi
    done
    [[ $found_creds -eq 0 ]] && ok "All services passed credential testing"

    # Exploit results (Full mode only)
    if [[ "$MODE" == "Full" ]]; then
        echo ""
        info "Exploit search results:"
        local ef="$OUTDIR/exploits/searchsploit.txt"
        if [[ -f "$ef" && -s "$ef" ]]; then
            cat "$ef"
        else
            ok "No exploits to display"
        fi
    fi
}

# ── Interactive search (criteria 4.3) ─────────────────────────────────────────
search_results() {
    echo ""
    read -rp "$(echo -e "${BOLD}Search inside results? [y/n]: ${NC}")" ans
    [[ "$ans" =~ ^[Yy]$ ]] || return 0

    phase "Interactive Result Search  (blank or 'q' to quit)"
    while true; do
        read -rp "$(echo -e "${BOLD}Search term: ${NC}")" term
        [[ -z "$term" || "$term" == "q" ]] && break
        local found=false
        grep -ri "$term" "$OUTDIR/scans/"       2>/dev/null && found=true
        grep -ri "$term" "$OUTDIR/credentials/" 2>/dev/null && found=true
        grep -ri "$term" "$OUTDIR/exploits/"    2>/dev/null && found=true
        grep -ri "$term" "$OUTDIR/logs/"        2>/dev/null && found=true
        [[ $found == false ]] && warn "No results for: '$term'"
    done
    ok "Search ended"
}

# ── Archive (criteria 4.4) ────────────────────────────────────────────────────
create_archive() {
    phase "Creating ZIP Archive"
    local zipname="${CLASS_ID}.${STUDENT_ID}.${PROJECT_ID}.zip"
    local parent; parent=$(dirname "$OUTDIR")
    local base;   base=$(basename "$OUTDIR")

    if [[ $DRY_RUN -eq 1 ]]; then
        warn "DRY RUN: zip -r $parent/$zipname $base"; return
    fi

    pushd "$parent" > /dev/null
    if zip -r "$zipname" "$base" >/dev/null 2>&1; then
        local sz; sz=$(du -h "$zipname" | cut -f1)
        ok "Archive: $(pwd)/$zipname  ($sz)"
    else
        err "Failed to create archive"
    fi
    popd > /dev/null
}

# ── Argument parsing ───────────────────────────────────────────────────────────
parse_args() {
    for arg in "$@"; do
        case "$arg" in
            -h|--help)
                echo "Usage: sudo $0 [--dry-run] [--verbose]"
                echo "  --dry-run   Simulate without executing real scans"
                echo "  --verbose   Enable bash debug output (set -x)"
                exit 0 ;;
            -d|--dry-run) DRY_RUN=1; warn "DRY RUN enabled" ;;
            --verbose)    set -x ;;
            *) err "Unknown option: $arg"; exit 1 ;;
        esac
    done
}

# ── Main ───────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    banner
    check_root
    check_requirements
    calculate_optimal_threads
    ethics_check
    get_inputs

    {
        echo "TITAN SCAN – $(date)"
        echo "Target: $TARGET | Mode: $MODE | Cores: $CORES | Rate: $NMAP_RATE | Output: $OUTDIR"
    } > "$OUTDIR/logs/scan.log"

    ok "Configuration complete – starting scan"

    run_nmap
    run_credential_attacks
    run_exploit_search
    display_results
    search_results
    create_archive

    echo ""
    echo -e "${GRN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GRN}${BOLD}  MISSION COMPLETE${NC}"
    echo -e "${GRN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    ok "Results : $OUTDIR"
    ok "Archive : $(dirname "$OUTDIR")/${CLASS_ID}.${STUDENT_ID}.${PROJECT_ID}.zip"
    [[ $DRY_RUN -eq 1 ]] && warn "This was a DRY RUN – no actual scanning occurred"
    echo ""
}

main "$@"