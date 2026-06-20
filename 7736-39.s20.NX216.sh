#!/bin/bash
# ============================================================================
#  Cyberium Arena - Project: Hunter (Network Forensics)
#  Student  : Yonatan Avitan
#  Code     : s20
#  Cohort   : 7736-39
#  Lecturer : Zach Azolis
# ============================================================================
#  This script implements the three functions required by the assignment:
#    NetAn()  - Network Analysis: detect malicious URLs/IPs from a given IOC link
#    FiAn()   - File Analysis: extract files <1MB, hash them, check on VirusTotal
#    LOG()    - Log & Audit: every malicious finding written with date+time
#
#  Live monitoring output (Module 4) follows the format shown in the project
#  PDF: header "//Hunter - Live//", an [+] start banner, and one line per
#  finding in the form:
#    Tue 28 Sep 2021 08:14:11 AM EDT: 10.0.0.2 accessed 120.55.164.86
#
#  Usage:
#    sudo ./hunter.sh -i <interface> -u <IOC_URL> [-k <VT_API_KEY>]
#
#  Tools used : tshark, curl, jq, sha256sum
#  API used   : VirusTotal API v3
#
#  Credits / references (code/snippets adapted from):
#    - tshark export-objects flag : https://www.wireshark.org/docs/man-pages/tshark.html
#    - VirusTotal API v3 lookup   : https://docs.virustotal.com/reference/file-info
#    - URLhaus IOC text feed      : https://urlhaus.abuse.ch/api/
#    - Bash signal trap pattern   : https://www.gnu.org/software/bash/manual/html_node/Signals.html
# ============================================================================

set -u   # error on unset vars (no -e: keep running on minor errors)

# ---------- Defaults / globals ----------
INTERFACE=""
IOC_URL=""
VT_API_KEY="${VT_API_KEY:-}"
WORK_DIR="/tmp/hunter_$$"
LOG_DIR="./hunter_logs"
FILE_ROTATE_SECS=30
SIZE_LIMIT=1048576           # 1 MB (project requirement)

# ---------- CLI parsing ----------
usage() {
    echo "Usage: sudo $0 -i <interface> -u <IOC_url> [-k <VT_api_key>]"
    exit 1
}
while getopts "i:u:k:h" opt; do
    case "$opt" in
        i) INTERFACE="$OPTARG" ;;
        u) IOC_URL="$OPTARG" ;;
        k) VT_API_KEY="$OPTARG" ;;
        h|*) usage ;;
    esac
done
[[ -z "$INTERFACE" || -z "$IOC_URL" ]] && usage
[[ $EUID -ne 0 ]] && { echo "Run as root (raw sockets needed)."; exit 1; }

# Verify required tools are installed
for cmd in tshark curl jq sha256sum; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Missing dependency: $cmd"; exit 1; }
done

# ---------- Working directories / files ----------
mkdir -p "$WORK_DIR" "$LOG_DIR"
FILES_DIR="$WORK_DIR/extracted"
mkdir -p "$FILES_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ALERT_LOG="$LOG_DIR/hunter_alerts_${TIMESTAMP}.log"
IOC_FILE="$WORK_DIR/iocs.raw"
touch "$WORK_DIR/checked_hashes.txt" "$ALERT_LOG"

# Detect the network we're listening on (e.g. 192.168.1.0/24) for the banner
IP_CIDR=$(ip -o -f inet addr show "$INTERFACE" 2>/dev/null | awk '{print $4}' | head -n1)
if [[ "$IP_CIDR" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+/([0-9]+)$ ]]; then
    SUBNET="${BASH_REMATCH[1]}.0/${BASH_REMATCH[2]}"
else
    SUBNET="$IP_CIDR"
fi

# ============================================================================
# LOG()  -  Module 3: Log and Audit
# ----------------------------------------------------------------------------
# Every malicious finding (network or file) is written here with the exact
# date+time and printed live to the screen. The timestamp format matches the
# project PDF: "Tue 28 Sep 2021 08:14:11 AM EDT".
# Output line format: "<timestamp>: <source> accessed <destination>"
# ============================================================================
LOG()
{
    local src="$1"
    local dst="$2"
    # %a = short weekday  %d = day  %b = short month  %Y = year
    # %r = 12-hour time (HH:MM:SS AM/PM)  %Z = timezone
    local ts
    ts=$(date '+%a %d %b %Y %r %Z')
    # tee prints to the live monitor AND appends to the log file
    echo "${ts}: ${src} accessed ${dst}" | tee -a "$ALERT_LOG"
}

# ============================================================================
# NetAn()  -  Module 1: Network Analysis
# ----------------------------------------------------------------------------
# Detects malicious URLs and IP addresses from a given IOC link.
# Workflow:
#   1) Download the IOC feed (text file with IPs/URLs/domains)
#   2) Split into IP / URL / domain match-lists
#   3) Run tshark live on the interface, pulling out src/dst IPs, HTTP hosts,
#      and DNS queries from every packet
#   4) For each event, check against the match-lists; on hit -> LOG()
# Tools: TShark (per assignment "Available tools: Zeek, TShark")
# ============================================================================
NetAn()
{
    # ---- Step 1: download the IOC list ----
    curl -fsSL --max-time 30 -o "$IOC_FILE" "$IOC_URL" \
        || { echo "[!] IOC download failed: $IOC_URL"; exit 1; }

    # ---- Step 2: parse - strip comments/blanks, then split by IOC type ----
    grep -vE '^\s*(#|$)' "$IOC_FILE" > "$IOC_FILE.clean"
    # IPv4 addresses (covers abuse.ch Feodo, Talos, ET feeds, mixed)
    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$IOC_FILE.clean" \
        | sort -u > "$WORK_DIR/ioc_ips.txt"
    # Full URLs (URLhaus-style)
    grep -Eo 'https?://[^[:space:]"]+' "$IOC_FILE.clean" \
        | sort -u > "$WORK_DIR/ioc_urls.txt"
    # Domains - both extracted from URLs and standalone bare-domain lines
    {
        sed -E 's|https?://||; s|/.*||' "$WORK_DIR/ioc_urls.txt"
        grep -Eo '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' "$IOC_FILE.clean"
    } | sort -u | grep -vE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' > "$WORK_DIR/ioc_domains.txt"

    # ---- Step 3-4: stream live tshark output and match against IOCs ----
    # We pull only the fields we care about (-T fields):
    #   ip.src, ip.dst, http.host, dns.qry.name
    # -Y filter restricts to HTTP requests, DNS queries, and TCP SYNs.
    tshark -i "$INTERFACE" -l -n \
        -Y 'http.request or dns.qry.name or tcp.flags.syn==1' \
        -T fields -E separator='|' -E quote=n -E header=n \
        -e ip.src -e ip.dst -e http.host -e dns.qry.name \
        2>/dev/null |
    while IFS='|' read -r src dst host dns; do
        # Match destination IP against IOC list
        if [[ -n "$dst" ]] && grep -qxF "$dst" "$WORK_DIR/ioc_ips.txt"; then
            LOG "$src" "$dst"
        fi
        # Match HTTP Host header against IOC domain list
        if [[ -n "$host" ]] && grep -qxF "$host" "$WORK_DIR/ioc_domains.txt"; then
            LOG "$src" "$host"
        fi
        # Match DNS query name against IOC domain list
        if [[ -n "$dns" ]] && grep -qxF "$dns" "$WORK_DIR/ioc_domains.txt"; then
            LOG "$src" "$dns"
        fi
    done
}

# ============================================================================
# FiAn()  -  Module 2: File Analysis
# ----------------------------------------------------------------------------
# Extract files under 1 MB transferred over the network, compute their
# SHA-256 hash, and look the hash up on VirusTotal. Malicious hits are
# reported via LOG().
# Tools: TShark + VirusTotal (per assignment).
# Strategy: tshark cannot --export-objects from a live stream, so we capture
# rotating pcap files (30 sec each) and process completed ones.
# ============================================================================
FiAn()
{
    # Start a rotating live capture in the background.
    # -b duration:N rotates every N seconds; -b files:10 keeps at most 10.
    tshark -i "$INTERFACE" -q \
        -w "$WORK_DIR/cap.pcap" \
        -b duration:$FILE_ROTATE_SECS -b files:10 \
        >/dev/null 2>&1 &

    # Loop: every rotation interval, process any *finished* pcaps.
    while true; do
        sleep $FILE_ROTATE_SECS
        for pcap in "$WORK_DIR"/cap_*.pcap; do
            [[ -f "$pcap" ]] || continue
            # Skip pcaps still being written (mtime < 5s ago)
            local age=$(( $(date +%s) - $(stat -c '%Y' "$pcap") ))
            (( age < 5 )) && continue
            # Skip already-processed pcaps
            [[ -f "${pcap}.done" ]] && continue
            touch "${pcap}.done"

            # Extract HTTP / SMB / TFTP file objects to a temp dir
            local outdir
            outdir=$(mktemp -d -p "$FILES_DIR")
            for proto in http smb tftp; do
                tshark -r "$pcap" --export-objects "${proto},${outdir}" -Q 2>/dev/null
            done

            # For each extracted file: enforce <1MB rule, hash, lookup on VT
            find "$outdir" -type f 2>/dev/null | while read -r f; do
                local sz
                sz=$(stat -c '%s' "$f")
                if (( sz > 0 && sz < SIZE_LIMIT )); then
                    local h
                    h=$(sha256sum "$f" | awk '{print $1}')

                    # Skip duplicates (free-tier VT quota saver)
                    grep -qxF "$h" "$WORK_DIR/checked_hashes.txt" && continue
                    echo "$h" >> "$WORK_DIR/checked_hashes.txt"

                    # No VT key? we still hashed the file, just can't classify
                    [[ -z "$VT_API_KEY" ]] && continue

                    # Query VirusTotal API v3 - GET /api/v3/files/{sha256}
                    local resp http_code body malicious
                    resp=$(curl -s --max-time 15 -w '\n%{http_code}' \
                           -H "x-apikey: $VT_API_KEY" \
                           "https://www.virustotal.com/api/v3/files/$h")
                    http_code=$(echo "$resp" | tail -n1)
                    body=$(echo "$resp" | head -n -1)

                    if [[ "$http_code" == "200" ]]; then
                        malicious=$(echo "$body" \
                            | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
                        if [[ "$malicious" =~ ^[0-9]+$ ]] && (( malicious > 0 )); then
                            # Log via LOG() so format stays consistent
                            LOG "file($(basename "$f"))" \
                                "malicious sha256:${h:0:16}... (${malicious} AV detections)"
                            cp "$f" "$WORK_DIR/malicious_${h:0:12}_$(basename "$f")" 2>/dev/null
                        fi
                    fi
                    # Free VT tier = 4 req/min, pace ourselves
                    sleep 16
                fi
            done
            rm -rf "$outdir" "$pcap" "${pcap}.done"
        done
    done
}

# ---------- Clean shutdown ----------
cleanup() {
    for pid in $(jobs -p); do kill "$pid" 2>/dev/null; done
}
trap cleanup EXIT INT TERM

# ============================================================================
# Module 4: Monitoring
# ----------------------------------------------------------------------------
# Clean screen, fixed header per the project PDF, then live findings stream
# directly through LOG() as they happen.
# ============================================================================
clear
echo "//Hunter - Live//"
echo
echo "[+] Hunter started analysis: $SUBNET"

# Launch File Analysis in the background, then run Network Analysis in
# the foreground so its LOG() output appears live on the screen.
FiAn &
NetAn
