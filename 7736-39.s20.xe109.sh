#!/usr/bin/env bash
# =============================================================================
#  DARKNET CRAWLER  |  Project XE109  |  AI Fundamentals
#  Student : Yonatan Avitan (s20)   Class : 7736-39   Lecturer : Zach Azolis
#  Submission filename (per spec UNIT.STUDENT.PROGRAM): 7736-39.s20.xe109.sh
# -----------------------------------------------------------------------------
#  Phases : A=Preflight  B=Input  C=Crawl/Index  D=NoAccess  E=AdminUI  F=Meta
#  Usage  : ./7736-39.s20.xe109.sh             (Admin UI; default)
#           ./7736-39.s20.xe109.sh --crawl     (background crawl pass)
#           ./7736-39.s20.xe109.sh --help      (usage)
# =============================================================================
set -uo pipefail

# ---------- 1. CONFIG --------------------------------------------------------
: "${WORK_DIR:=$HOME/darknet_crawler}"
: "${MAX_PARALLEL_WORKERS:=5}"
: "${CONNECT_TIMEOUT_SEC:=45}"
: "${MAX_REQUEST_TIME_SEC:=90}"
: "${TOR_BOOTSTRAP_WAIT_SEC:=35}"
: "${LOCK_WAIT_SEC:=30}"
: "${REFRESH_INTERVAL_SEC:=3}"
: "${NETWORK_STATUS_TTL_SEC:=30}"
USER_AGENT_STRING="Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
PROXY_CMD=""
PROXY_BINARY=""
SELF_SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
CRAWLER_PID_FILE="$WORK_DIR/crawler.pid"
UI_PID_FILE="$WORK_DIR/ui.pid"
NETWORK_STATUS_CACHE="$WORK_DIR/network_status.cache"
CRAWLER_BG_OUTPUT="$WORK_DIR/crawler_bg.out"
PROXYCHAINS_CONF="/etc/proxychains4.conf"

# ---------- 2. INIT ----------------------------------------------------------
initialize_working_directory() {
    mkdir -p "$WORK_DIR"/{locks,tmp} || return 1
    local f
    for f in queue.txt index.txt crawled.txt failed.txt crawler_log.txt keywords.txt alerts.log; do
        [ -f "$WORK_DIR/$f" ] || : > "$WORK_DIR/$f"
    done
}

# ---------- 3. UI SINGLETON LOCK --------------------------------------------
acquire_ui_singleton_lock() {
    if [ -f "$UI_PID_FILE" ]; then
        local p; p=$(cat "$UI_PID_FILE" 2>/dev/null)
        if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
            printf '[FATAL] another Admin UI is running (PID %s). Remove %s if stale.\n' \
                   "$p" "$UI_PID_FILE" >&2
            return 1
        fi
        rm -f "$UI_PID_FILE"
    fi
    printf '%s\n' "$$" > "$UI_PID_FILE"
}
release_ui_singleton_lock() {
    [ -f "$UI_PID_FILE" ] || return 0
    [ "$(cat "$UI_PID_FILE" 2>/dev/null)" = "$$" ] && rm -f "$UI_PID_FILE"
}

# ---------- 4. PHASE A : AUTONOMOUS PRE-FLIGHT (auto-heal) ------------------
# proxychains4 preferred; proxychains accepted as fallback. -q hides banner.
resolve_proxy_command() {
    if command -v proxychains4 >/dev/null 2>&1; then
        PROXY_CMD="proxychains4 -q"; PROXY_BINARY="proxychains4"
    elif command -v proxychains >/dev/null 2>&1; then
        PROXY_CMD="proxychains -q"; PROXY_BINARY="proxychains"
    else
        return 1
    fi
    export PROXY_CMD PROXY_BINARY
}

# Auto-install proxychains4 + tor on Debian/Kali. Sudo will prompt once.
auto_install_dependencies() {
    printf '[BOOTSTRAP] installing proxychains4 + tor (sudo required)...\n'
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq         || return 1
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
         proxychains4 tor curl >/dev/null                           || return 1
    printf '[BOOTSTRAP] packages installed.\n'
}

# Make sure tor is running. Try systemd, then sysvinit fallback.
ensure_tor_service_running() {
    systemctl is-active --quiet tor 2>/dev/null && return 0
    pgrep -x tor >/dev/null 2>&1 && return 0
    printf '[BOOTSTRAP] starting tor...\n'
    sudo systemctl enable --now tor 2>/dev/null \
        || sudo service tor start    2>/dev/null \
        || { printf '[FATAL] could not start tor service.\n' >&2; return 1; }
}

# Idempotent, additive: ensure proxy_dns + socks5 entry are present.
auto_configure_proxychains() {
    [ -r "$PROXYCHAINS_CONF" ] || return 0
    # Uncomment any commented "proxy_dns" line.
    sudo sed -i -E 's/^[[:space:]]*#[[:space:]]*proxy_dns([[:space:]]|$)/proxy_dns\1/' "$PROXYCHAINS_CONF"
    # Append proxy_dns if still missing.
    grep -qE '^[[:space:]]*proxy_dns([[:space:]]|$)' "$PROXYCHAINS_CONF" \
        || printf 'proxy_dns\n' | sudo tee -a "$PROXYCHAINS_CONF" >/dev/null
    # Append socks5 entry if missing (never touches existing socks lines).
    grep -qE '^[[:space:]]*socks5[[:space:]]+127\.0\.0\.1[[:space:]]+9050' "$PROXYCHAINS_CONF" \
        || printf 'socks5 127.0.0.1 9050\n' | sudo tee -a "$PROXYCHAINS_CONF" >/dev/null
    printf '[OK] proxychains config verified.\n'
}

# Connectivity probe through the tunnel; clearnet target proves DNS is tunneled.
verify_tor_connectivity() {
    local code
    code=$($PROXY_CMD curl --silent --connect-timeout 45 --max-time 60 \
            --output /dev/null --write-out '%{http_code}' \
            "https://check.torproject.org/" 2>/dev/null)
    [ -z "$code" ] && code=000
    [ "$code" -ge 200 ] && [ "$code" -lt 400 ]
}

# Aggregate Phase A: install -> configure -> start -> probe -> repair-once.
run_preflight_checks() {
    printf '\n=== Pre-flight (Phase A) ===\n'
    if ! resolve_proxy_command; then
        auto_install_dependencies || return 1
        resolve_proxy_command     || return 1
    fi
    auto_configure_proxychains
    ensure_tor_service_running    || return 1

    # Mandatory bootstrap window: Tor needs ~30s after start to build circuits.
    printf '[BOOTSTRAP] Waiting for Tor to bootstrap (%ss)...\n' "$TOR_BOOTSTRAP_WAIT_SEC"
    sleep "$TOR_BOOTSTRAP_WAIT_SEC"

    printf '[INFO] verifying Tor connectivity (up to 60s)...\n'
    if ! verify_tor_connectivity; then
        printf '[BOOTSTRAP] probe failed; restarting tor and retrying...\n'
        sudo systemctl restart tor 2>/dev/null || sudo service tor restart 2>/dev/null
        sleep "$TOR_BOOTSTRAP_WAIT_SEC"
        verify_tor_connectivity || {
            printf '[FATAL] Tor connectivity could not be established.\n' >&2
            printf '         Check %s and the tor service log.\n' "$PROXYCHAINS_CONF" >&2
            return 1
        }
    fi
    printf '[OK] %s + tor reachable.\n=== Pre-flight passed ===\n\n' "$PROXY_BINARY"
}

# ---------- 5. CONCURRENCY-SAFE FILE PRIMITIVES -----------------------------
# Append a line to a shared file under exclusive flock (auto-released on subshell exit).
safe_append_line() {
    local f="$1" line="$2"
    local lf="$WORK_DIR/locks/$(basename "$f").lock"
    ( flock -x -w "$LOCK_WAIT_SEC" 200 || exit 1
      printf '%s\n' "$line" >> "$f"
    ) 200>"$lf"
}

# Race-free dedupe: check membership AND append within the same lock.
add_url_to_index_if_new() {
    ( flock -x -w "$LOCK_WAIT_SEC" 200 || exit 2
      grep -Fxq "$1" "$WORK_DIR/index.txt" 2>/dev/null && exit 1
      printf '%s\n' "$1" >> "$WORK_DIR/index.txt"
    ) 200>"$WORK_DIR/locks/index.lock"
}

# ---------- 6. NETWORK FETCH (proxychains-tunnelled curl) -------------------
fetch_url_via_proxy() {
    local url="$1" out="$2" code rc
    code=$($PROXY_CMD curl --connect-timeout "$CONNECT_TIMEOUT_SEC" \
        --max-time "$MAX_REQUEST_TIME_SEC" --retry 1 --retry-delay 2 \
        --location --silent --show-error --user-agent "$USER_AGENT_STRING" \
        --output "$out" --write-out '%{http_code}' "$url" 2>/dev/null)
    rc=$?
    [ -z "$code" ] && code=000
    [ "$rc" -eq 0 ] && [ "$code" -lt 400 ] && [ -s "$out" ]
}

# HEAD-only probe -- used by the resume guard (Requirement 2.4).
probe_url_active_status() {
    local code
    code=$($PROXY_CMD curl --head --silent --output /dev/null \
        --connect-timeout 20 --max-time 40 --write-out '%{http_code}' "$1" 2>/dev/null)
    [ -z "$code" ] && code=000
    if [ "$code" -ge 200 ] && [ "$code" -lt 400 ]; then printf 'Active'
    else printf 'Non-Active'; fi
}

# ---------- 7. HTML PARSING -------------------------------------------------
# Title: PCRE (?is) + non-greedy with lookbehind/lookahead; trims whitespace.
extract_html_title() {
    local t
    t=$(grep -oPm1 '(?is)(?<=<title>).*?(?=</title>)' "$1" 2>/dev/null \
        | head -n1 | tr '\n\r\t' '   ' \
        | sed -E 's/[[:space:]]+/ /g; s/^ +//; s/ +$//')
    [ -z "$t" ] && printf '[NO TITLE]' || printf '%s' "$t"
}

# Onion-link extractor: v2 (16) + v3 (56) base32 alphabet only.
extract_onion_links_from_html() {
    grep -oE 'https?://[a-z2-7]{16,56}\.onion(/[^"'\''<> )]*)?' "$1" 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' | sort -u
}

# ---------- 8. KEYWORD ALERTING ---------------------------------------------
scan_html_for_alert_keywords() {
    local html="$1" url="$2" kwfile="$WORK_DIR/keywords.txt"
    [ -s "$kwfile" ] || return 0
    local hits ts
    # Strip tags first so "admin" doesn't false-match class="admin".
    hits=$(sed 's/<[^>]*>//g' "$html" | grep -oFif "$kwfile" 2>/dev/null | sort -u)
    [ -z "$hits" ] && return 0
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    local k
    while IFS= read -r k; do
        [ -z "$k" ] && continue
        safe_append_line "$WORK_DIR/alerts.log" "[$ts] [$url] [$k]"
    done <<< "$hits"
}

# ---------- 9. WORKER (Phase C + D) -----------------------------------------
crawl_one_url() {
    local url="$1"
    [ -z "$url" ] && return 0
    local h tmp ts
    h=$(printf '%s' "$url" | md5sum | cut -d' ' -f1)
    tmp="$WORK_DIR/tmp/$$_$h.html"
    ts=$(date '+%Y-%m-%d %H:%M:%S')

    # Resume: skip already-crawled, just probe active status.
    if grep -Fxq "$url" "$WORK_DIR/crawled.txt" 2>/dev/null; then
        probe_url_active_status "$url" >/dev/null
        return 0
    fi

    # Phase D: failure path -> [NO ACCESS]
    if ! fetch_url_via_proxy "$url" "$tmp"; then
        safe_append_line "$WORK_DIR/crawler_log.txt" "[$ts] [$url] [NO ACCESS]"
        safe_append_line "$WORK_DIR/failed.txt" "$url"
        rm -f "$tmp"
        return 1
    fi

    # Phase C: success path
    local title; title=$(extract_html_title "$tmp")
    safe_append_line "$WORK_DIR/crawler_log.txt" "[$ts] [$url] [$title]"
    safe_append_line "$WORK_DIR/crawled.txt" "$url"

    # Discover new links (do NOT recurse this run).
    local link
    while IFS= read -r link; do
        [ -z "$link" ] && continue
        add_url_to_index_if_new "$link" >/dev/null
    done < <(extract_onion_links_from_html "$tmp")

    scan_html_for_alert_keywords "$tmp" "$url"
    rm -f "$tmp"
}

# ---------- 10. DISPATCHER --------------------------------------------------
# pending = index - (crawled ∪ failed). O(n+m) via sort + comm.
rebuild_work_queue() {
    local a b
    a=$(mktemp); b=$(mktemp)
    sort -u "$WORK_DIR/index.txt" > "$a"
    sort -u "$WORK_DIR/crawled.txt" "$WORK_DIR/failed.txt" > "$b"
    comm -23 "$a" "$b" > "$WORK_DIR/queue.txt"
    rm -f "$a" "$b"
    printf '[INFO] queue rebuilt: %s pending\n' "$(wc -l < "$WORK_DIR/queue.txt")"
}

# xargs -P pool with cap. Workers need exported funcs+vars.
dispatch_crawler_workers() {
    [ -s "$WORK_DIR/queue.txt" ] || { printf '[INFO] queue empty.\n'; return 0; }
    local cores n
    cores=$(nproc 2>/dev/null || printf '4')
    n=$(( cores > MAX_PARALLEL_WORKERS ? MAX_PARALLEL_WORKERS : cores ))
    export -f crawl_one_url fetch_url_via_proxy probe_url_active_status \
              extract_html_title extract_onion_links_from_html \
              scan_html_for_alert_keywords add_url_to_index_if_new safe_append_line
    export WORK_DIR PROXY_CMD USER_AGENT_STRING \
           CONNECT_TIMEOUT_SEC MAX_REQUEST_TIME_SEC LOCK_WAIT_SEC
    printf '[INFO] dispatching %s workers...\n' "$n"
    xargs -a "$WORK_DIR/queue.txt" -n1 -P "$n" -I {} \
          bash -c 'crawl_one_url "$1"' _ {}
    printf '[INFO] crawl pass complete.\n'
}

# ---------- 11. INPUT VALIDATION (Phase B) ----------------------------------
is_valid_onion_url() {
    local u; u=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    [[ "$u" =~ ^https?://[a-z2-7]{16,56}\.onion(/.*)?$ ]]
}

ingest_seed_file() {
    local p="$1"
    [ -f "$p" ] && [ -r "$p" ] && [ -s "$p" ] || {
        printf '[ERROR] seed file missing/empty/unreadable: %s\n' "$p"; return 1; }
    local line url ok=0 bad=0 ln=0
    while IFS= read -r line || [ -n "$line" ]; do
        ln=$((ln+1))
        url=$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
        [ -z "$url" ] && continue
        case "$url" in '#'*) continue ;; esac
        if is_valid_onion_url "$url"; then
            url=$(printf '%s' "$url" | tr '[:upper:]' '[:lower:]')
            add_url_to_index_if_new "$url" >/dev/null
            ok=$((ok+1))
        else
            printf '  [WARN] line %s rejected: %s\n' "$ln" "$url"
            bad=$((bad+1))
        fi
    done < "$p"
    printf '[INFO] ingested %s valid, rejected %s.\n' "$ok" "$bad"
    [ "$ok" -gt 0 ]
}

# Reject empty / multi-line keywords (would corrupt the line-per-keyword file).
is_valid_keyword() {
    [ -n "$1" ] || return 1
    case "$1" in *$'\n'*|*$'\r'*) return 1 ;; esac
    return 0
}

# ---------- 12. STATS HELPERS -----------------------------------------------
count_lines() {
    [ -f "$1" ] || { printf '0'; return; }
    local n; n=$(grep -c . "$1" 2>/dev/null)
    printf '%s' "${n:-0}"
}

# ---------- 13. NETWORK STATUS CACHE ----------------------------------------
update_network_status_cache() {
    [ -n "$PROXY_CMD" ] || resolve_proxy_command 2>/dev/null || {
        printf 'Non-Active|%s\n' "$(date +%s)" > "$NETWORK_STATUS_CACHE"; return 1; }
    local code label="Non-Active"
    code=$($PROXY_CMD curl --head --silent --output /dev/null \
        --connect-timeout 45 --max-time 60 --write-out '%{http_code}' \
        "https://check.torproject.org/" 2>/dev/null)
    [ -z "$code" ] && code=000
    [ "$code" -ge 200 ] && [ "$code" -lt 400 ] && label="Active"
    printf '%s|%s\n' "$label" "$(date +%s)" > "$NETWORK_STATUS_CACHE"
}

get_network_status() {
    local s="" t=0 now; now=$(date +%s)
    [ -s "$NETWORK_STATUS_CACHE" ] && IFS='|' read -r s t < "$NETWORK_STATUS_CACHE"
    if [ -z "$s" ] || [ $((now - t)) -gt "$NETWORK_STATUS_TTL_SEC" ]; then
        update_network_status_cache
        IFS='|' read -r s t < "$NETWORK_STATUS_CACHE"
    fi
    printf '%s' "$s"
}

# ---------- 14. CRAWLER PROCESS CONTROL -------------------------------------
is_crawler_running() {
    [ -f "$CRAWLER_PID_FILE" ] || return 1
    local p; p=$(cat "$CRAWLER_PID_FILE" 2>/dev/null)
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null
}

# nohup + disown -> survives terminal close. Re-execs THIS file with --crawl.
start_crawler_in_background() {
    if is_crawler_running; then
        printf '[INFO] crawler already running (PID %s).\n' "$(cat "$CRAWLER_PID_FILE")"
        return 0
    fi
    if [ "$(count_lines "$WORK_DIR/queue.txt")" -eq 0 ] \
       && [ "$(count_lines "$WORK_DIR/index.txt")" -eq 0 ]; then
        printf '[ERROR] no URLs available -- load a seed file first.\n'; return 1
    fi
    nohup bash "$SELF_SCRIPT_PATH" --crawl > "$CRAWLER_BG_OUTPUT" 2>&1 &
    local p=$!
    printf '%s\n' "$p" > "$CRAWLER_PID_FILE"
    disown "$p" 2>/dev/null || true
    printf '[INFO] crawler launched (PID %s); output -> %s\n' "$p" "$CRAWLER_BG_OUTPUT"
}

# SIGTERM (10s grace) -> SIGKILL. pkill -P also reaps xargs/curl children.
stop_crawler_in_background() {
    if ! is_crawler_running; then
        printf '[INFO] crawler is not running.\n'
        rm -f "$CRAWLER_PID_FILE"; return 0
    fi
    local p i=0; p=$(cat "$CRAWLER_PID_FILE")
    printf '[INFO] SIGTERM -> %s\n' "$p"
    kill -TERM "$p" 2>/dev/null; pkill -TERM -P "$p" 2>/dev/null
    while kill -0 "$p" 2>/dev/null && [ "$i" -lt 10 ]; do sleep 1; i=$((i+1)); done
    if kill -0 "$p" 2>/dev/null; then
        printf '[WARN] escalating to SIGKILL.\n'
        kill -KILL "$p" 2>/dev/null; pkill -KILL -P "$p" 2>/dev/null
    fi
    rm -f "$CRAWLER_PID_FILE"
    printf '[INFO] crawler stopped.\n'
}

# ---------- 15. KEYWORD MANAGEMENT (Requirement 4.2) ------------------------
list_configured_keywords() {
    local n; n=$(count_lines "$WORK_DIR/keywords.txt")
    [ "$n" -eq 0 ] && { printf '  (no keywords configured)\n'; return; }
    printf '  Currently configured (%s):\n' "$n"
    local kw i=1
    while IFS= read -r kw; do
        [ -z "$kw" ] && continue
        printf '    %s. %s\n' "$i" "$kw"; i=$((i+1))
    done < "$WORK_DIR/keywords.txt"
}

add_one_keyword() {
    local k; read -r -p "  Keyword to add: " k
    is_valid_keyword "$k" || { printf '  [ERROR] invalid keyword.\n'; return 1; }
    ( flock -x -w "$LOCK_WAIT_SEC" 200 || exit 1
      if grep -Fxq "$k" "$WORK_DIR/keywords.txt" 2>/dev/null; then
          printf '  [INFO] already configured.\n'
      else
          printf '%s\n' "$k" >> "$WORK_DIR/keywords.txt"
          printf '  [OK] added.\n'
      fi
    ) 200>"$WORK_DIR/locks/keywords.lock"
}

# Index-based removal. tempfile + mv = atomic on same FS (sed -i is not).
remove_one_keyword() {
    local n; n=$(count_lines "$WORK_DIR/keywords.txt")
    [ "$n" -eq 0 ] && { printf '  [INFO] nothing to remove.\n'; return; }
    list_configured_keywords
    local idx
    read -r -p "  Number to remove (blank=cancel): " idx
    [ -z "$idx" ] && { printf '  cancelled.\n'; return; }
    [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "$n" ] || {
        printf '  [ERROR] invalid index.\n'; return 1; }
    ( flock -x -w "$LOCK_WAIT_SEC" 200 || exit 1
      local t; t=$(mktemp "$WORK_DIR/keywords.XXXXXX")
      awk -v target="$idx" 'NF { c++; if (c==target) next } { print }' \
          "$WORK_DIR/keywords.txt" > "$t"
      mv "$t" "$WORK_DIR/keywords.txt"
      printf '  [OK] removed.\n'
    ) 200>"$WORK_DIR/locks/keywords.lock"
}

pause_for_user() { printf '\n  Press Enter...'; read -r _; }

keyword_management_submenu() {
    local c
    while :; do
        clear
        printf '\n=== Keyword Management ===\n'
        list_configured_keywords
        printf '%s\n  1) Add\n  2) Remove\n  3) Back\n%s\n' \
               '--------------------------' '--------------------------'
        read -r -p "  Choice: " c
        case "$c" in
            1) add_one_keyword    ; pause_for_user ;;
            2) remove_one_keyword ; pause_for_user ;;
            3) return ;;
            *) printf '  [ERROR] invalid.\n'; pause_for_user ;;
        esac
    done
}

# ---------- 16. LOG VIEWER (Requirement 4.3) --------------------------------
view_log_full() {
    [ -s "$WORK_DIR/crawler_log.txt" ] || { printf '  [INFO] log empty.\n'; return; }
    if command -v less >/dev/null 2>&1; then less "$WORK_DIR/crawler_log.txt"
    else cat "$WORK_DIR/crawler_log.txt"; fi
}
view_log_tail() {
    [ -s "$WORK_DIR/crawler_log.txt" ] || { printf '  [INFO] log empty.\n'; return; }
    printf '  --- last 20 ---\n'; tail -n 20 "$WORK_DIR/crawler_log.txt"
}
view_alerts() {
    [ -s "$WORK_DIR/alerts.log" ] || { printf '  [INFO] no alerts.\n'; return; }
    printf '  --- alerts ---\n'; cat "$WORK_DIR/alerts.log"
}

log_viewer_submenu() {
    local c
    while :; do
        clear
        printf '\n=== Log Viewer ===\n'
        printf '  Log entries: %s   Alerts: %s\n' \
               "$(count_lines "$WORK_DIR/crawler_log.txt")" \
               "$(count_lines "$WORK_DIR/alerts.log")"
        printf '%s\n  1) Full log (paged)\n  2) Last 20\n  3) Alerts\n  4) Back\n%s\n' \
               '------------------' '------------------'
        read -r -p "  Choice: " c
        case "$c" in
            1) view_log_full ; pause_for_user ;;
            2) view_log_tail ; pause_for_user ;;
            3) view_alerts   ; pause_for_user ;;
            4) return ;;
            *) printf '  [ERROR] invalid.\n'; pause_for_user ;;
        esac
    done
}

# ---------- 17. DASHBOARD + LIVE MONITOR ------------------------------------
render_dashboard() {
    local st="Idle"
    is_crawler_running && st="Running (PID $(cat "$CRAWLER_PID_FILE"))"
    cat <<EOF

+--------------------------------------------------------------+
|             DARKNET CRAWLER  --  Project XE109               |
|  Yonatan Avitan (s20)        Class 7736-39   Lecturer Z.A.   |
+--------------------------------------------------------------+
  Sites successfully crawled : $(count_lines "$WORK_DIR/crawled.txt")
  Sites in index (known)     : $(count_lines "$WORK_DIR/index.txt")
  Sites pending in queue     : $(count_lines "$WORK_DIR/queue.txt")
  Sites marked [NO ACCESS]   : $(count_lines "$WORK_DIR/failed.txt")
  Active alert keywords      : $(count_lines "$WORK_DIR/keywords.txt")
  Alerts logged              : $(count_lines "$WORK_DIR/alerts.log")
  ------------------------------------------------------------
  Darknet access             : $(get_network_status)
  Crawler status             : $st
+--------------------------------------------------------------+
EOF
}

# Auto-refresh tick. Background probe keeps cache warm without freezing UI.
live_monitor_view() {
    while :; do
        clear; render_dashboard
        printf '\n  Auto-refresh %ss. Press any key to return.\n' "$REFRESH_INTERVAL_SEC"
        ( update_network_status_cache >/dev/null 2>&1 ) & disown 2>/dev/null || true
        if read -r -t "$REFRESH_INTERVAL_SEC" -n 1 -s; then return; fi
    done
}

# ---------- 18. MAIN MENU (Phase E) -----------------------------------------
prompt_for_seed_file() {
    local p
    read -r -p "  Path to seed file (10 .onion URLs, one per line): " p
    p="${p/#\~/$HOME}"
    ingest_seed_file "$p"
}

main_admin_menu() {
    local c
    while :; do
        clear; render_dashboard
        cat <<'MENU'

  ============== Main Menu ==============
  1) Load seed file (10 .onion URLs)
  2) Manage alert keywords
  3) Start crawler in background
  4) Stop running crawler
  5) Live monitor (auto-refresh)
  6) Refresh network status now
  7) View logs / alerts
  8) Quit (crawler keeps running)
  =======================================
MENU
        read -r -p "  Choice: " c
        case "$c" in
            1) prompt_for_seed_file        ; pause_for_user ;;
            2) keyword_management_submenu                    ;;
            3) start_crawler_in_background ; pause_for_user ;;
            4) stop_crawler_in_background  ; pause_for_user ;;
            5) live_monitor_view                             ;;
            6) update_network_status_cache ; pause_for_user ;;
            7) log_viewer_submenu                            ;;
            8) printf '  Goodbye.\n'; return ;;
            *) printf '  [ERROR] invalid.\n'; pause_for_user ;;
        esac
    done
}

# ---------- 19. ENTRY POINT -------------------------------------------------
print_usage() {
    cat <<USAGE
Darknet Crawler  --  Project XE109  --  Yonatan Avitan (s20)

Usage:
    $0                Launch the Admin UI (default).
    $0 --crawl        Run a single backgrounded crawl pass.
    $0 --help | -h    Print this message.

State directory: $WORK_DIR
USAGE
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    initialize_working_directory || exit 1
    case "${1:-}" in
        --crawl)
            resolve_proxy_command >/dev/null 2>&1 || {
                printf '[FATAL] --crawl: proxychains missing.\n' >&2; exit 1; }
            rebuild_work_queue
            dispatch_crawler_workers
            exit $?
            ;;
        --help|-h) print_usage; exit 0 ;;
        '')
            trap 'release_ui_singleton_lock' EXIT INT TERM
            acquire_ui_singleton_lock || exit 1
            run_preflight_checks      || exit 1
            main_admin_menu
            ;;
        *) printf '[ERROR] unknown argument: %s\n' "$1" >&2; print_usage; exit 2 ;;
    esac
fi
# =========================== END OF FILE ===================================
