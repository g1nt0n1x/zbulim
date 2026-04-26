#!/usr/bin/env bash
# common.sh — shared helpers, colors, notifications, /etc/hosts management

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Banner ────────────────────────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ███████╗██████╗ ██╗   ██╗██╗     ██╗███╗   ███╗"
    echo "  ╚══███╔╝██╔══██╗██║   ██║██║     ██║████╗ ████║"
    echo "    ███╔╝ ██████╔╝██║   ██║██║     ██║██╔████╔██║"
    echo "   ███╔╝  ██╔══██╗██║   ██║██║     ██║██║╚██╔╝██║"
    echo "  ███████╗██████╔╝╚██████╔╝███████╗██║██║ ╚═╝ ██║"
    echo "  ╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝╚═╝     ╚═╝"
    echo -e "${RESET}${DIM}         zbulim v2 — recon automation by g1nt0n1x${RESET}"
    echo
}

# ── Basic logging ─────────────────────────────────────────────────────────────
info()    { echo -e "${BOLD}${CYAN}[*]${RESET} $*"; }
success() { echo -e "${BOLD}${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${BOLD}${YELLOW}[!]${RESET} $*"; }
fail()    { echo -e "${BOLD}${RED}[-]${RESET} $*"; }
section() { echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

log_verbose() {
    if [[ -n "${LOGFILE:-}" ]]; then
        echo "$@" >> "$LOGFILE"
    fi
}

# ── Progress line ─────────────────────────────────────────────────────────────
TOTAL_MODULES=0
CURRENT_MODULE=0
CURRENT_PHASE=0
TOTAL_PHASES=5

progress() {
    local module_name="$1"
    (( CURRENT_MODULE++ )) || true
    echo -e "\n${DIM}[Phase ${CURRENT_PHASE}/${TOTAL_PHASES}] [Module ${CURRENT_MODULE}/${TOTAL_MODULES}: ${module_name}] [Elapsed: $(elapsed)]${RESET}"
}

# ── Notification boxes ────────────────────────────────────────────────────────
notify_finding() {
    local title="$1"; shift
    echo
    echo -e "${GREEN}${BOLD}  ┌──────────────────────────────────────────────────────────┐${RESET}"
    printf "${GREEN}${BOLD}  │ %-56s │${RESET}\n" "$title"
    echo -e "${GREEN}${BOLD}  ├──────────────────────────────────────────────────────────┤${RESET}"
    for line in "$@"; do
        printf "${GREEN}${BOLD}  │${RESET} %-56s ${GREEN}${BOLD}│${RESET}\n" "$line"
    done
    echo -e "${GREEN}${BOLD}  └──────────────────────────────────────────────────────────┘${RESET}"
    echo
}

notify_warning() {
    local title="$1"; shift
    echo
    echo -e "${YELLOW}${BOLD}  ┌──────────────────────────────────────────────────────────┐${RESET}"
    printf "${YELLOW}${BOLD}  │ %-56s │${RESET}\n" "$title"
    echo -e "${YELLOW}${BOLD}  ├──────────────────────────────────────────────────────────┤${RESET}"
    for line in "$@"; do
        printf "${YELLOW}${BOLD}  │${RESET} %-56s ${YELLOW}${BOLD}│${RESET}\n" "$line"
    done
    echo -e "${YELLOW}${BOLD}  └──────────────────────────────────────────────────────────┘${RESET}"
    echo
}

notify_critical() {
    local title="$1"; shift
    echo
    echo -e "${RED}${BOLD}  ┌──────────────────────────────────────────────────────────┐${RESET}"
    printf "${RED}${BOLD}  │ %-56s │${RESET}\n" "$title"
    echo -e "${RED}${BOLD}  ├──────────────────────────────────────────────────────────┤${RESET}"
    for line in "$@"; do
        printf "${RED}${BOLD}  │${RESET} %-56s ${RED}${BOLD}│${RESET}\n" "$line"
    done
    echo -e "${RED}${BOLD}  └──────────────────────────────────────────────────────────┘${RESET}"
    echo
}

# ── File ownership helpers ────────────────────────────────────────────────────
REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_GROUP="$(id -gn "$REAL_USER" 2>/dev/null || echo "$REAL_USER")"

safe_write() {
    local dest="$1"
    cat > "$dest"
    if [[ ! -s "$dest" ]]; then
        rm -f "$dest"
        return 1
    fi
    chown "$REAL_USER:$REAL_GROUP" "$dest" 2>/dev/null || true
    return 0
}

fix_owner() {
    local f="$1"
    if [[ -e "$f" ]]; then
        chown "$REAL_USER:$REAL_GROUP" "$f" 2>/dev/null || true
    fi
}

rm_if_empty() {
    local f="$1"
    if [[ -f "$f" && ! -s "$f" ]]; then
        rm -f "$f"
    fi
}

# ── Elapsed time ──────────────────────────────────────────────────────────────
elapsed() {
    local secs=$(( $(date +%s) - START_TIME ))
    printf "%dm%02ds" $(( secs / 60 )) $(( secs % 60 ))
}

# ── Port check ────────────────────────────────────────────────────────────────
port_open() {
    local port="$1"
    [[ -z "${TCP_PORTS:-}" && -z "${UDP_PORTS:-}" ]] && return 0
    if [[ "$2" == "udp" ]]; then
        echo ",$UDP_PORTS," | grep -q ",$port,"
    else
        echo ",$TCP_PORTS," | grep -q ",$port,"
    fi
}

# ── nxc result parser ────────────────────────────────────────────────────────
nxc_result() {
    local output="$1"
    local stripped
    stripped=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')
    local line
    line=$(echo "$stripped" | grep -P '\[\+\]|\[-\]' | head -1) || true
    [[ -z "$line" ]] && return
    if echo "$line" | grep -qP '\[\+\]'; then
        echo -e "  ${BOLD}${GREEN}${line}${RESET}"
    else
        echo -e "  ${BOLD}${RED}${line}${RESET}"
    fi
}

# ── User merging ──────────────────────────────────────────────────────────────
merge_users() {
    local src_file="$1"
    [[ ! -s "$src_file" ]] && return

    local tmp_users
    tmp_users=$(mktemp)

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local clean
        clean=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')
        local user
        user=$(echo "$clean" | awk '{print $1}' | sed 's/.*\\//' | sed 's/@.*//')
        [[ -n "$user" && "$user" != "SMB" && "$user" != "LDAP" ]] && echo "$user" >> "$tmp_users"
    done < "$src_file"

    if [[ -s "$tmp_users" ]]; then
        touch "${RECONDIR}/users.txt"
        cat "${RECONDIR}/users.txt" "$tmp_users" | sort -uf > "${RECONDIR}/users.txt.tmp"
        mv "${RECONDIR}/users.txt.tmp" "${RECONDIR}/users.txt"
        fix_owner "${RECONDIR}/users.txt"
    fi
    rm -f "$tmp_users"
}

merge_users_plain() {
    local src_file="$1"
    [[ ! -s "$src_file" ]] && return
    touch "${RECONDIR}/users.txt"
    cat "${RECONDIR}/users.txt" "$src_file" | sort -uf > "${RECONDIR}/users.txt.tmp"
    mv "${RECONDIR}/users.txt.tmp" "${RECONDIR}/users.txt"
    fix_owner "${RECONDIR}/users.txt"
}

# ── /etc/hosts management ────────────────────────────────────────────────────
add_to_hosts() {
    local ip="$1"
    local names="$2"

    local to_add=""
    for name in $names; do
        if ! grep -qP "\\b${name}\\b" /etc/hosts 2>/dev/null; then
            to_add="$to_add $name"
        fi
    done
    to_add=$(echo "$to_add" | xargs)

    if [[ -n "$to_add" ]]; then
        if grep -qP "^${ip}\\s" /etc/hosts 2>/dev/null; then
            sed -i "s/^${ip}\\s.*$/& ${to_add}/" /etc/hosts
        else
            echo "${ip}    ${to_add}" >> /etc/hosts
        fi
        notify_finding "/etc/hosts updated" "${ip} →  ${to_add}"
    fi
}

# ── RID brute parser ─────────────────────────────────────────────────────────
parse_rid_brute() {
    local output="$1"
    local rid_file="$2"

    echo "$output" | sed 's/\x1b\[[0-9;]*m//g' | \
        grep -i 'SidTypeUser' | \
        grep -oP '\d+:\s+\S+\\(\K[^(\s]+)' | \
        sed 's/[[:space:]]*$//' | \
        sort -uf | safe_write "$rid_file" || true
}

# ── Extract open ports from gnmap ─────────────────────────────────────────────
extract_open_ports() {
    local gnmap_file="$1"
    local proto="${2:-tcp}"
    grep -oP "\d+(?=/open/${proto})" "$gnmap_file" 2>/dev/null | paste -sd, || true
}

# ── Ctrl+C trap ───────────────────────────────────────────────────────────────
BACKGROUND_PIDS=()

cleanup() {
    echo
    warn "Interrupted — cleaning up..."
    for pid in "${BACKGROUND_PIDS[@]}"; do
        kill "$pid" 2>/dev/null && info "Killed background process $pid"
    done
    if declare -F print_summary &>/dev/null; then
        section "PARTIAL SUMMARY (interrupted)"
        print_summary
    fi
    [[ -n "${LOGFILE:-}" ]] && info "Full log: ${LOGFILE}"
    exit 130
}

trap cleanup INT TERM
