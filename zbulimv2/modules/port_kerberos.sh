#!/usr/bin/env bash
# port_kerberos.sh — Port 88 Kerberos enumeration

enum_kerberos() {
    local target="$1"
    progress "Kerberos (88)"

    if $NULL_AUTH || $GUEST_AUTH; then
        info "Kerberos: skipping kerbrute (null/guest auth available — users already enumerated)."
        return
    fi

    if ! command -v kerbrute &>/dev/null; then
        warn "kerbrute not found — skipping Kerberos user enum."
        info "Install: https://github.com/ropnop/kerbrute/releases"
        return
    fi

    if [[ -z "${DOMAIN:-}" ]]; then
        warn "Domain not detected — cannot run kerbrute."
        return
    fi

    local kerb_wl=""
    for wl in \
        /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
        /usr/share/seclists/Usernames/Names/names.txt \
        /usr/share/wordlists/seclists/Usernames/Names/names.txt \
        /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt; do
        [[ -f "$wl" ]] && kerb_wl="$wl" && break
    done

    if [[ -z "$kerb_wl" ]]; then
        warn "kerbrute: no username wordlist found — install seclists."
        return
    fi

    info "Kerbrute userenum: domain=${BOLD}${DOMAIN}${RESET} dc=${BOLD}${target}${RESET}"
    info "Wordlist: ${DIM}${kerb_wl}${RESET}"

    local kerb_raw
    kerb_raw=$(mktemp)
    kerbrute userenum --dc "$target" -d "$DOMAIN" "$kerb_wl" \
        --output "$kerb_raw" 2>&1 | grep -E 'VALID|ERROR|Done' | head -20 || true

    if [[ -s "$kerb_raw" ]]; then
        grep -oP 'VALID USERNAME:\s+\K\S+' "$kerb_raw" | \
            sed 's/@.*//' | sort -u | \
            safe_write "${RECONDIR}/kerbrute-users.txt" || true
    fi
    rm -f "$kerb_raw"
    fix_owner "${RECONDIR}/kerbrute-users.txt"

    if [[ -s "${RECONDIR}/kerbrute-users.txt" ]]; then
        local kerb_count
        kerb_count=$(wc -l < "${RECONDIR}/kerbrute-users.txt")
        success "Kerbrute found ${BOLD}${kerb_count}${RESET} valid users"
        merge_users "${RECONDIR}/kerbrute-users.txt"

        notify_finding "KERBEROS USERS FOUND" \
            "${kerb_count} valid users via kerbrute" \
            "Saved to: ${RECONDIR}/kerbrute-users.txt"
    else
        info "Kerbrute: no valid users found."
    fi
}
