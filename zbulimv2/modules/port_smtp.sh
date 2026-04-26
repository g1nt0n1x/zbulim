#!/usr/bin/env bash
# port_smtp.sh — Port 25/587 SMTP enumeration

enum_smtp() {
    local target="$1"
    local port="${2:-25}"
    progress "SMTP (${port})"

    # nmap scripts
    info "Running SMTP nmap scripts on port ${port}..."
    nmap -p "$port" -Pn \
        --script=smtp-commands,smtp-enum-users,smtp-open-relay,smtp-ntlm-info \
        -oN "${RECONDIR}/smtp-nmap-${port}.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/smtp-nmap-${port}.txt"

    # check for NTLM domain leak
    local ntlm_domain
    ntlm_domain=$(grep -oP 'Target_Name:\s*\K\S+' "${RECONDIR}/smtp-nmap-${port}.txt" 2>/dev/null | head -1) || true
    if [[ -n "$ntlm_domain" ]]; then
        notify_finding "SMTP NTLM DOMAIN LEAK" \
            "Domain: ${ntlm_domain}" \
            "Leaked via SMTP NTLM authentication"
        [[ -z "${DOMAIN:-}" ]] && DOMAIN="$ntlm_domain"
    fi

    # check for open relay
    if grep -qi 'open relay\|Server is an open relay' "${RECONDIR}/smtp-nmap-${port}.txt" 2>/dev/null; then
        notify_warning "SMTP OPEN RELAY" \
            "Server accepts mail for any destination!" \
            "Can be used for phishing or spam relay"
    fi

    # check VRFY support from nmap commands output
    local vrfy_supported=false
    if grep -qi 'VRFY' "${RECONDIR}/smtp-nmap-${port}.txt" 2>/dev/null; then
        vrfy_supported=true
    fi

    # smtp-user-enum if available
    if command -v smtp-user-enum &>/dev/null; then
        local user_wordlist=""
        for wl in \
            "${RECONDIR}/users.txt" \
            /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
            /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt; do
            [[ -f "$wl" ]] && user_wordlist="$wl" && break
        done

        if [[ -n "$user_wordlist" ]]; then
            if $vrfy_supported; then
                info "SMTP user enum via VRFY..."
                smtp-user-enum -M VRFY -U "$user_wordlist" -t "$target" -p "$port" \
                    2>/dev/null | tee -a "${RECONDIR}/smtp-users.txt" | log_verbose || true
            fi

            # try RCPT as fallback
            info "SMTP user enum via RCPT TO..."
            smtp-user-enum -M RCPT -U "$user_wordlist" -t "$target" -p "$port" \
                2>/dev/null >> "${RECONDIR}/smtp-users.txt" 2>&1 || true
        fi

        rm_if_empty "${RECONDIR}/smtp-users.txt"
        fix_owner "${RECONDIR}/smtp-users.txt"

        if [[ -s "${RECONDIR}/smtp-users.txt" ]]; then
            local user_count
            user_count=$(grep -c 'exists' "${RECONDIR}/smtp-users.txt" 2>/dev/null || echo 0)
            if [[ "$user_count" -gt 0 ]]; then
                notify_finding "SMTP USERS ENUMERATED" \
                    "${user_count} valid users found" \
                    "Saved to: ${RECONDIR}/smtp-users.txt"
                # extract usernames and merge
                grep 'exists' "${RECONDIR}/smtp-users.txt" | \
                    grep -oP '\S+(?=\s+exists)' | sort -u > "${RECONDIR}/smtp-users-clean.txt" 2>/dev/null || true
                merge_users_plain "${RECONDIR}/smtp-users-clean.txt"
                rm -f "${RECONDIR}/smtp-users-clean.txt"
            fi
        fi
    else
        warn "smtp-user-enum not found — skipping SMTP user enumeration."
    fi
}
