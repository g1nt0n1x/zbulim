#!/usr/bin/env bash
# port_smb.sh — Port 139/445 SMB enumeration (extracted from original zbulim)

enum_smb() {
    local target="$1"
    progress "SMB (445)"

    if ! command -v nxc &>/dev/null; then
        warn "nxc not found — skipping SMB enumeration."
        return
    fi

    local NXC_LOCAL_FLAG=""
    $LOCAL_AUTH && NXC_LOCAL_FLAG="--local-auth"

    # ── Host discovery + /etc/hosts ───────────────────────────────────────────
    info "Enumerating target via SMB..."
    rm -f "${RECONDIR}/hosts"
    local nxc_init
    nxc_init=$(nxc smb "$target" $NXC_LOCAL_FLAG \
        --generate-hosts-file "${RECONDIR}/hosts" 2>&1) || true
    if [[ -s "${RECONDIR}/hosts" ]]; then
        sort -u "${RECONDIR}/hosts" > "${RECONDIR}/hosts.tmp" \
            && mv "${RECONDIR}/hosts.tmp" "${RECONDIR}/hosts"
        fix_owner "${RECONDIR}/hosts"
    else
        rm -f "${RECONDIR}/hosts"
    fi

    local init_stripped
    init_stripped=$(echo "$nxc_init" | sed 's/\x1b\[[0-9;]*m//g')
    HOSTNAME=$(echo "$init_stripped" | grep -oP 'name:\K[^\s\)]+' | head -1) || true
    local smb_domain
    smb_domain=$(echo "$init_stripped" | grep -oP 'domain:\K[^\s\)]+' | head -1) || true
    [[ -n "$smb_domain" && -z "${DOMAIN:-}" ]] && DOMAIN="$smb_domain"

    [[ -n "$HOSTNAME" ]] && success "Hostname: ${BOLD}${HOSTNAME}${RESET}"
    [[ -n "$DOMAIN"   ]] && success "Domain  : ${BOLD}${DOMAIN}${RESET}"

    if [[ -s "${RECONDIR}/hosts" ]]; then
        local hosts_entry
        hosts_entry=$(head -1 "${RECONDIR}/hosts")
        success "Hosts entry: ${BOLD}${hosts_entry}${RESET}"

        if grep -qF "$target" /etc/hosts 2>/dev/null; then
            info "Target already present in /etc/hosts."
        else
            if tee -a /etc/hosts < "${RECONDIR}/hosts" > /dev/null 2>&1; then
                success "Appended to /etc/hosts"
            else
                warn "Could not append to /etc/hosts."
            fi
        fi
    else
        warn "nxc returned no host info — SMB may not be available."
    fi

    # ── Null session ──────────────────────────────────────────────────────────
    info "Testing null session..."
    local nxc_null
    nxc_null=$(nxc smb "$target" -u '' -p '' $NXC_LOCAL_FLAG 2>&1) || true
    nxc_result "$nxc_null"

    if echo "$nxc_null" | grep -qP '\[\+\]'; then
        NULL_AUTH=true
        notify_warning "NULL SESSION AUTHENTICATED" \
            "Anonymous access is allowed on this target." \
            "Shares, users, and further enum will use null creds."
    fi

    # ── Guest login ───────────────────────────────────────────────────────────
    info "Testing guest login..."
    local nxc_guest
    nxc_guest=$(nxc smb "$target" -u 'guest' -p '' $NXC_LOCAL_FLAG 2>&1) || true
    nxc_result "$nxc_guest"

    if echo "$nxc_guest" | grep -qP '\[\+\]'; then
        GUEST_AUTH=true
        notify_warning "GUEST LOGIN AUTHENTICATED" \
            "Guest account is active on this target."
    fi

    # ── SMB signing ───────────────────────────────────────────────────────────
    info "Checking SMB signing..."
    nxc smb "$target" $NXC_LOCAL_FLAG \
        --gen-relay-list "${RECONDIR}/signing-off.txt" > /dev/null 2>&1 || true
    rm_if_empty "${RECONDIR}/signing-off.txt"
    fix_owner "${RECONDIR}/signing-off.txt"

    if [[ -s "${RECONDIR}/signing-off.txt" ]]; then
        notify_warning "SMB SIGNING NOT REQUIRED" \
            "Target is vulnerable to SMB relay attacks." \
            "Saved to: ${RECONDIR}/signing-off.txt"
    else
        info "SMB signing is required — relay not possible."
    fi

    # ── Password policy ───────────────────────────────────────────────────────
    if $NULL_AUTH || $GUEST_AUTH; then
        info "Enumerating password policy..."
        local pp_user pp_pass
        if $NULL_AUTH; then pp_user=''; pp_pass=''; else pp_user='guest'; pp_pass=''; fi
        local passpol_out
        passpol_out=$(nxc smb "$target" -u "$pp_user" -p "$pp_pass" \
            $NXC_LOCAL_FLAG --pass-pol 2>&1) || true
        local passpol_stripped
        passpol_stripped=$(echo "$passpol_out" | sed 's/\x1b\[[0-9;]*m//g')
        LOCKOUT_THRESHOLD=$(echo "$passpol_stripped" | \
            grep -oP 'Account Lockout Threshold:\s*\K\S+' | head -1 || echo "?")
        MIN_PW_LEN=$(echo "$passpol_stripped" | \
            grep -oP 'Minimum password length:\s*\K\S+' | head -1 || echo "?")
        PW_COMPLEX=$(echo "$passpol_stripped" | \
            grep -oP 'Domain Password Complex:\s*\K\S+' | head -1 || echo "?")
        if [[ "$LOCKOUT_THRESHOLD" != "?" ]]; then
            success "Lockout: ${BOLD}${LOCKOUT_THRESHOLD}${RESET} | Min length: ${BOLD}${MIN_PW_LEN}${RESET} | Complexity: ${BOLD}${PW_COMPLEX}${RESET}"
        fi
    fi

    # ── Share + User enumeration ──────────────────────────────────────────────
    if $NULL_AUTH || $GUEST_AUTH; then
        section "Share + User Enumeration"
        _smb_enum_with_creds "$target" "$NXC_LOCAL_FLAG"
    fi

    # ── Spider + Download ─────────────────────────────────────────────────────
    _smb_spider "$target" "$NXC_LOCAL_FLAG"

    # ── RID Brute Force ───────────────────────────────────────────────────────
    section "RID Brute Force"

    info "RID brute via SMB (anonymous)..."
    local rid_out
    rid_out=$(nxc smb "$target" -u '' -p '' $NXC_LOCAL_FLAG --rid-brute 2>&1) || true
    parse_rid_brute "$rid_out" "${RECONDIR}/rid-brute-smb.txt"
    if [[ -s "${RECONDIR}/rid-brute-smb.txt" ]]; then
        local rid_count
        rid_count=$(wc -l < "${RECONDIR}/rid-brute-smb.txt")
        success "RID brute found ${BOLD}${rid_count}${RESET} users (anon)"
        merge_users "${RECONDIR}/rid-brute-smb.txt"
    else
        warn "No users found via anonymous RID brute."
    fi

    if $GUEST_AUTH; then
        info "RID brute via SMB guest session..."
        rid_out=$(nxc smb "$target" -u 'guest' -p '' $NXC_LOCAL_FLAG --rid-brute 2>&1) || true
        parse_rid_brute "$rid_out" "${RECONDIR}/rid-brute-smb-guest.txt"
        if [[ -s "${RECONDIR}/rid-brute-smb-guest.txt" ]]; then
            rid_count=$(wc -l < "${RECONDIR}/rid-brute-smb-guest.txt")
            success "RID brute found ${BOLD}${rid_count}${RESET} users (guest)"
            merge_users "${RECONDIR}/rid-brute-smb-guest.txt"
        fi
    fi

    if [[ -s "${RECONDIR}/users.txt" ]]; then
        local total_users
        total_users=$(wc -l < "${RECONDIR}/users.txt")
        success "Unified users.txt: ${BOLD}${total_users}${RESET} unique users"
    fi
}

_smb_enum_with_creds() {
    local target="$1"
    local nxc_flags="$2"

    local cred_sets=()
    $NULL_AUTH  && cred_sets+=("null::")
    $GUEST_AUTH && cred_sets+=("guest:guest:")

    for cred in "${cred_sets[@]}"; do
        local label user pass
        label=$(echo "$cred" | cut -d: -f1)
        user=$(echo "$cred" | cut -d: -f2)
        pass=$(echo "$cred" | cut -d: -f3)

        # shares
        info "Enumerating shares via ${label} session..."
        local shares_out
        shares_out=$(nxc smb "$target" -u "$user" -p "$pass" $nxc_flags --shares 2>&1) || true
        echo "$shares_out" | safe_write "${RECONDIR}/shares-${label}.txt" || true
        if [[ -s "${RECONDIR}/shares-${label}.txt" ]]; then
            local share_count
            share_count=$(grep -cP 'READ|WRITE' "${RECONDIR}/shares-${label}.txt" || true)

            local share_lines=()
            while IFS= read -r line; do
                share_lines+=("$line")
            done < <(echo "$shares_out" | sed 's/\x1b\[[0-9;]*m//g' | \
                grep -vP '^\[\*\]|^\[\+\]|^\[-\]|^$' | head -15)

            notify_finding "SMB SHARES (${label}) — ${share_count} accessible" \
                "${share_lines[@]}"
        fi

        # users
        info "Enumerating users via ${label} session..."
        nxc smb "$target" -u "$user" -p "$pass" $nxc_flags \
            --users --users-export "${RECONDIR}/users-${label}.txt" > /dev/null 2>&1 || true
        rm_if_empty "${RECONDIR}/users-${label}.txt"
        fix_owner "${RECONDIR}/users-${label}.txt"
        if [[ -s "${RECONDIR}/users-${label}.txt" ]]; then
            local user_count
            user_count=$(wc -l < "${RECONDIR}/users-${label}.txt")
            success "Exported ${BOLD}${user_count}${RESET} users (${label})"
            merge_users "${RECONDIR}/users-${label}.txt"
        fi
    done
}

_smb_spider() {
    local target="$1"
    local nxc_flags="$2"

    local spider_user="" spider_pass="" spider_auth=false
    if $GUEST_AUTH; then
        local guest_shares
        guest_shares=$(grep -cP 'READ' "${RECONDIR}/shares-guest.txt" 2>/dev/null || true)
        [[ "${guest_shares:-0}" -gt 0 ]] && spider_user="guest" && spider_auth=true
    fi
    if ! $spider_auth && $NULL_AUTH; then
        local null_shares
        null_shares=$(grep -cP 'READ' "${RECONDIR}/shares-null.txt" 2>/dev/null || true)
        [[ "${null_shares:-0}" -gt 0 ]] && spider_auth=true
    fi

    if $spider_auth; then
        section "Share Download (spider_plus)"
        info "Spidering and downloading accessible shares..."
        nxc smb "$target" -u "$spider_user" -p "$spider_pass" $nxc_flags \
            -M spider_plus -o "DOWNLOAD_FLAG=True" > /dev/null 2>&1 || true

        local spider_src="$HOME/.nxc/modules/nxc_spider_plus"
        if [[ -d "${spider_src}/${target}" ]]; then
            mkdir -p "${LOOTDIR}"
            cp -r "${spider_src}/${target}/." "${LOOTDIR}/" 2>/dev/null || true
            [[ -f "${spider_src}/${target}.json" ]] && \
                cp "${spider_src}/${target}.json" "${LOOTDIR}/spider_plus.json" 2>/dev/null || true
            chown -R "$REAL_USER:$REAL_GROUP" "$LOOTDIR" 2>/dev/null || true

            local loot_files
            loot_files=$(find "${LOOTDIR}" -type f ! -name 'spider_plus.json' 2>/dev/null | wc -l || true)
            if [[ "$loot_files" -gt 0 ]]; then
                local file_list=()
                while IFS= read -r f; do
                    file_list+=("  $f")
                done < <(find "${LOOTDIR}" -type f ! -name 'spider_plus.json' -printf '%P\n' 2>/dev/null | head -20)

                notify_finding "SMB FILES DOWNLOADED (${loot_files} files)" \
                    "Saved to: ${LOOTDIR}/" \
                    "${file_list[@]}"
            else
                info "Spider completed but no files downloaded."
                rmdir "${LOOTDIR}" 2>/dev/null || true
            fi
        fi
    fi
}
