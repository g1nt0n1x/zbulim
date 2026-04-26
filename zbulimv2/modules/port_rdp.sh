#!/usr/bin/env bash
# port_rdp.sh — Port 3389 RDP enumeration

enum_rdp() {
    local target="$1"
    progress "RDP (3389)"

    # nmap NTLM info leak + encryption check
    info "Running RDP nmap scripts..."
    nmap -p 3389 -Pn \
        --script=rdp-ntlm-info,rdp-enum-encryption \
        -oN "${RECONDIR}/rdp-info.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/rdp-info.txt"

    # extract NTLM domain info
    local ntlm_domain
    ntlm_domain=$(grep -oP 'Target_Name:\s*\K\S+' "${RECONDIR}/rdp-info.txt" 2>/dev/null | head -1) || true
    local ntlm_dns
    ntlm_dns=$(grep -oP 'DNS_Domain_Name:\s*\K\S+' "${RECONDIR}/rdp-info.txt" 2>/dev/null | head -1) || true
    local ntlm_host
    ntlm_host=$(grep -oP 'DNS_Computer_Name:\s*\K\S+' "${RECONDIR}/rdp-info.txt" 2>/dev/null | head -1) || true

    if [[ -n "$ntlm_domain" ]]; then
        notify_finding "RDP NTLM INFO LEAK" \
            "Domain: ${ntlm_domain}" \
            "DNS: ${ntlm_dns:-n/a}" \
            "Host: ${ntlm_host:-n/a}"
        [[ -z "${DOMAIN:-}" && -n "$ntlm_dns" ]] && DOMAIN="$ntlm_dns"
    fi

    # check NLA/encryption
    if grep -qi 'ENCRYPT_WHEN_POSSIBLE\|Not Coverage' "${RECONDIR}/rdp-info.txt" 2>/dev/null; then
        notify_warning "RDP WEAK ENCRYPTION" \
            "NLA may not be enforced — easier brute force"
    fi

    # nxc auth check
    if command -v nxc &>/dev/null; then
        local NXC_LOCAL_FLAG=""
        $LOCAL_AUTH && NXC_LOCAL_FLAG="--local-auth"

        info "Checking RDP access..."
        local rdp_out
        rdp_out=$(nxc rdp "$target" -u '' -p '' $NXC_LOCAL_FLAG 2>&1) || true
        log_verbose "$rdp_out"
        if echo "$rdp_out" | grep -qP '\[\+\]'; then
            notify_warning "RDP ANONYMOUS ACCESS" \
                "RDP accessible without credentials!"
        elif echo "$rdp_out" | sed 's/\x1b\[[0-9;]*m//g' | grep -qP 'RDP'; then
            info "RDP: port open, auth required"
        fi
    fi
}
