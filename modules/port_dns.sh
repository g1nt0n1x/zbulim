#!/usr/bin/env bash
# port_dns.sh — Port 53 DNS enumeration

enum_dns() {
    local target="$1"
    progress "DNS (53)"

    if [[ -z "${DOMAIN:-}" ]]; then
        warn "DNS: no domain known yet — will retry after HTTP module if domain is detected."
        DNS_DEFERRED=true
        return
    fi

    _run_dns_enum "$target"
}

enum_dns_deferred() {
    local target="$1"
    if [[ "${DNS_DEFERRED:-false}" != "true" ]]; then
        return
    fi
    if [[ -z "${DOMAIN:-}" ]]; then
        warn "DNS: still no domain known — skipping DNS enumeration."
        return
    fi
    progress "DNS (53) — deferred"
    _run_dns_enum "$target"
}

_run_dns_enum() {
    local target="$1"

    info "DNS enumeration for domain: ${BOLD}${DOMAIN}${RESET}"

    # zone transfer
    info "Attempting zone transfer..."
    dig axfr "@${target}" "$DOMAIN" > "${RECONDIR}/dns-axfr.txt" 2>&1 || true
    fix_owner "${RECONDIR}/dns-axfr.txt"

    if grep -qP '\bIN\b' "${RECONDIR}/dns-axfr.txt" 2>/dev/null && \
       ! grep -qi 'Transfer failed\|REFUSED\|SERVFAIL' "${RECONDIR}/dns-axfr.txt" 2>/dev/null; then

        local record_count
        record_count=$(grep -cP '\bIN\b' "${RECONDIR}/dns-axfr.txt" || echo 0)

        notify_critical "DNS ZONE TRANSFER SUCCESS" \
            "${record_count} records for ${DOMAIN}" \
            "Saved to: ${RECONDIR}/dns-axfr.txt" \
            "$(head -5 "${RECONDIR}/dns-axfr.txt")"

        # extract subdomains from zone transfer
        grep -oP "\\S+\\.${DOMAIN}" "${RECONDIR}/dns-axfr.txt" 2>/dev/null | \
            sed "s/\\.$//" | sort -u > "${RECONDIR}/dns-subdomains.txt" || true
        fix_owner "${RECONDIR}/dns-subdomains.txt"

        if [[ -s "${RECONDIR}/dns-subdomains.txt" ]]; then
            local subs
            subs=$(cat "${RECONDIR}/dns-subdomains.txt" | tr '\n' ', ' | sed 's/,$//')
            notify_finding "DNS SUBDOMAINS FROM ZONE TRANSFER" "$subs"

            # add all subdomains to /etc/hosts
            local all_names
            all_names=$(cat "${RECONDIR}/dns-subdomains.txt" | tr '\n' ' ')
            add_to_hosts "$target" "$all_names"
        fi
    else
        info "Zone transfer failed (expected on most targets)."
        rm_if_empty "${RECONDIR}/dns-axfr.txt"
    fi

    # standard queries
    info "Running DNS queries (ANY, NS, MX, TXT)..."
    {
        echo "=== ANY ==="
        dig any "$DOMAIN" "@${target}" 2>&1 || true
        echo "=== NS ==="
        dig ns "$DOMAIN" "@${target}" 2>&1 || true
        echo "=== MX ==="
        dig mx "$DOMAIN" "@${target}" 2>&1 || true
        echo "=== TXT ==="
        dig txt "$DOMAIN" "@${target}" 2>&1 || true
    } > "${RECONDIR}/dns-records.txt" 2>&1
    fix_owner "${RECONDIR}/dns-records.txt"
    rm_if_empty "${RECONDIR}/dns-records.txt"

    # dnsrecon
    if command -v dnsrecon &>/dev/null; then
        info "Running dnsrecon standard enum..."
        dnsrecon -d "$DOMAIN" -n "$target" -t std \
            > "${RECONDIR}/dns-dnsrecon.txt" 2>&1 || true
        fix_owner "${RECONDIR}/dns-dnsrecon.txt"
        rm_if_empty "${RECONDIR}/dns-dnsrecon.txt"

        info "Running dnsrecon subdomain brute..."
        local dns_wl=""
        for wl in \
            /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
            /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt; do
            [[ -f "$wl" ]] && dns_wl="$wl" && break
        done

        if [[ -n "$dns_wl" ]]; then
            dnsrecon -d "$DOMAIN" -n "$target" -t brt -D "$dns_wl" \
                >> "${RECONDIR}/dns-subdomains.txt" 2>&1 || true
            fix_owner "${RECONDIR}/dns-subdomains.txt"
        fi
    fi

    # nmap scripts
    info "Running DNS nmap scripts..."
    nmap -p 53 -Pn --script=dns-nsid,dns-service-discovery \
        -oN "${RECONDIR}/dns-nmap.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/dns-nmap.txt"
    rm_if_empty "${RECONDIR}/dns-nmap.txt"
}
