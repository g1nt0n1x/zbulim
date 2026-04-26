#!/usr/bin/env bash
# port_snmp.sh — Port 161 (UDP) SNMP enumeration

enum_snmp() {
    local target="$1"
    progress "SNMP (161/UDP)"

    local community=""

    # community string brute force
    if command -v onesixtyone &>/dev/null; then
        local snmp_wl=""
        for wl in \
            /usr/share/seclists/Discovery/SNMP/snmp.txt \
            /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt; do
            [[ -f "$wl" ]] && snmp_wl="$wl" && break
        done

        if [[ -n "$snmp_wl" ]]; then
            info "Brute-forcing SNMP community strings..."
            local onesixtyone_out
            onesixtyone_out=$(onesixtyone "$target" -c "$snmp_wl" 2>&1) || true
            log_verbose "$onesixtyone_out"

            community=$(echo "$onesixtyone_out" | grep -oP '\[.*?\]\s*\K\S+' | head -1) || true
            if [[ -z "$community" ]]; then
                community=$(echo "$onesixtyone_out" | grep -oP "\\[$target\\]\\s+\\K\\S+" | head -1) || true
            fi
        else
            warn "No SNMP community wordlist found — trying 'public'..."
        fi
    else
        warn "onesixtyone not found — trying 'public'..."
    fi

    # fallback: try public and private
    if [[ -z "$community" ]]; then
        for c in public private; do
            if snmpwalk -v2c -c "$c" "$target" 1.3.6.1.2.1.1.1.0 2>&1 | grep -qv 'Timeout\|No Response'; then
                community="$c"
                break
            fi
        done 2>/dev/null || true
    fi

    if [[ -z "$community" ]]; then
        info "SNMP: no valid community string found."
        return
    fi

    echo "$community" > "${RECONDIR}/snmp-community.txt"
    fix_owner "${RECONDIR}/snmp-community.txt"

    notify_finding "SNMP COMMUNITY STRING FOUND" \
        "Community: ${community}" \
        "Running targeted SNMP walks..."

    # targeted OID walks
    info "SNMP: extracting users..."
    snmpwalk -v2c -c "$community" "$target" 1.3.6.1.4.1.77.1.2.25 \
        2>/dev/null > "${RECONDIR}/snmp-users-raw.txt" || true
    if [[ -s "${RECONDIR}/snmp-users-raw.txt" ]]; then
        grep -oP 'STRING:\s*"\K[^"]+' "${RECONDIR}/snmp-users-raw.txt" 2>/dev/null | \
            sort -u > "${RECONDIR}/snmp-users.txt" || true
        fix_owner "${RECONDIR}/snmp-users.txt"
        if [[ -s "${RECONDIR}/snmp-users.txt" ]]; then
            local user_count
            user_count=$(wc -l < "${RECONDIR}/snmp-users.txt")
            local users_preview
            users_preview=$(head -10 "${RECONDIR}/snmp-users.txt" | tr '\n' ', ' | sed 's/,$//')
            notify_finding "SNMP USERS EXTRACTED (${user_count})" "$users_preview"
            merge_users_plain "${RECONDIR}/snmp-users.txt"
        fi
    fi
    rm -f "${RECONDIR}/snmp-users-raw.txt"

    info "SNMP: extracting running processes..."
    snmpwalk -v2c -c "$community" "$target" 1.3.6.1.2.1.25.4.2.1.2 \
        2>/dev/null > "${RECONDIR}/snmp-processes.txt" || true
    fix_owner "${RECONDIR}/snmp-processes.txt"
    rm_if_empty "${RECONDIR}/snmp-processes.txt"
    if [[ -s "${RECONDIR}/snmp-processes.txt" ]]; then
        local proc_count
        proc_count=$(wc -l < "${RECONDIR}/snmp-processes.txt")
        info "SNMP: ${proc_count} running processes captured"
    fi

    info "SNMP: extracting installed software..."
    snmpwalk -v2c -c "$community" "$target" 1.3.6.1.2.1.25.6.3.1.2 \
        2>/dev/null > "${RECONDIR}/snmp-software.txt" || true
    fix_owner "${RECONDIR}/snmp-software.txt"
    rm_if_empty "${RECONDIR}/snmp-software.txt"

    info "SNMP: extracting open TCP ports (internal view)..."
    snmpwalk -v2c -c "$community" "$target" 1.3.6.1.2.1.6.13.1.3 \
        2>/dev/null > "${RECONDIR}/snmp-ports.txt" || true
    fix_owner "${RECONDIR}/snmp-ports.txt"
    rm_if_empty "${RECONDIR}/snmp-ports.txt"

    # full walk
    info "SNMP: running full walk (this may take a while)..."
    snmpwalk -v2c -c "$community" "$target" \
        2>/dev/null > "${RECONDIR}/snmpwalk.txt" || true
    fix_owner "${RECONDIR}/snmpwalk.txt"
    rm_if_empty "${RECONDIR}/snmpwalk.txt"
    if [[ -s "${RECONDIR}/snmpwalk.txt" ]]; then
        local walk_lines
        walk_lines=$(wc -l < "${RECONDIR}/snmpwalk.txt")
        success "SNMP full walk: ${BOLD}${walk_lines}${RESET} lines — ${RECONDIR}/snmpwalk.txt"
    fi

    # snmp-check for pretty output
    if command -v snmp-check &>/dev/null; then
        info "SNMP: running snmp-check..."
        snmp-check "$target" -c "$community" \
            2>/dev/null > "${RECONDIR}/snmp-check.txt" || true
        fix_owner "${RECONDIR}/snmp-check.txt"
        rm_if_empty "${RECONDIR}/snmp-check.txt"
    fi

    # nmap SNMP scripts
    info "SNMP: running nmap scripts..."
    nmap -sU -p 161 -Pn \
        --script=snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr,snmp-netstat \
        -oN "${RECONDIR}/snmp-nmap.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/snmp-nmap.txt"
    rm_if_empty "${RECONDIR}/snmp-nmap.txt"
}
