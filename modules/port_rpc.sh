#!/usr/bin/env bash
# port_rpc.sh — Port 135 MSRPC enumeration

enum_rpc() {
    local target="$1"
    progress "MSRPC (135)"

    # rpcdump via impacket
    if command -v rpcdump.py &>/dev/null || command -v impacket-rpcdump &>/dev/null; then
        info "Dumping RPC endpoints..."
        local rpcdump_cmd
        command -v rpcdump.py &>/dev/null && rpcdump_cmd="rpcdump.py" || rpcdump_cmd="impacket-rpcdump"
        $rpcdump_cmd "$target" > "${RECONDIR}/rpcdump.txt" 2>&1 || true
        fix_owner "${RECONDIR}/rpcdump.txt"
        rm_if_empty "${RECONDIR}/rpcdump.txt"

        if [[ -s "${RECONDIR}/rpcdump.txt" ]]; then
            local endpoint_count
            endpoint_count=$(grep -c 'Protocol' "${RECONDIR}/rpcdump.txt" 2>/dev/null || echo 0)
            info "RPC: ${endpoint_count} endpoints found"

            # check for spoolss (PrintNightmare)
            if grep -qi 'spoolss\|\\\\pipe\\\\spoolss' "${RECONDIR}/rpcdump.txt" 2>/dev/null; then
                notify_warning "PRINT SPOOLER SERVICE FOUND" \
                    "\\pipe\\spoolss is available" \
                    "Potential PrintNightmare (CVE-2021-1675 / CVE-2021-34527)"
            fi
        fi
    else
        warn "rpcdump.py / impacket-rpcdump not found."
    fi

    # rpcinfo
    if command -v rpcinfo &>/dev/null; then
        info "Querying rpcinfo..."
        rpcinfo -p "$target" > "${RECONDIR}/rpcinfo.txt" 2>&1 || true
        fix_owner "${RECONDIR}/rpcinfo.txt"
        rm_if_empty "${RECONDIR}/rpcinfo.txt"
    fi

    # nmap
    info "Running MSRPC nmap scripts..."
    nmap -p 135 -Pn --script=msrpc-enum \
        -oN "${RECONDIR}/rpc-nmap.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/rpc-nmap.txt"
    rm_if_empty "${RECONDIR}/rpc-nmap.txt"
}
