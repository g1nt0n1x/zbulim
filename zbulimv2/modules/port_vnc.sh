#!/usr/bin/env bash
# port_vnc.sh — Port 5900 VNC enumeration

enum_vnc() {
    local target="$1"
    progress "VNC (5900)"

    # nmap scripts
    info "Running VNC nmap scripts..."
    nmap -p 5900 -Pn --script=vnc-info,vnc-title,vnc-brute \
        -oN "${RECONDIR}/vnc-info.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/vnc-info.txt"

    # check no-auth
    if grep -qi 'Authentication: None\|No authentication' "${RECONDIR}/vnc-info.txt" 2>/dev/null; then
        notify_critical "VNC NO AUTH REQUIRED" \
            "Direct desktop access without password!" \
            "Connect: vncviewer ${target}:5900"
    fi

    # check brute results
    if grep -qi 'Valid credentials' "${RECONDIR}/vnc-info.txt" 2>/dev/null; then
        notify_critical "VNC PASSWORD FOUND" \
            "$(grep -iP 'Valid|credentials' "${RECONDIR}/vnc-info.txt" | head -3)"
    fi

    # check title leak
    local vnc_title
    vnc_title=$(grep -oP 'Desktop name:\s*\K.*' "${RECONDIR}/vnc-info.txt" 2>/dev/null | head -1) || true
    if [[ -n "$vnc_title" ]]; then
        info "VNC desktop title: ${BOLD}${vnc_title}${RESET}"
    fi
}
