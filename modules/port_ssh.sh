#!/usr/bin/env bash
# port_ssh.sh — Port 22 SSH enumeration

enum_ssh() {
    local target="$1"
    progress "SSH (22)"

    # nxc banner grab
    if command -v nxc &>/dev/null; then
        info "Grabbing SSH banner..."
        local ssh_out
        ssh_out=$(timeout 15 nxc ssh "$target" -u '' -p '' 2>&1) || true
        log_verbose "$ssh_out"
        local ssh_stripped
        ssh_stripped=$(echo "$ssh_out" | sed 's/\x1b\[[0-9;]*m//g')
        if echo "$ssh_stripped" | grep -qP 'SSH'; then
            info "SSH: port open"
        fi
    fi

    # nmap for version + auth methods
    info "Running SSH nmap scripts..."
    nmap -p 22 -Pn --script=ssh-auth-methods,ssh2-enum-algos \
        -sV -oN "${RECONDIR}/ssh-info.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/ssh-info.txt"

    # extract version
    local ssh_version
    ssh_version=$(grep -oP 'OpenSSH[_ ]\K[0-9.p]+' "${RECONDIR}/ssh-info.txt" 2>/dev/null | head -1) || true

    if [[ -n "$ssh_version" ]]; then
        info "SSH version: ${BOLD}OpenSSH ${ssh_version}${RESET}"

        # flag known vulnerable versions
        local major minor
        major=$(echo "$ssh_version" | cut -d. -f1)
        minor=$(echo "$ssh_version" | cut -d. -f2 | sed 's/p.*//')

        if [[ "$major" -lt 7 ]] || { [[ "$major" -eq 7 ]] && [[ "$minor" -lt 7 ]]; }; then
            notify_warning "SSH VULNERABLE VERSION" \
                "OpenSSH ${ssh_version} < 7.7" \
                "CVE-2018-15473: Username enumeration" \
                "Tool: ssh-user-enum or auxiliary/scanner/ssh/ssh_enumusers"
        fi
    fi

    # extract auth methods
    local auth_methods
    auth_methods=$(grep -oP 'Supported authentication methods:.*' "${RECONDIR}/ssh-info.txt" 2>/dev/null | head -1) || true
    if [[ -n "$auth_methods" ]]; then
        info "SSH: $auth_methods"
        if ! echo "$auth_methods" | grep -qi 'password'; then
            info "SSH: password auth disabled — brute force won't work"
        fi
    fi
}
