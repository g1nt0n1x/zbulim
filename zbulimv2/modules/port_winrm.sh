#!/usr/bin/env bash
# port_winrm.sh — Port 5985/5986 WinRM enumeration

enum_winrm() {
    local target="$1"
    progress "WinRM (5985/5986)"

    if ! command -v nxc &>/dev/null; then
        warn "nxc not found — skipping WinRM check."
        return
    fi

    local NXC_LOCAL_FLAG=""
    $LOCAL_AUTH && NXC_LOCAL_FLAG="--local-auth"

    info "Checking WinRM..."
    local winrm_out
    winrm_out=$(nxc winrm "$target" -u '' -p '' $NXC_LOCAL_FLAG 2>&1) || true
    log_verbose "$winrm_out"
    local winrm_stripped
    winrm_stripped=$(echo "$winrm_out" | sed 's/\x1b\[[0-9;]*m//g')

    if echo "$winrm_stripped" | grep -qP '\[\+\]'; then
        notify_warning "WINRM ACCESSIBLE" \
            "WinRM anonymous access!"
    elif echo "$winrm_stripped" | grep -qP 'WINRM|HTTP'; then
        info "WinRM: port open, auth required"
    else
        info "WinRM: not available."
    fi
}
