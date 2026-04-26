#!/usr/bin/env bash
# port_nfs.sh — Port 111/2049 NFS + RPC enumeration

enum_nfs() {
    local target="$1"
    progress "NFS/RPC (111/2049)"

    # rpcinfo
    if command -v rpcinfo &>/dev/null; then
        info "Enumerating RPC services..."
        rpcinfo -p "$target" > "${RECONDIR}/rpcinfo.txt" 2>&1 || true
        fix_owner "${RECONDIR}/rpcinfo.txt"
        rm_if_empty "${RECONDIR}/rpcinfo.txt"

        if [[ -s "${RECONDIR}/rpcinfo.txt" ]]; then
            local rpc_count
            rpc_count=$(wc -l < "${RECONDIR}/rpcinfo.txt")
            info "RPC: ${rpc_count} services registered"
        fi
    fi

    # showmount
    if command -v showmount &>/dev/null; then
        info "Checking NFS exports..."
        showmount -e "$target" > "${RECONDIR}/nfs-exports.txt" 2>&1 || true
        fix_owner "${RECONDIR}/nfs-exports.txt"
        rm_if_empty "${RECONDIR}/nfs-exports.txt"

        if [[ -s "${RECONDIR}/nfs-exports.txt" ]] && \
           grep -qP '/' "${RECONDIR}/nfs-exports.txt" 2>/dev/null; then

            local exports
            exports=$(grep -P '/' "${RECONDIR}/nfs-exports.txt" | head -10)
            local export_lines=()
            while IFS= read -r line; do
                export_lines+=("$line")
            done <<< "$exports"

            notify_finding "NFS EXPORTS FOUND" \
                "${export_lines[@]}" \
                "" \
                "Mount: mount -t nfs ${target}:<share> /mnt/nfs"

            # check for no_root_squash via nmap
            info "Running NFS nmap scripts..."
            nmap -p 111,2049 -Pn \
                --script=nfs-ls,nfs-showmount,nfs-statfs \
                -oN "${RECONDIR}/nfs-nmap.txt" "$target" > /dev/null 2>&1 || true
            fix_owner "${RECONDIR}/nfs-nmap.txt"

            # save nfs-ls file listing
            if [[ -s "${RECONDIR}/nfs-nmap.txt" ]]; then
                grep -A 100 'nfs-ls' "${RECONDIR}/nfs-nmap.txt" 2>/dev/null > "${RECONDIR}/nfs-files.txt" || true
                rm_if_empty "${RECONDIR}/nfs-files.txt"
                fix_owner "${RECONDIR}/nfs-files.txt"
            fi

            if grep -qi 'no_root_squash\|root_squash.*no' "${RECONDIR}/nfs-nmap.txt" 2>/dev/null; then
                notify_critical "NFS no_root_squash DETECTED" \
                    "Root-level access possible on NFS share!" \
                    "Mount as root and plant SSH key or SUID binary"
            fi
        else
            info "No NFS exports found."
        fi
    else
        warn "showmount not found — install nfs-common."
    fi
}
