#!/usr/bin/env bash
# port_mysql.sh — Port 3306 MySQL enumeration

enum_mysql() {
    local target="$1"
    progress "MySQL (3306)"

    # nmap scripts
    info "Running MySQL nmap scripts..."
    nmap -p 3306 -Pn \
        --script=mysql-info,mysql-enum,mysql-empty-password \
        -oN "${RECONDIR}/mysql-nmap.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/mysql-nmap.txt"

    if grep -qi 'empty password' "${RECONDIR}/mysql-nmap.txt" 2>/dev/null; then
        notify_critical "MYSQL EMPTY ROOT PASSWORD" \
            "nmap detected empty password for root"
    fi

    # nxc default cred checks
    if command -v nxc &>/dev/null; then
        local creds=("root:" "root:root" "root:toor" "mysql:mysql")
        for cred in "${creds[@]}"; do
            local u p
            u=$(echo "$cred" | cut -d: -f1)
            p=$(echo "$cred" | cut -d: -f2)

            info "MySQL: testing ${u}:${p:-<empty>}..."
            local out
            out=$(nxc mysql "$target" -u "$u" -p "$p" 2>&1) || true
            log_verbose "$out"

            if echo "$out" | grep -qP '\[\+\]'; then
                notify_critical "MYSQL AUTH SUCCESS" \
                    "Credentials: ${u}:${p:-<empty>}"
                echo "user=${u}" > "${RECONDIR}/mysql-info.txt"
                echo "pass=${p}" >> "${RECONDIR}/mysql-info.txt"
                fix_owner "${RECONDIR}/mysql-info.txt"
                break
            fi
        done
    fi
}
