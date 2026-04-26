#!/usr/bin/env bash
# port_postgresql.sh — Port 5432 PostgreSQL enumeration

enum_postgresql() {
    local target="$1"
    progress "PostgreSQL (5432)"

    # nmap scripts
    info "Running PostgreSQL nmap scripts..."
    nmap -p 5432 -Pn --script=pgsql-brute \
        -oN "${RECONDIR}/postgresql-nmap.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/postgresql-nmap.txt"

    if grep -qi 'Valid credentials' "${RECONDIR}/postgresql-nmap.txt" 2>/dev/null; then
        notify_critical "POSTGRESQL CREDS FOUND (nmap brute)" \
            "$(grep -iP 'Valid credentials' "${RECONDIR}/postgresql-nmap.txt" | head -3)"
    fi

    # default cred checks via nxc or psql
    local authed=false
    local pg_user="" pg_pass=""

    if command -v nxc &>/dev/null; then
        local creds=("postgres:postgres" "postgres:" "admin:admin")
        for cred in "${creds[@]}"; do
            local u p
            u=$(echo "$cred" | cut -d: -f1)
            p=$(echo "$cred" | cut -d: -f2)

            info "PostgreSQL: testing ${u}:${p:-<empty>}..."
            local out
            out=$(nxc postgres "$target" -u "$u" -p "$p" 2>&1) || true
            log_verbose "$out"

            if echo "$out" | grep -qP '\[\+\]'; then
                authed=true
                pg_user="$u"
                pg_pass="$p"
                notify_critical "POSTGRESQL AUTH SUCCESS" \
                    "Credentials: ${u}:${p:-<empty>}"
                break
            fi
        done
    fi

    if $authed; then
        echo "user=${pg_user}" > "${RECONDIR}/postgresql-info.txt"
        echo "pass=${pg_pass}" >> "${RECONDIR}/postgresql-info.txt"
        fix_owner "${RECONDIR}/postgresql-info.txt"
    fi
}
