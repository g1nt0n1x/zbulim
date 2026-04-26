#!/usr/bin/env bash
# port_mongodb.sh — Port 27017 MongoDB enumeration

enum_mongodb() {
    local target="$1"
    progress "MongoDB (27017)"

    # nmap scripts
    info "Running MongoDB nmap scripts..."
    nmap -p 27017 -Pn --script=mongodb-info,mongodb-databases \
        -oN "${RECONDIR}/mongodb-nmap.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/mongodb-nmap.txt"

    # check if databases were listed (no auth)
    if grep -qP 'databases' "${RECONDIR}/mongodb-nmap.txt" 2>/dev/null; then
        local db_list
        db_list=$(grep -oP 'name\s*=\s*\K\S+' "${RECONDIR}/mongodb-nmap.txt" 2>/dev/null | head -10 | tr '\n' ', ' | sed 's/,$//') || true

        if [[ -n "$db_list" ]]; then
            notify_critical "MONGODB NO AUTH — DATABASES ACCESSIBLE" \
                "Databases: ${db_list}" \
                "Saved to: ${RECONDIR}/mongodb-nmap.txt"
        fi
    fi

    # try mongosh if available
    if command -v mongosh &>/dev/null; then
        info "Testing MongoDB with mongosh..."
        local mongo_out
        mongo_out=$(timeout 15 mongosh --host "$target" --quiet \
            --eval 'JSON.stringify(db.adminCommand({listDatabases:1}))' 2>&1) || true
        log_verbose "$mongo_out"

        if echo "$mongo_out" | grep -qP '"databases"'; then
            echo "$mongo_out" > "${RECONDIR}/mongodb-databases.txt"
            fix_owner "${RECONDIR}/mongodb-databases.txt"

            notify_critical "MONGODB NO AUTH (mongosh confirmed)" \
                "Full database access without credentials" \
                "Saved to: ${RECONDIR}/mongodb-databases.txt"
        fi
    fi
}
