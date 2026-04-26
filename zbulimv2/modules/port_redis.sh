#!/usr/bin/env bash
# port_redis.sh — Port 6379 Redis enumeration

enum_redis() {
    local target="$1"
    progress "Redis (6379)"

    local authed=false

    # nmap info
    info "Running Redis nmap scripts..."
    nmap -p 6379 -Pn --script=redis-info \
        -oN "${RECONDIR}/redis-nmap.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/redis-nmap.txt"

    # try no-auth connection
    if command -v redis-cli &>/dev/null; then
        info "Testing Redis no-auth access..."
        local redis_info
        redis_info=$(timeout 10 redis-cli -h "$target" INFO 2>&1) || true

        if echo "$redis_info" | grep -qP 'redis_version'; then
            authed=true
            local version
            version=$(echo "$redis_info" | grep -oP 'redis_version:\K\S+' | head -1) || true
            echo "$redis_info" > "${RECONDIR}/redis-info.txt"
            fix_owner "${RECONDIR}/redis-info.txt"

            notify_critical "REDIS NO AUTH REQUIRED" \
                "Version: ${version:-unknown}" \
                "Full access without password!"

            # list keys
            info "Dumping Redis keys..."
            local keys_out
            keys_out=$(timeout 10 redis-cli -h "$target" KEYS '*' 2>&1) || true
            echo "$keys_out" > "${RECONDIR}/redis-keys.txt"
            fix_owner "${RECONDIR}/redis-keys.txt"
            rm_if_empty "${RECONDIR}/redis-keys.txt"

            if [[ -s "${RECONDIR}/redis-keys.txt" ]]; then
                local key_count
                key_count=$(wc -l < "${RECONDIR}/redis-keys.txt")
                notify_finding "REDIS KEYS (${key_count})" \
                    "$(head -10 "${RECONDIR}/redis-keys.txt")"
            fi

            # check CONFIG writable
            local config_dir
            config_dir=$(timeout 10 redis-cli -h "$target" CONFIG GET dir 2>&1) || true
            if echo "$config_dir" | grep -qvP 'ERR\|DENIED\|error'; then
                notify_warning "REDIS CONFIG WRITABLE" \
                    "CONFIG GET/SET works — file write attacks possible" \
                    "Potential: SSH key write, webshell, crontab"
            fi
        elif echo "$redis_info" | grep -qiP 'NOAUTH\|Authentication required'; then
            info "Redis: auth required, trying common passwords..."
            for pw in password redis admin; do
                local auth_out
                auth_out=$(timeout 10 redis-cli -h "$target" -a "$pw" INFO 2>&1) || true
                if echo "$auth_out" | grep -qP 'redis_version'; then
                    authed=true
                    notify_critical "REDIS AUTH WITH DEFAULT PASSWORD" \
                        "Password: ${pw}"
                    echo "$auth_out" > "${RECONDIR}/redis-info.txt"
                    fix_owner "${RECONDIR}/redis-info.txt"
                    break
                fi
            done
            if ! $authed; then
                info "Redis: common passwords failed."
            fi
        else
            info "Redis: could not connect."
        fi
    else
        warn "redis-cli not found — only nmap results available."
    fi
}
