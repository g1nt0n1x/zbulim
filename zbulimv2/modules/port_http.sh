#!/usr/bin/env bash
# port_http.sh — Port 80/443/8080/8443 HTTP(S) enumeration
# Domain detection, /etc/hosts, vhost discovery, directory enumeration per vhost

detect_domain() {
    local target="$1"
    local outdir="$2"

    [[ -n "${DOMAIN:-}" ]] && return

    # 1. nmap redirect
    for nmap_file in "${outdir}/tcp-targeted.nmap" "${outdir}/tcp-quick.nmap" "${outdir}/tcp-allports.nmap"; do
        if [[ -f "$nmap_file" ]]; then
            local dom
            dom=$(grep -oP '(?:redirect to|Requested resource was) https?://\K[^/:\s]+' "$nmap_file" 2>/dev/null | \
                grep -v "^${target}$" | head -1) || true
            if [[ -n "$dom" ]]; then
                DOMAIN="$dom"
                return
            fi
        fi
    done

    # 2. SSL cert CN/SAN
    for nmap_file in "${outdir}/tcp-targeted.nmap" "${outdir}/tcp-quick.nmap"; do
        if [[ -f "$nmap_file" ]]; then
            local dom
            dom=$(grep -oP 'commonName=\K[^\s/]+' "$nmap_file" 2>/dev/null | \
                grep -vP '^\*\.' | grep -v "^${target}$" | head -1) || true
            if [[ -n "$dom" ]]; then
                DOMAIN="$dom"
                return
            fi
            dom=$(grep -oP 'DNS:\K[^\s,]+' "$nmap_file" 2>/dev/null | \
                grep -vP '^\*\.' | grep -v "^${target}$" | head -1) || true
            if [[ -n "$dom" ]]; then
                DOMAIN="$dom"
                return
            fi
        fi
    done

    # 3. whatweb redirect
    for ww_file in "${RECONDIR}"/whatweb-*.txt; do
        [[ -f "$ww_file" ]] || continue
        local dom
        dom=$(grep -oP 'RedirectLocation\[https?://\K[^/\]]+' "$ww_file" 2>/dev/null | \
            grep -v "^${target}$" | head -1) || true
        if [[ -n "$dom" ]]; then
            DOMAIN="$dom"
            return
        fi
    done
}

enum_http() {
    local target="$1"
    local outdir="$2"

    local web_ports=()
    for p in 80 443 8080 8443; do
        port_open "$p" && web_ports+=("$p")
    done

    [[ ${#web_ports[@]} -eq 0 ]] && return

    progress "HTTP (${web_ports[*]})"

    # detect best tools
    local dir_brute=""
    command -v feroxbuster &>/dev/null && dir_brute="feroxbuster"
    [[ -z "$dir_brute" ]] && command -v gobuster &>/dev/null && dir_brute="gobuster"

    local dir_wordlist=""
    for wl in \
        /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
        /usr/share/seclists/Discovery/Web-Content/common.txt \
        /usr/share/wordlists/dirb/common.txt \
        /usr/share/dirb/wordlists/common.txt; do
        [[ -f "$wl" ]] && dir_wordlist="$wl" && break
    done
    [[ -n "${ZBULIM_WL_DIRS:-}" && -f "${ZBULIM_WL_DIRS}" ]] && dir_wordlist="$ZBULIM_WL_DIRS"

    local vhost_wordlist=""
    for wl in \
        /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt; do
        [[ -f "$wl" ]] && vhost_wordlist="$wl" && break
    done
    [[ -n "${ZBULIM_WL_VHOSTS:-}" && -f "${ZBULIM_WL_VHOSTS}" ]] && vhost_wordlist="$ZBULIM_WL_VHOSTS"

    for port in "${web_ports[@]}"; do
        local scheme="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
        local url="${scheme}://${target}:${port}"

        section "Web Recon — ${url}"

        # Step 1: whatweb fingerprint
        if command -v whatweb &>/dev/null; then
            info "whatweb ${url}..."
            whatweb --no-errors -a 3 "$url" 2>/dev/null | \
                tee "${RECONDIR}/whatweb-${port}.txt" || true
            fix_owner "${RECONDIR}/whatweb-${port}.txt"
            rm_if_empty "${RECONDIR}/whatweb-${port}.txt"
        fi

        # Step 2: detect domain
        detect_domain "$target" "$outdir"

        if [[ -n "${DOMAIN:-}" ]]; then
            notify_finding "DOMAIN DETECTED" \
                "${target} → ${DOMAIN}" \
                "Source: nmap redirect / SSL cert / whatweb"

            # Step 3: update /etc/hosts
            add_to_hosts "$target" "$DOMAIN"

            local domain_url="${scheme}://${DOMAIN}"
            [[ "$port" != "80" && "$port" != "443" ]] && domain_url="${scheme}://${DOMAIN}:${port}"

            # Step 4: directory enumeration on main domain
            _run_dir_enum "$domain_url" "$port" "$dir_brute" "$dir_wordlist" "$scheme" "${RECONDIR}/ferox-${DOMAIN}-${port}.txt"

            # Step 5: vhost enumeration
            if [[ -n "$vhost_wordlist" ]] && command -v ffuf &>/dev/null; then
                info "Vhost enumeration on ${DOMAIN}..."

                local ffuf_target="${scheme}://${DOMAIN}"
                [[ "$port" != "80" && "$port" != "443" ]] && ffuf_target="${scheme}://${DOMAIN}:${port}"

                ffuf -u "$ffuf_target" -H "Host: FUZZ.${DOMAIN}" \
                    -w "$vhost_wordlist" -ac \
                    -o "${RECONDIR}/vhosts-${port}.json" -of json \
                    -t 50 2>&1 | log_verbose || true
                fix_owner "${RECONDIR}/vhosts-${port}.json"

                # parse vhosts from ffuf JSON
                local vhosts=()
                if [[ -s "${RECONDIR}/vhosts-${port}.json" ]]; then
                    while IFS= read -r vhost; do
                        [[ -n "$vhost" ]] && vhosts+=("${vhost}.${DOMAIN}")
                    done < <(grep -oP '"input":\{"FUZZ":"([^"]+)"\}' "${RECONDIR}/vhosts-${port}.json" | \
                        grep -oP 'FUZZ":"([^"]+)' | sed 's/FUZZ":"//' | sort -u 2>/dev/null || true)
                fi

                # also try parsing with different json structure
                if [[ ${#vhosts[@]} -eq 0 && -s "${RECONDIR}/vhosts-${port}.json" ]]; then
                    while IFS= read -r vhost; do
                        [[ -n "$vhost" ]] && vhosts+=("${vhost}.${DOMAIN}")
                    done < <(grep -oP '"host":\s*"([^"]+)"' "${RECONDIR}/vhosts-${port}.json" | \
                        grep -oP '"host":\s*"\K[^"]+' | grep -v "^${DOMAIN}$" | sort -u 2>/dev/null || true)
                fi

                if [[ ${#vhosts[@]} -gt 0 ]]; then
                    # save vhosts list
                    printf '%s\n' "${vhosts[@]}" > "${RECONDIR}/vhosts.txt"
                    fix_owner "${RECONDIR}/vhosts.txt"

                    local vhost_list
                    vhost_list=$(printf '%s\n' "${vhosts[@]}" | tr '\n' ', ' | sed 's/,$//')

                    notify_finding "VHOSTS DISCOVERED" \
                        "$vhost_list" \
                        "Adding to /etc/hosts..."

                    # Step 6: add vhosts to /etc/hosts
                    local all_vhosts
                    all_vhosts=$(printf '%s ' "${vhosts[@]}")
                    add_to_hosts "$target" "$all_vhosts"

                    # Step 7: directory enum per vhost
                    for vhost in "${vhosts[@]}"; do
                        local vhost_url="${scheme}://${vhost}"
                        [[ "$port" != "80" && "$port" != "443" ]] && vhost_url="${scheme}://${vhost}:${port}"

                        info "Directory enum on vhost: ${BOLD}${vhost}${RESET}"
                        _run_dir_enum "$vhost_url" "$port" "$dir_brute" "$dir_wordlist" "$scheme" "${RECONDIR}/ferox-${vhost}.txt"
                    done
                else
                    info "No vhosts discovered via ffuf."
                fi
            elif ! command -v ffuf &>/dev/null; then
                warn "ffuf not found — skipping vhost enumeration."
            elif [[ -z "$vhost_wordlist" ]]; then
                warn "No vhost wordlist found — install seclists."
            fi
        else
            # no domain — dir enum on IP
            warn "No domain detected — running dir enum on IP only. No vhost enum possible."
            _run_dir_enum "$url" "$port" "$dir_brute" "$dir_wordlist" "$scheme" "${RECONDIR}/ferox-${port}.txt"
        fi
    done
}

_run_dir_enum() {
    local url="$1"
    local port="$2"
    local tool="$3"
    local wordlist="$4"
    local scheme="$5"
    local outfile="$6"

    case "$tool" in
        feroxbuster)
            info "  feroxbuster ${url}..."
            local extra_flags=""
            [[ "$scheme" == "https" ]] && extra_flags="-k"
            feroxbuster -u "$url" --silent \
                -o "$outfile" \
                --no-state -t 50 $extra_flags 2>&1 | log_verbose || true
            fix_owner "$outfile"
            rm_if_empty "$outfile"
            if [[ -s "$outfile" ]]; then
                local dir_count
                dir_count=$(wc -l < "$outfile")
                success "  feroxbuster: ${BOLD}${dir_count}${RESET} path(s) — ${outfile}"
                # show top interesting results (non-403)
                local interesting
                interesting=$(grep -vP '^\s*403\s' "$outfile" 2>/dev/null | head -10) || true
                if [[ -n "$interesting" ]]; then
                    notify_finding "DIRECTORIES: ${url}" \
                        "$(echo "$interesting" | head -10)"
                fi
            fi
            ;;
        gobuster)
            if [[ -n "$wordlist" ]]; then
                info "  gobuster ${url}..."
                local extra_flags=""
                [[ "$scheme" == "https" ]] && extra_flags="-k"
                gobuster dir -u "$url" -w "$wordlist" -q \
                    -o "$outfile" $extra_flags 2>&1 | log_verbose || true
                fix_owner "$outfile"
                rm_if_empty "$outfile"
                if [[ -s "$outfile" ]]; then
                    local dir_count
                    dir_count=$(wc -l < "$outfile")
                    success "  gobuster: ${BOLD}${dir_count}${RESET} path(s) — ${outfile}"
                fi
            else
                warn "  No wordlist found for gobuster."
            fi
            ;;
        *)
            warn "  No dir-brute tool found (feroxbuster/gobuster)."
            ;;
    esac
}
