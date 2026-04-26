#!/usr/bin/env bash
# summary.sh — consolidated findings report

print_summary() {
    local target="$1"

    echo
    echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}${BOLD}║                   ZBULIM — SCAN SUMMARY                   ║${RESET}"
    echo -e "${GREEN}${BOLD}╠═══════════════════════════════════════════════════════════╣${RESET}"

    printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Target    : ${target}"
    [[ -n "${HOSTNAME:-}" ]] && \
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Hostname  : ${HOSTNAME}"
    [[ -n "${DOMAIN:-}" ]] && \
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Domain    : ${DOMAIN}"
    [[ -n "${TCP_PORTS:-}" ]] && \
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "TCP Ports : ${TCP_PORTS}"
    [[ -n "${UDP_PORTS:-}" ]] && \
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "UDP Ports : ${UDP_PORTS}"

    # HTTP section
    if [[ -s "${RECONDIR}/vhosts.txt" ]] || ls "${RECONDIR}"/ferox-*.txt &>/dev/null 2>&1; then
        echo -e "${GREEN}${BOLD}║${RESET}                                                         ${GREEN}${BOLD}║${RESET}"
        printf "${GREEN}${BOLD}║${RESET}  ${BOLD}%-53s${RESET} ${GREEN}${BOLD}║${RESET}\n" "── HTTP ──"
        [[ -n "${DOMAIN:-}" ]] && \
            printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Domain    : ${DOMAIN}"
        if [[ -s "${RECONDIR}/vhosts.txt" ]]; then
            local vhosts
            vhosts=$(tr '\n' ', ' < "${RECONDIR}/vhosts.txt" | sed 's/,$//')
            printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Vhosts    : ${vhosts}"
        fi
        for ferox_file in "${RECONDIR}"/ferox-*.txt; do
            [[ -f "$ferox_file" ]] || continue
            local fname count
            fname=$(basename "$ferox_file")
            count=$(wc -l < "$ferox_file")
            printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Dirs (${fname}) : ${count} paths"
        done
    fi

    # SMB section
    if $NULL_AUTH || $GUEST_AUTH || [[ -s "${RECONDIR}/signing-off.txt" ]]; then
        echo -e "${GREEN}${BOLD}║${RESET}                                                         ${GREEN}${BOLD}║${RESET}"
        printf "${GREEN}${BOLD}║${RESET}  ${BOLD}%-53s${RESET} ${GREEN}${BOLD}║${RESET}\n" "── SMB ──"
        $NULL_AUTH  && printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Auth      : null session"
        $GUEST_AUTH && printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Auth      : guest login"
        [[ -s "${RECONDIR}/signing-off.txt" ]] && \
            printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Signing   : NOT REQUIRED (relay possible)"
        if [[ -d "${LOOTDIR}" ]]; then
            local loot_count
            loot_count=$(find "${LOOTDIR}" -type f ! -name 'spider_plus.json' 2>/dev/null | wc -l || echo 0)
            printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Loot      : ${loot_count} files → ${LOOTDIR}/"
        fi
    fi

    # SNMP section
    if [[ -s "${RECONDIR}/snmp-community.txt" ]]; then
        echo -e "${GREEN}${BOLD}║${RESET}                                                         ${GREEN}${BOLD}║${RESET}"
        printf "${GREEN}${BOLD}║${RESET}  ${BOLD}%-53s${RESET} ${GREEN}${BOLD}║${RESET}\n" "── SNMP ──"
        local snmp_comm
        snmp_comm=$(cat "${RECONDIR}/snmp-community.txt")
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Community : ${snmp_comm}"
        if [[ -s "${RECONDIR}/snmp-users.txt" ]]; then
            local snmp_users
            snmp_users=$(head -5 "${RECONDIR}/snmp-users.txt" | tr '\n' ', ' | sed 's/,$//')
            printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Users     : ${snmp_users}"
        fi
    fi

    # DNS section
    if [[ -s "${RECONDIR}/dns-axfr.txt" ]]; then
        echo -e "${GREEN}${BOLD}║${RESET}                                                         ${GREEN}${BOLD}║${RESET}"
        printf "${GREEN}${BOLD}║${RESET}  ${BOLD}%-53s${RESET} ${GREEN}${BOLD}║${RESET}\n" "── DNS ──"
        local axfr_count
        axfr_count=$(grep -cP '\bIN\b' "${RECONDIR}/dns-axfr.txt" || echo 0)
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Zone Xfer : SUCCESS (${axfr_count} records)"
    fi

    # NFS section
    if [[ -s "${RECONDIR}/nfs-exports.txt" ]]; then
        echo -e "${GREEN}${BOLD}║${RESET}                                                         ${GREEN}${BOLD}║${RESET}"
        printf "${GREEN}${BOLD}║${RESET}  ${BOLD}%-53s${RESET} ${GREEN}${BOLD}║${RESET}\n" "── NFS ──"
        local exports
        exports=$(grep -P '/' "${RECONDIR}/nfs-exports.txt" | head -3 | tr '\n' ', ' | sed 's/,$//')
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Exports   : ${exports}"
    fi

    # Redis section
    if [[ -s "${RECONDIR}/redis-info.txt" ]]; then
        echo -e "${GREEN}${BOLD}║${RESET}                                                         ${GREEN}${BOLD}║${RESET}"
        printf "${GREEN}${BOLD}║${RESET}  ${BOLD}%-53s${RESET} ${GREEN}${BOLD}║${RESET}\n" "── Redis ──"
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Auth      : NO PASSWORD"
    fi

    # Users section
    if [[ -s "${RECONDIR}/users.txt" ]]; then
        echo -e "${GREEN}${BOLD}║${RESET}                                                         ${GREEN}${BOLD}║${RESET}"
        printf "${GREEN}${BOLD}║${RESET}  ${BOLD}%-53s${RESET} ${GREEN}${BOLD}║${RESET}\n" "── Users ──"
        local total_users
        total_users=$(wc -l < "${RECONDIR}/users.txt")
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "${total_users} unique → ${RECONDIR}/users.txt"
    fi

    # Hashes section
    if [[ -s "${RECONDIR}/asreproast.txt" ]] || [[ -s "${RECONDIR}/kerberoast.txt" ]]; then
        echo -e "${GREEN}${BOLD}║${RESET}                                                         ${GREEN}${BOLD}║${RESET}"
        printf "${GREEN}${BOLD}║${RESET}  ${BOLD}%-53s${RESET} ${GREEN}${BOLD}║${RESET}\n" "── Hashes ──"
        [[ -s "${RECONDIR}/asreproast.txt" ]] && \
            printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" \
                "AS-REP  : $(grep -c 'krb5asrep' "${RECONDIR}/asreproast.txt" 2>/dev/null || echo 0) hash(es)"
        [[ -s "${RECONDIR}/kerberoast.txt" ]] && \
            printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" \
                "Kerberos: $(grep -c 'krb5tgs' "${RECONDIR}/kerberoast.txt" 2>/dev/null || echo 0) hash(es)"
    fi

    # Password policy
    if [[ "${LOCKOUT_THRESHOLD:-?}" != "?" ]]; then
        echo -e "${GREEN}${BOLD}║${RESET}                                                         ${GREEN}${BOLD}║${RESET}"
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" \
            "Lockout: ${LOCKOUT_THRESHOLD} | MinLen: ${MIN_PW_LEN:-?} | Complex: ${PW_COMPLEX:-?}"
    fi

    # Files section
    echo -e "${GREEN}${BOLD}║${RESET}                                                         ${GREEN}${BOLD}║${RESET}"
    printf "${GREEN}${BOLD}║${RESET}  ${BOLD}%-53s${RESET} ${GREEN}${BOLD}║${RESET}\n" "── Files ──"

    for f in \
        "${RECONDIR}/users.txt" \
        "${RECONDIR}/shares-null.txt" \
        "${RECONDIR}/shares-guest.txt" \
        "${RECONDIR}/signing-off.txt" \
        "${RECONDIR}/asreproast.txt" \
        "${RECONDIR}/kerberoast.txt" \
        "${RECONDIR}/vhosts.txt" \
        "${RECONDIR}/dns-axfr.txt" \
        "${RECONDIR}/snmpwalk.txt" \
        "${RECONDIR}/snmp-users.txt" \
        "${RECONDIR}/nfs-exports.txt" \
        "${RECONDIR}/redis-info.txt" \
        "${RECONDIR}/redis-keys.txt" \
        "${RECONDIR}/ftp-files.txt"; do
        if [[ -s "$f" ]]; then
            local lines
            lines=$(wc -l < "$f")
            printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "$(basename "$f") (${lines} lines)"
        fi
    done

    for ferox_file in "${RECONDIR}"/ferox-*.txt; do
        if [[ -s "$ferox_file" ]]; then
            local lines
            lines=$(wc -l < "$ferox_file")
            printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "$(basename "$ferox_file") (${lines} lines)"
        fi
    done

    [[ -d "${LOOTDIR}" ]] && \
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "${LOOTDIR}/ (downloaded files)"
    printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "${OUTDIR}/ (nmap scans)"
    [[ -n "${LOGFILE:-}" ]] && \
        printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "$(basename "${LOGFILE}") (full log)"

    echo -e "${GREEN}${BOLD}║${RESET}                                                         ${GREEN}${BOLD}║${RESET}"
    printf "${GREEN}${BOLD}║${RESET}  %-55s ${GREEN}${BOLD}║${RESET}\n" "Elapsed: $(elapsed)"
    echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════╝${RESET}"
}
