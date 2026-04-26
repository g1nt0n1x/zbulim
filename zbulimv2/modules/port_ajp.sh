#!/usr/bin/env bash
# port_ajp.sh — Port 8009 AJP/Tomcat enumeration

enum_ajp() {
    local target="$1"
    progress "AJP (8009)"

    # nmap scripts
    info "Running AJP nmap scripts..."
    nmap -p 8009 -Pn -sV --script=ajp-methods,ajp-request \
        -oN "${RECONDIR}/ajp-info.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/ajp-info.txt"

    # check Ghostcat vulnerability based on Tomcat version
    local tomcat_version
    tomcat_version=$(grep -oP 'Apache Tomcat[/ ]\K[0-9.]+' "${RECONDIR}/ajp-info.txt" 2>/dev/null | head -1) || true

    if [[ -n "$tomcat_version" ]]; then
        info "Tomcat version: ${BOLD}${tomcat_version}${RESET}"

        local major minor patch
        major=$(echo "$tomcat_version" | cut -d. -f1)
        minor=$(echo "$tomcat_version" | cut -d. -f2)
        patch=$(echo "$tomcat_version" | cut -d. -f3)

        local ghostcat=false
        if [[ "$major" -lt 7 ]]; then
            ghostcat=true
        elif [[ "$major" -eq 7 && "$minor" -eq 0 && "${patch:-0}" -lt 100 ]]; then
            ghostcat=true
        elif [[ "$major" -eq 8 && "$minor" -eq 5 && "${patch:-0}" -lt 51 ]]; then
            ghostcat=true
        elif [[ "$major" -eq 9 && "$minor" -eq 0 && "${patch:-0}" -lt 31 ]]; then
            ghostcat=true
        fi

        if $ghostcat; then
            notify_critical "GHOSTCAT VULNERABLE (CVE-2020-1938)" \
                "Tomcat ${tomcat_version} is vulnerable" \
                "AJP connector allows file read/include" \
                "Tool: ajpShooter.py or exploit/multi/http/tomcat_ghostcat"
        fi
    fi

    # check methods
    if grep -qi 'PUT\|DELETE' "${RECONDIR}/ajp-info.txt" 2>/dev/null; then
        notify_warning "AJP DANGEROUS METHODS" \
            "PUT/DELETE methods available via AJP"
    fi
}
