#!/usr/bin/env bash
# scan.sh — nmap scanning logic: quick, full TCP, targeted, UDP

run_quick_scan() {
    local target="$1"
    local outdir="$2"

    section "TCP — Quick Scan (top 1000)"
    info "Running quick TCP scan (top 1000 ports)..."

    nmap -Pn --top-ports 1000 --min-rate 5000 -oA "${outdir}/tcp-quick" "$target" \
        > /dev/null 2>&1

    for f in "${outdir}"/tcp-quick.*; do fix_owner "$f" 2>/dev/null || true; done

    local ports
    ports=$(extract_open_ports "${outdir}/tcp-quick.gnmap" tcp)

    if [[ -z "$ports" ]]; then
        warn "No open TCP ports found in quick scan."
    else
        notify_finding "QUICK SCAN — Open TCP Ports" "$ports"
    fi

    echo "$ports"
}

run_full_tcp_scan() {
    local target="$1"
    local outdir="$2"

    info "Launching full TCP scan (all 65535 ports) in background..."
    nmap -p- --min-rate 10000 -Pn -oA "${outdir}/tcp-allports" "$target" \
        > /dev/null 2>&1 &
    local pid=$!
    BACKGROUND_PIDS+=("$pid")
    info "nmap PID ${BOLD}${pid}${RESET} — enumeration starting in parallel..."
    echo "$pid"
}

wait_full_tcp_scan() {
    local pid="$1"
    local outdir="$2"
    local quick_ports="$3"

    section "TCP — Waiting for Full Scan"
    info "Waiting for nmap (PID ${pid}) to finish..."
    wait "$pid" || true

    for f in "${outdir}"/tcp-allports.*; do fix_owner "$f" 2>/dev/null || true; done

    local all_ports
    all_ports=$(extract_open_ports "${outdir}/tcp-allports.gnmap" tcp)

    if [[ -z "$all_ports" ]]; then
        warn "No open TCP ports found in full scan."
        return
    fi

    # Show .nmap file
    if [[ -f "${outdir}/tcp-allports.nmap" ]]; then
        echo
        echo -e "${CYAN}${BOLD}── Full TCP Scan Results (.nmap) ──${RESET}"
        cat "${outdir}/tcp-allports.nmap"
        echo -e "${CYAN}${BOLD}── End of nmap output ──${RESET}"
        echo
    fi

    # Find new ports not in quick scan
    local new_ports=""
    IFS=',' read -ra ALL_ARR <<< "$all_ports"
    IFS=',' read -ra QUICK_ARR <<< "$quick_ports"
    for p in "${ALL_ARR[@]}"; do
        local found=false
        for q in "${QUICK_ARR[@]}"; do
            [[ "$p" == "$q" ]] && found=true && break
        done
        $found || new_ports="${new_ports:+$new_ports,}$p"
    done

    if [[ -n "$new_ports" ]]; then
        notify_finding "NEW PORTS from full scan" "Quick scan had: $quick_ports" "Full scan added: $new_ports"
    fi

    echo "$all_ports"
}

run_targeted_tcp_scan() {
    local target="$1"
    local outdir="$2"
    local ports="$3"

    [[ -z "$ports" ]] && return

    section "TCP — Targeted Version + Script Scan"
    info "Running -sCV on: ${ports}"

    nmap -p "$ports" -sCV -Pn -oA "${outdir}/tcp-targeted" "$target"
    for f in "${outdir}"/tcp-targeted.*; do fix_owner "$f" 2>/dev/null || true; done

    success "TCP targeted scan complete."
}

run_udp_scan() {
    local target="$1"
    local outdir="$2"

    section "UDP — Port Sweep"
    info "Running UDP scan (top 200 ports) in background..."

    nmap -sU --top-ports 200 --min-rate 5000 --open -Pn -oA "${outdir}/udp-allports" "$target" \
        > /dev/null 2>&1 &
    local pid=$!
    BACKGROUND_PIDS+=("$pid")
    info "UDP nmap PID ${BOLD}${pid}${RESET}"
    echo "$pid"
}

wait_udp_scan() {
    local pid="$1"
    local outdir="$2"

    section "UDP — Waiting for Scan"
    info "Waiting for UDP nmap (PID ${pid}) to finish..."
    wait "$pid" || true

    for f in "${outdir}"/udp-allports.*; do fix_owner "$f" 2>/dev/null || true; done

    local ports
    ports=$(extract_open_ports "${outdir}/udp-allports.gnmap" udp)

    if [[ -z "$ports" ]]; then
        warn "No open UDP ports found."
    else
        notify_finding "UDP Ports Open" "$ports"
    fi

    echo "$ports"
}

run_targeted_udp_scan() {
    local target="$1"
    local outdir="$2"
    local ports="$3"

    [[ -z "$ports" ]] && return

    section "UDP — Targeted Version + Script Scan"
    info "Running -sUCV on: ${ports}"

    nmap -p "$ports" -sUCV -Pn -oA "${outdir}/udp-targeted" "$target"
    for f in "${outdir}"/udp-targeted.*; do fix_owner "$f" 2>/dev/null || true; done

    success "UDP targeted scan complete."
}
