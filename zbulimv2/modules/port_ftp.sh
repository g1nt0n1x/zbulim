#!/usr/bin/env bash
# port_ftp.sh — Port 21 FTP enumeration

enum_ftp() {
    local target="$1"
    progress "FTP (21)"

    local anon_access=false

    # nxc anonymous check
    if command -v nxc &>/dev/null; then
        info "Testing FTP anonymous login..."
        local ftp_out
        ftp_out=$(nxc ftp "$target" -u 'anonymous' -p '' 2>&1) || true
        log_verbose "$ftp_out"
        nxc_result "$ftp_out"

        if echo "$ftp_out" | grep -qP '\[\+\]'; then
            anon_access=true
        fi
    fi

    # nmap scripts
    info "Running FTP nmap scripts..."
    nmap -p 21 -Pn --script=ftp-anon,ftp-syst,ftp-vsftpd-backdoor,ftp-bounce \
        -oN "${RECONDIR}/ftp-nmap.txt" "$target" > /dev/null 2>&1 || true
    fix_owner "${RECONDIR}/ftp-nmap.txt"

    if grep -qi 'Anonymous FTP login allowed' "${RECONDIR}/ftp-nmap.txt" 2>/dev/null; then
        anon_access=true
    fi

    # check vsftpd backdoor
    if grep -qi 'VULNERABLE' "${RECONDIR}/ftp-nmap.txt" 2>/dev/null; then
        notify_critical "FTP BACKDOOR DETECTED" \
            "vsftpd 2.3.4 backdoor vulnerability found!" \
            "See: ${RECONDIR}/ftp-nmap.txt"
    fi

    if $anon_access; then
        notify_warning "FTP ANONYMOUS ACCESS" \
            "Anonymous login is allowed" \
            "Listing files and downloading..."

        # list files recursively and download
        mkdir -p "${LOOTDIR}/ftp"
        info "Downloading FTP files to ${LOOTDIR}/ftp/ ..."

        # use wget for recursive download
        if command -v wget &>/dev/null; then
            wget -q -r -nH --no-parent --reject="index.html*" \
                "ftp://anonymous:@${target}/" \
                -P "${LOOTDIR}/ftp/" 2>&1 | log_verbose || true
        fi
        chown -R "$REAL_USER:$REAL_GROUP" "${LOOTDIR}/ftp" 2>/dev/null || true

        # list what we got
        local ftp_file_count
        ftp_file_count=$(find "${LOOTDIR}/ftp" -type f 2>/dev/null | wc -l || echo 0)

        if [[ "$ftp_file_count" -gt 0 ]]; then
            # save file listing
            find "${LOOTDIR}/ftp" -type f -printf '%P\n' > "${RECONDIR}/ftp-files.txt" 2>/dev/null || true
            fix_owner "${RECONDIR}/ftp-files.txt"

            local file_lines=()
            while IFS= read -r f; do
                file_lines+=("  $f")
            done < <(head -20 "${RECONDIR}/ftp-files.txt")

            notify_finding "FTP FILES DOWNLOADED (${ftp_file_count} files)" \
                "Saved to: ${LOOTDIR}/ftp/" \
                "${file_lines[@]}"
        else
            info "Anonymous access confirmed but no files found."
            rmdir "${LOOTDIR}/ftp" 2>/dev/null || true
        fi

        # check writable
        info "Testing FTP write access..."
        local write_test
        write_test=$(echo -e "user anonymous\npass \nmkdir .zbulim_write_test\nrmdir .zbulim_write_test\nquit" | \
            ftp -n "$target" 2>&1) || true
        if echo "$write_test" | grep -qi '257\|directory.*created'; then
            notify_warning "FTP WRITABLE DIRECTORY" \
                "Anonymous user can upload files!"
        fi
    else
        info "FTP: anonymous access denied."
    fi
}
