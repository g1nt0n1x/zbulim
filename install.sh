#!/usr/bin/env bash
set -e

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo ./install.sh"
    exit 1
fi

echo "[*] Installing zbulim dependencies..."

apt-get update
apt-get install -y \
    nmap \
    netexec \
    seclists \
    feroxbuster \
    ffuf \
    whatweb \
    gobuster \
    dnsrecon \
    snmp \
    snmp-mibs-downloader \
    onesixtyone \
    nfs-common \
    ntpdate \
    nikto \
    smtp-user-enum \
    redis-tools \
    python3-impacket

# optional: mongosh (may not be in default repos)
apt-get install -y mongosh 2>/dev/null || echo "[!] mongosh not in repos — skip (MongoDB enum will use nmap only)"

# download SNMP MIBs for human-readable snmpwalk output
download-mibs 2>/dev/null || true
sed -i 's/^mibs :$/# mibs :/' /etc/snmp/snmp.conf 2>/dev/null || true

# kerbrute (not in apt)
if ! command -v kerbrute &>/dev/null; then
    echo "[*] Installing kerbrute..."
    KERB_URL="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64"
    curl -sL "$KERB_URL" -o /usr/local/bin/kerbrute
    chmod +x /usr/local/bin/kerbrute
fi

# install zbulim
DEST="/usr/local/bin/zbulim"
cp zbulim "$DEST"
chmod +x "$DEST"

# install modules
MODDIR="/usr/local/share/zbulim/modules"
mkdir -p "$MODDIR"
cp modules/*.sh "$MODDIR/"

echo "[+] zbulim installed → $DEST"
echo "[+] Modules → $MODDIR"
echo "[+] Run: sudo zbulim <target>"
