# zbulim

> *zbulim* (Albanian) - reconnaissance, discovery

Automated AD / Windows recon tool for OSCP and CTF engagements. Runs `nxc` across multiple protocols and `nmap` in a single command, producing a clean `recon/` folder with deduplicated results and a summary of key findings.

```
TCP scan     →  full port discovery (gates all subsequent checks)
SMB enum     →  host discovery, /etc/hosts, null/guest auth, signing, shares, users
Spider+      →  auto-download accessible share files to ./loot/
RID brute    →  user enumeration via RID cycling (SMB + MSSQL)
LDAP enum    →  ASREPRoast, Kerberoast, delegation, PASSWD_NOTREQD, adminCount
Multi-proto  →  test null/guest on RDP, WinRM, MSSQL, FTP, SSH (port-gated)
Password spray → username-as-password against SMB (interactive confirmation)
TCP targeted →  -sCV --version-intensity 9 on open ports
UDP sweep    →  top-1000 scan → targeted -sUCV on open ports
Summary      →  key findings at a glance + optional spray re-prompt
```

## Usage

```bash
zbulim <target> [target2 ...] [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `target` | One or more IP addresses or hostnames | required |
| `-o, --output DIR` | Base directory for nmap results | `./nmap` |
| `--skip-nmap` | Skip all nmap scans (re-runs, nxc-only recon) | off |
| `--skip-clock` | Skip clock sync via ntpdate | off |
| `-h, --help` | Show help | |

### Examples

```bash
zbulim 10.10.10.1                        # single target (flat dirs)
zbulim 10.10.10.1 10.10.10.2 10.10.10.3  # multi-target (per-IP subdirs)
zbulim 10.10.10.1 --skip-nmap            # nxc recon only, no nmap
zbulim 10.10.10.1 -o ./scans
sudo zbulim 10.10.10.1                   # enables UDP scans
```

## Phases

| # | Phase | What it does |
|---|-------|-------------|
| 1 | **TCP Port Discovery** | Full port scan (`-p- --min-rate 10000 -Pn`) — results gate all subsequent protocol checks |
| 2 | **SMB Enum** | Host discovery via `nxc smb`, auto-update `/etc/hosts`, null/guest auth, SMB signing, password policy (gated on 445/139) |
| 3 | **Share + User Enum** | Enumerate shares and domain users (null/guest) |
| 4 | **Spider+** | Auto-download accessible share files to `./loot/` |
| 5 | **RID Brute** | Enumerate users via RID cycling over SMB and MSSQL (MSSQL gated on 1433) |
| 6 | **LDAP Enum** | ASREPRoast, Kerberoast, delegation, `PASSWD_NOTREQD`, `adminCount=1` (gated on 389/636) |
| 7 | **Multi-Protocol** | Test null/guest auth on RDP (3389), WinRM (5985/5986), MSSQL (1433), FTP (21), SSH (22) — each gated on its port |
| 8 | **Password Spray** | Username-as-password spray against SMB (prompted at start; re-prompted after summary if skipped) |
| 9 | **TCP Targeted** | `-sCV --version-intensity 9` on discovered open ports |
| 10 | **UDP Sweep** | Full port scan → targeted `-sUCV --version-intensity 9` (requires root) |
| 11 | **Summary** | Key findings, generated files, optional spray re-prompt, exit confirmation |

> Phases gracefully skip if the required tool is missing, the port is closed, or privileges are insufficient.

## Output

**Single target** — flat directories in the current working directory:
```
recon/    loot/    nmap/
```

**Multiple targets** — per-IP subdirectories:
```
recon/10.10.10.1/    recon/10.10.10.2/
nmap/10.10.10.1/     nmap/10.10.10.2/
loot/10.10.10.1/     loot/10.10.10.2/
```

### Generated files

```
recon/
├── users.txt            # unified, deduplicated user list
├── users-null.txt       # users via null session
├── users-guest.txt      # users via guest login
├── users-ldap.txt       # users via LDAP enumeration
├── rid-brute-smb.txt    # users via SMB RID brute (null/anon)
├── rid-brute-smb-guest.txt  # users via SMB RID brute (guest)
├── rid-brute-mssql.txt  # users via MSSQL RID brute
├── shares-null.txt      # shares via null session
├── shares-guest.txt     # shares via guest login
├── signing-off.txt      # hosts with SMB signing disabled
├── asreproast.txt       # AS-REP roastable hashes
├── kerberoast.txt       # Kerberoastable hashes
├── spray-hits.txt       # valid username=password creds
└── hosts                # generated /etc/hosts entry

loot/
├── <ShareName>/         # downloaded files from accessible shares
└── spider_plus.json     # share metadata from spider_plus module

nmap/
├── tcp-allports.*       # full TCP sweep
├── tcp-targeted.*       # version + script scan on open TCP ports
├── udp-allports.*       # UDP top-1000 sweep
└── udp-targeted.*       # version + script scan on open UDP ports
```

### File ownership

When running under `sudo`, all output files are owned by the real (non-root) user via `$SUDO_USER`.

## Install

```bash
git clone https://github.com/g1nt0n1x/zbulim
cd zbulim
sudo ./install.sh
```

Or manually:

```bash
sudo cp zbulim /usr/local/bin/
sudo chmod +x /usr/local/bin/zbulim
```

## Requirements

- `nmap`
- `nxc` (NetExec) - for SMB/LDAP/multi-protocol enumeration
- `bash` 4+
- `sudo` - for UDP scans and `/etc/hosts` update

## Author

**g1nt0n1x**
