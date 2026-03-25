# zbulim

> *zbulim* (Albanian) - reconnaissance, discovery

Automated AD / Windows recon tool for OSCP and CTF engagements. Runs `nxc` across multiple protocols and `nmap` in a single command, producing a clean `recon/` folder with deduplicated results and a summary of key findings.

```
SMB enum     →  host discovery, /etc/hosts, null/guest auth, signing, shares, users
RID brute    →  user enumeration via RID cycling (SMB + MSSQL)
LDAP enum    →  ASREPRoast, Kerberoast, delegation, PASSWD_NOTREQD, adminCount
Multi-proto  →  test null/guest on RDP, WinRM, MSSQL, FTP, SSH
Password spray → username-as-password against SMB
TCP sweep    →  full port scan → targeted -sCV on open ports
UDP sweep    →  top-1000 scan → targeted -sUCV on open ports
Summary      →  key findings at a glance
```

## Usage

```bash
zbulim <target> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `target` | IP address or hostname | required |
| `-o, --output DIR` | Directory for nmap results | `./nmap` |
| `--skip-nmap` | Skip all nmap scans (re-runs, nxc-only recon) | off |
| `-h, --help` | Show help | |

### Examples

```bash
zbulim 10.10.10.1
zbulim 10.10.10.1 --skip-nmap        # nxc recon only, no nmap
zbulim 10.10.10.1 -o ./scans
sudo zbulim 10.10.10.1               # enables UDP scans
```

## Phases

| # | Phase | What it does |
|---|-------|-------------|
| 1 | **SMB Enum** | Host discovery via `nxc smb`, auto-update `/etc/hosts`, null/guest auth, SMB signing, password policy |
| 2 | **Share + User Enum** | Enumerate shares and domain users (null/guest) |
| 3 | **RID Brute** | Enumerate users via RID cycling over SMB and MSSQL |
| 4 | **LDAP Enum** | ASREPRoast, Kerberoast, delegation, `PASSWD_NOTREQD`, `adminCount=1` |
| 5 | **Multi-Protocol** | Test null/guest auth on RDP, WinRM, MSSQL, FTP (anonymous), SSH |
| 6 | **Password Spray** | Username-as-password spray against SMB |
| 7 | **TCP Sweep** | Full port scan (`-p- --min-rate 10000`) → targeted `-sCV` |
| 8 | **UDP Sweep** | Full port scan → targeted `-sUCV` (requires root!) |
| 9 | **Summary** | Key findings box - what matters at a glance |

> Phases gracefully skip if the required tool is missing or privileges are insufficient.

## Output

All recon output goes to `./recon/`, nmap scans go to `./nmap/` (or custom `-o` dir). Empty files are never created.

```
recon/
├── users.txt            # unified, deduplicated user list
├── users-null.txt       # users via null session
├── users-guest.txt      # users via guest login
├── rid-brute-smb.txt    # users via SMB RID brute
├── rid-brute-mssql.txt  # users via MSSQL RID brute
├── shares-null.txt      # shares via null session
├── shares-guest.txt     # shares via guest login
├── signing-off.txt      # hosts with SMB signing disabled
├── asreproast.txt       # AS-REP roastable hashes
├── kerberoast.txt       # Kerberoastable hashes
├── spray-hits.txt       # valid username=password creds
└── hosts                # generated /etc/hosts entry

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
