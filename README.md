# zbulim

> *zbulim* (Albanian) - reconnaissance, discovery

Port-based reconnaissance automation for OSCP and HackTheBox. Scans all ports, then enumerates each open service with the right tools — regardless of OS.

## How it works

```
Phase 1: Quick TCP scan (top 1000, ~10s) + full scan (background) + UDP (background)
Phase 2: Enumerate every open port immediately (SMB, HTTP, DNS, SNMP, etc.)
Phase 3: Full scan finishes → enumerate any newly discovered ports → targeted -sCV
Phase 4: UDP results → SNMP walks, DNS zone transfers
Phase 5: Consolidated summary
```

Findings are shown in real-time as colored notification boxes. Everything is logged to `recon/zbulim.log`.

## Supported services (21 modules)

| Port | Service | What it does |
|------|---------|-------------|
| 21 | FTP | Anonymous check, file listing, auto-download to `loot/ftp/`, writable dir check, vsftpd backdoor |
| 22 | SSH | Auth methods, version CVE flagging (e.g. OpenSSH < 7.7 username enum) |
| 25/587 | SMTP | VRFY/RCPT/EXPN user enum, open relay, NTLM domain leak |
| 53 | DNS | Zone transfer, ALL/NS/MX/TXT queries, dnsrecon subdomain brute |
| 80/443/8080/8443 | HTTP(S) | Domain detection from nmap redirect/SSL cert → /etc/hosts → ffuf vhost enum → feroxbuster dirs per vhost |
| 88 | Kerberos | Kerbrute user enumeration |
| 111/2049 | NFS | showmount, rpcinfo, nfs-ls, no_root_squash detection |
| 135 | MSRPC | rpcdump, named pipe enum, PrintNightmare flag |
| 139/445 | SMB | nxc: null/guest auth, shares, users, RID brute, spider_plus download, signing, pass policy |
| 161 | SNMP (UDP) | Community string brute, targeted OID walks (users, processes, software, internal ports), snmpwalk |
| 389/636 | LDAP | ldapsearch anonymous dump, ASREPRoast, Kerberoast, delegation, PASSWD_NOTREQD, adminCount |
| 1433 | MSSQL | Default creds (sa), NTLM domain leak, xp_cmdshell check, RID brute |
| 3306 | MySQL | Default creds (root), empty password, nmap scripts |
| 3389 | RDP | rdp-ntlm-info (domain/hostname leak), encryption check, auth test |
| 5432 | PostgreSQL | Default creds (postgres), nmap brute |
| 5900 | VNC | No-auth check, version, small brute, desktop title leak |
| 5985/5986 | WinRM | Auth test |
| 6379 | Redis | No-auth check, INFO, KEYS dump, CONFIG writable check |
| 8009 | AJP | Ghostcat CVE-2020-1938 detection, AJP methods |
| 27017 | MongoDB | No-auth check, database listing |

## HTTP workflow (the big one)

```
nmap detects redirect to http://box.htb
  → extracts domain, adds to /etc/hosts
  → feroxbuster on box.htb
  → ffuf vhost enum → finds dev.box.htb, admin.box.htb
  → adds vhosts to /etc/hosts
  → feroxbuster on each vhost
  → shows all results as they happen
```

## Install

```bash
sudo ./install.sh
```

Installs all dependencies (nmap, netexec, feroxbuster, ffuf, seclists, snmp, etc.) and copies zbulim + modules to `/usr/local/bin` and `/usr/local/share/zbulim/`.

## Usage

```bash
sudo zbulim 10.10.10.1
sudo zbulim 10.10.10.0/24
sudo zbulim 10.10.10.1 10.10.10.2
sudo zbulim 10.10.10.1 -o ./scans
sudo zbulim 10.10.10.1 --local-auth
sudo zbulim 10.10.10.1 --skip-nmap          # re-run with previous scan results
```

### Options

| Flag | Description |
|------|-------------|
| `-o, --output DIR` | Base directory for nmap results (default: `./nmap`) |
| `--local-auth` | Pass `--local-auth` to all nxc commands |
| `--skip-nmap` | Skip scans, use previous nmap results |
| `--skip-clock` | Skip ntpdate clock sync |

### Custom wordlists

```bash
ZBULIM_WL_DIRS="/path/to/dirs.txt" sudo zbulim 10.10.10.1
ZBULIM_WL_VHOSTS="/path/to/vhosts.txt" sudo zbulim 10.10.10.1
```

## Output

```
recon/              Findings (users, shares, vhosts, hashes, etc.)
recon/zbulim.log    Full verbose log of everything
loot/               Downloaded files (SMB spider, FTP anonymous)
nmap/               All nmap scan results
```

## Features

- **Port-based, not OS-based** — modules run based on open ports, not OS guesses
- **Quick scan first** — results in ~10 seconds, full scan runs in background
- **Real-time notifications** — findings shown as they happen in colored boxes
- **Auto domain detection** — extracts domain from nmap redirects and SSL certs
- **Auto /etc/hosts** — adds domains and vhosts automatically
- **Vhost + dir enum per vhost** — ffuf discovers vhosts, feroxbuster runs on each
- **Users merged** — users from SMB, SNMP, SMTP, LDAP, Kerberos all go into `users.txt`
- **Ctrl+C safe** — kills background scans, prints partial summary
- **Full log** — everything in `recon/zbulim.log`, terminal stays clean

## Requirements

- Kali Linux (or any Debian-based with pentest tools)
- Root/sudo (needed for nmap SYN scan, UDP, /etc/hosts, clock sync)

## Author

g1nt0n1x — https://github.com/g1nt0n1x/zbulim
