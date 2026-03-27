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
| 9 | **TCP Targeted** | `-sCV --version-intensity 7` on discovered open ports |
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

## To Do
- zbulim works very well for Windows AD machines and their ports: DNS, Kerberos, LDAP, etc. which we mainly enumerate using the fantabolous tool nxc. 
- But what if it a Linux OS with a webserver installed, or database server? 
- An initial recon with Web enumeration like dir busting, sublisting, etc. is also very useful.
- A pentest a always starts with an initial port scan, then we analyze the ports.
- The goal is to have always automated recon running.
- And instead of having one big script, wouldnt it be better to split this into multiple scripts? the current zbulim script stand alone is 1000 rows long, and that is only nxc + nmap!
- I checked online and there are already a lot of cool tools out there! I just want to cerate my own custom one, and make it inshaAllah even better!
- nmapautomator is quite a good tool, just like mine! It start with a host, check which hosts are up, and then does a quick port sweep to check what ports are up, enumerate the services with a version scan, and then it also uses tools to enumerate, something which I also want to add is to add nmap vuln scripts, and do actual good vuln scans.
- Tools to integrate from nmapautomator:
-   wpscan: port 80 for wordpress sites
-   sslscan to audit the SSL/TLS configuration of servers (very imporant, no need to run these very specific tools on all sites, first need to confirm and validate it is this kind, maybe even input, but I need to clearly structure it)
-   droopescan for CMS website (same thing as above)
-   joomscan for Joomla‑based websites
-   dnsrecon for dns
-   ODAT for oracle DB for default port 1521
-   snmp tools: smtp-user-enum	snmp-check	snmpwalk
- So after the initial nmap scan, the scripts starts the real recon (these are just my thoughts and tools I use):
-   SMB (445): Most is in zbulim now, could add - after identified null/guest auth - ldapsearch, etc. and create own folder.
-   HTTP (80):
-     Feroxbuster: deep path mapping
-     FUFF: directory discovery, virtual host identification, and parameter manipulation
-     Gobuster: Traditional directory and DNS brute-forcing; often used for straightforward path discovery.
-     Nikto: Automated vulnerability scanning for misconfigurations, outdated versions, and dangerous files.
-     Does not matter what tools are used, the goal is to utilize the most effective way to get the recon done.
-   Kerberos (88): Check for kerberoastable users with the users file we attained from SMB, or other tools, the options are limitless!
-   DNS (53):
-     Dig Querying DNS records and attempting zone transfers to map internal networks.
-     Nmblookup	Resolving NetBIOS names over TCP/IP to identify hostnames.
-     Nslookup	Directly querying name servers for domain name or IP address mapping.
-   etc. etc. etc. I want to focus now on the most commmon ones and not to go too much astray.
My goal is to do a fully functioning initial recon script for any OS which will appear on the OSCP, saving immense time, and providing a clear initial recon.
And what I really want to add is, instead of having to wait for everything, it would be better to split them. So for instance, after having the port sweep, knowing that http is open, we can directy scan with direcotry busting, path mapping, etc. no actuall need for a normal port scan. We can safe time.
Furthermore, I have in the end a "result" page, but I want to remove this for now, just to make sure everything works, every output is correct, so I would still like to see the most important output. And very important, every output, every command is saved onto a file, just like nmap.  

As we are aware, the OSCP requires pivoting, this may be something  I will add to the future. 

## Author

**g1nt0n1x**
