# zbulim

> *zbulim* (Albanian) — reconnaissance, discovery

Automated recon workflow for CTF / pentest engagements.

```
SMB enum     →  host discovery, /etc/hosts, null/guest auth, signing, shares
TCP sweep    →  full port scan → targeted -sCV on open ports
UDP sweep    →  top-1000 scan → targeted -sUCV on open ports
```

## Usage

```bash
zbulim <target> [output-dir]
```

| Argument     | Description                          | Default  |
|--------------|--------------------------------------|----------|
| `target`     | IP address or hostname               | required |
| `output-dir` | Directory where results are saved    | `./nmap` |

### Examples

```bash
zbulim 10.10.10.1
zbulim 10.10.10.1 ./nmap
sudo zbulim 10.10.10.1        # enables UDP scans
```

## Phases

| # | Phase | Description |
|---|-------|-------------|
| 1 | **SMB Enum** | Host discovery via `nxc smb`, auto-update `/etc/hosts` |
| 2 | **Null Session** | Test anonymous access (`-u '' -p ''`) |
| 3 | **Guest Login** | Test guest account (`-u 'guest' -p ''`) |
| 4 | **SMB Signing** | Check if signing is required (relay attack surface) |
| 5 | **Share + User Enum** | Enumerate shares and domain users if null or guest auth succeeded |
| 6 | **TCP Sweep** | Full port scan (`-p- --min-rate 10000`) → targeted `-sCV` |
| 7 | **UDP Sweep** | Top-1000 scan → targeted `-sUCV` (requires root) |

> Phases gracefully skip if the tool is missing (`nxc`) or privileges are insufficient (UDP).

## Output files

| File | Contents |
|------|----------|
| `hosts` | Generated hosts entry (appended to `/etc/hosts`) |
| `signing-off.txt` | Hosts with SMB signing not required |
| `shares-null.txt` | Shares accessible via null session |
| `shares-guest.txt` | Shares accessible via guest login |
| `users-null.txt` | Domain users enumerated via null session |
| `users-guest.txt` | Domain users enumerated via guest login |
| `tcp-allports.*` | Full TCP port sweep |
| `tcp-targeted.*` | Version + script scan on open TCP ports |
| `udp-allports.*` | UDP top-1000 sweep |
| `udp-targeted.*` | Version + script scan on open UDP ports |

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
- `nxc` (NetExec) — optional, for SMB enumeration
- `bash` 4+
- `sudo` — for UDP scans and `/etc/hosts` update

## Author

**g1nt0n1x**
