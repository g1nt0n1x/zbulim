# zbulim v2 — Port-Based Reconnaissance Framework

## Philosophy Change

**Current:** OS-centric. Assumes Windows/AD → runs SMB/LDAP/Kerberos first, web as afterthought.

**New:** Port-centric. Full scan → enumerate each open port with the right tools. A Linux box with SMB gets nxc. A Windows box with port 80 gets vhost/dir enum. The port dictates the module, not the OS.

**Operator role:** zbulim surfaces findings fast and saves everything. The human decides what to exploit. The tool should never be blindly trusted — it shows you what's there, you think about what it means.

---

## Architecture

### Decision: Stay in Bash, Modularize

- **Why bash:** Runs on stock Kali, no Python venv headaches during OSCP, pentesters can read/tweak it
- **What changes:** Split the monolith into sourced modules. Main script orchestrates; each module handles one service.
- **Python:** Not needed. All parsing (domain extraction, nmap grep) can be done with sed/awk/grep.

### File Structure

```
zbulim                     # main entry point — arg parsing, orchestration, flow control
modules/
  common.sh                # colors, helpers, notify(), safe_write(), /etc/hosts mgmt
  scan.sh                  # nmap logic: quick, full TCP, targeted -sCV, UDP
  port_ftp.sh              # 21
  port_ssh.sh              # 22
  port_smtp.sh             # 25/587
  port_dns.sh              # 53 (TCP + UDP)
  port_http.sh             # 80/443/8080/8443 — the big one (domain detect, vhost, dirs)
  port_kerberos.sh         # 88
  port_nfs.sh              # 111/2049
  port_rpc.sh              # 135 (MSRPC)
  port_smb.sh              # 139/445 (existing nxc logic, cleaned up)
  port_snmp.sh             # 161 (UDP)
  port_ldap.sh             # 389/636 (existing nxc logic, cleaned up)
  port_mssql.sh            # 1433
  port_mysql.sh            # 3306
  port_rdp.sh              # 3389
  port_postgresql.sh       # 5432
  port_vnc.sh              # 5900
  port_winrm.sh            # 5985/5986
  port_redis.sh            # 6379
  port_ajp.sh              # 8009 (AJP/Tomcat)
  port_mongodb.sh          # 27017
  summary.sh               # final consolidated report
install.sh                 # apt install all deps
```

Each module exports a single function: `enum_<service> $TARGET`. Modules source `common.sh` for shared helpers. The main script calls them based on open ports.

---

## Execution Flow

```
Phase 0: Setup
  ├── Parse args, create dirs (recon/, nmap/, loot/)
  ├── CIDR ping sweep if target is a range
  └── Clock sync (optional, --skip-clock)

Phase 1: Discovery (parallel)
  ├── TCP quick scan (top 1000, --min-rate 5000) → FOREGROUND → gives ports in ~10s
  ├── TCP full scan (all 65535, --min-rate 10000) → BACKGROUND
  └── UDP top 200 → BACKGROUND

Phase 2: Quick Enumeration (starts immediately after quick scan)
  ├── *** NOTIFY USER: show open ports from quick scan ***
  ├── For each open port → run matching port module
  │   (SMB, HTTP, DNS, SNMP, etc. — all based on what's open)
  └── Modules run sequentially per service (no race conditions)

Phase 3: Full Scan Results (when background TCP full scan completes)
  ├── *** NOTIFY USER: paste the .nmap file contents ***
  ├── Diff against quick scan → find newly discovered ports
  ├── Run port modules for NEW ports only (skip already-enumerated)
  └── TCP targeted -sCV on ALL open ports → save to nmap/

Phase 4: UDP Results (when background UDP scan completes)
  ├── *** NOTIFY USER: show open UDP ports ***
  ├── Run UDP port modules (SNMP, DNS-UDP)
  └── UDP targeted -sUCV on open UDP ports

Phase 5: Summary
  └── Consolidated findings report (dirs, vhosts, shares, users, etc.)
```

### Why quick scan + full scan?

The quick scan (top 1000) finishes in ~10 seconds and catches 95% of services. We start enumerating immediately. The full scan (all 65535) runs in background and catches weird high ports. When it finishes, we only enumerate the *new* ports. This means the user sees results within 30 seconds, not 2 minutes.

---

## Port Modules — What Each Does

### Port 21 — FTP (`port_ftp.sh`)

| Tool | Purpose |
|------|---------|
| `nxc ftp $TARGET -u anonymous -p ''` | Test anonymous login |
| nmap `--script=ftp-anon,ftp-syst,ftp-vsftpd-backdoor,ftp-bounce` | Anon access, system type, backdoor CVE, bounce attack |
| `ftp -n $TARGET` → `ls -la` | If anonymous works: list all files recursively |
| Auto-download | If anonymous READ: download all files to `loot/ftp/` |
| Writable check | If anonymous: try `put testfile` to detect writable dirs |

**Deep enum flow:**
1. Test anonymous login (nxc)
2. If anonymous works → connect and list all files/dirs recursively
3. Download everything to `loot/ftp/` (like spider_plus does for SMB)
4. Check if any directory is writable (upload test)
5. Run nmap scripts for known CVEs (vsftpd 2.3.4 backdoor, bounce)

- **Alert if:** anonymous access, writable directory, backdoor detected
- **Save:** `recon/ftp-anon.txt`, `recon/ftp-files.txt`, `loot/ftp/`
- **Priority:** Low-hanging

### Port 22 — SSH (`port_ssh.sh`)

| Tool | Purpose |
|------|---------|
| `nxc ssh $TARGET -u '' -p ''` | Banner grab |
| nmap `--script=ssh-auth-methods` | Check allowed auth methods (password, publickey, etc.) |
| nmap version detection | Extract exact OpenSSH version |
| Version check | Flag known-vulnerable versions (e.g., OpenSSH < 7.7 = username enum CVE-2018-15473) |

**Deep enum flow:**
1. Banner grab for exact version string
2. Check auth methods — if only `publickey`, password brute is useless (saves time later)
3. Flag vulnerable versions with a note:
   - OpenSSH < 7.7 → username enumeration (CVE-2018-15473)
   - OpenSSH < 9.3p2 → CVE-2023-38408 (agent forwarding RCE)
   - Note: don't auto-exploit, just flag for the operator

- **Alert if:** known vulnerable version detected
- **Save:** `recon/ssh-info.txt` (version + auth methods)
- **Priority:** Low-hanging

### Port 25/587 — SMTP (`port_smtp.sh`)

| Tool | Purpose |
|------|---------|
| nmap `--script=smtp-commands,smtp-enum-users,smtp-open-relay,smtp-ntlm-info` | Commands, user enum, open relay, NTLM domain leak |
| `smtp-user-enum -M VRFY -U users.txt -t $TARGET` | User enum via VRFY (if users.txt exists) |
| `smtp-user-enum -M RCPT -U users.txt -t $TARGET` | User enum via RCPT TO (fallback if VRFY disabled) |
| `smtp-user-enum -M EXPN -U users.txt -t $TARGET` | User enum via EXPN (mailing list expansion) |

**Deep enum flow:**
1. nmap scripts first — get supported commands, check relay, extract NTLM info
2. If VRFY is listed in commands → `smtp-user-enum -M VRFY`
3. If VRFY disabled → try RCPT TO method (works more often)
4. If EXPN available → try that too
5. If users.txt doesn't exist yet → use a small default wordlist (`/usr/share/seclists/Usernames/top-usernames-shortlist.txt`)
6. `smtp-ntlm-info` leaks internal hostname/domain on Exchange servers — feed into DOMAIN variable

- **Alert if:** VRFY/RCPT enumerable, open relay, NTLM domain leaked
- **Save:** `recon/smtp-commands.txt`, `recon/smtp-users.txt`
- **Merge:** found users into `recon/users.txt`
- **Priority:** Mid-hanging

### Port 53 — DNS (`port_dns.sh`)

| Tool | Purpose |
|------|---------|
| `dig axfr @$TARGET $DOMAIN` | Zone transfer — the goldmine |
| `dig any $DOMAIN @$TARGET` | All DNS records (A, MX, NS, TXT, etc.) |
| `dig ns $DOMAIN @$TARGET` | Nameserver records |
| `dig mx $DOMAIN @$TARGET` | Mail server records |
| `dig txt $DOMAIN @$TARGET` | TXT records (SPF, DKIM — sometimes leak internal info) |
| `dnsrecon -d $DOMAIN -n $TARGET -t std` | Standard enum |
| `dnsrecon -d $DOMAIN -n $TARGET -t brt -D <subdomains>` | Subdomain brute (complement to ffuf vhost) |
| nmap `--script=dns-nsid,dns-service-discovery,dns-zone-transfer` | NSE scripts |

**Deep enum flow:**
1. Zone transfer attempt first — if it works, you get everything and can skip brute forcing
2. If zone transfer fails → run individual queries (ANY, NS, MX, TXT)
3. dnsrecon standard enum
4. dnsrecon subdomain brute — uses DNS resolution (different from ffuf vhost which uses HTTP Host header). Both should run since they find different things.
5. Parse zone transfer output for subdomains → add all to `/etc/hosts`
6. Feed discovered subdomains into HTTP module for dir enum

**Important:** DNS enum needs DOMAIN. If DOMAIN isn't known yet (no SMB, HTTP hasn't run), defer this module until after HTTP domain detection, then come back.

- **Alert if:** zone transfer succeeds (CRITICAL — show full output), new subdomains found
- **Save:** `recon/dns-axfr.txt`, `recon/dns-records.txt`, `recon/dns-subdomains.txt`
- **Priority:** Low-hanging (zone transfers are common in OSCP/HTB)

### Port 80/443/8080/8443 — HTTP(S) (`port_http.sh`) — THE BIG ONE

This is the core module for Linux boxes. The flow:

```
Step 1: whatweb fingerprint
  → whatweb --no-errors -a 3 http://TARGET:PORT
  → Save to recon/whatweb-PORT.txt

Step 2: Detect domain from nmap output
  → Parse tcp-targeted.nmap (or quick scan) for:
    - "Did not follow redirect to http://box.htb/"     ← most common
    - "Requested resource was http://box.htb/login"     ← redirect variant
    - SSL cert: "Subject: CN=box.htb"                   ← HTTPS
    - SSL cert: "Subject Alternative Name: DNS:box.htb" ← SAN
  → Also check whatweb output for domain hints
  → If domain found: DOMAIN="box.htb"

Step 3: Update /etc/hosts
  → If DOMAIN detected and not already in /etc/hosts:
    → Append: "10.10.10.10    box.htb"
    → *** NOTIFY USER: "Domain detected: box.htb → added to /etc/hosts" ***

Step 4: Directory enumeration on main domain
  → feroxbuster -u http://box.htb -o recon/ferox-PORT.txt --silent --no-state -t 50
  → (Falls back to gobuster if feroxbuster not installed)
  → *** NOTIFY USER: show interesting results (non-403, non-404) ***
  → Save: recon/ferox-PORT.txt

Step 5: Vhost enumeration
  → Only if DOMAIN is known
  → ffuf -u http://DOMAIN -H "Host: FUZZ.DOMAIN" \
         -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
         -ac -o recon/vhosts-PORT.json -of json
  → Parse JSON output for discovered vhosts
  → *** NOTIFY USER: "Vhosts found: dev.box.htb, admin.box.htb" ***
  → Save: recon/vhosts.txt (one per line)

Step 6: Update /etc/hosts for each vhost
  → For each vhost: append "10.10.10.10    dev.box.htb"
  → *** NOTIFY USER: "Added dev.box.htb, admin.box.htb to /etc/hosts" ***

Step 7: Directory enumeration per vhost
  → For each discovered vhost:
    → feroxbuster -u http://dev.box.htb -o recon/ferox-dev.box.htb.txt ...
    → *** NOTIFY USER: show results per vhost ***
  → Save: recon/ferox-<vhost>.txt

Step 8: (HTTPS variant)
  → Repeat steps 4-7 for https:// if 443/8443 is open
  → Add -k flag to feroxbuster for self-signed certs
```

**Domain detection logic (priority order):**
1. nmap output: `Did not follow redirect to http://DOMAIN/` — most reliable
2. nmap output: `Subject: CN=DOMAIN` or `DNS:DOMAIN` in SSL cert
3. whatweb output: redirect or domain mention
4. SMB/nxc hostname.domain (already extracted in SMB module) — for AD joined web servers
5. No domain found → dir enum on IP only, skip vhost enum

- **Priority:** Low-hanging (this is the #1 gap in current zbulim)

### Port 88 — Kerberos (`port_kerberos.sh`)

Existing logic, cleaned up:

| Tool | Purpose |
|------|---------|
| `kerbrute userenum --dc $TARGET -d $DOMAIN wordlist` | User enumeration |

- Only runs when no null/guest auth (already correct behavior)
- **Priority:** Low-hanging (already implemented, just extract to module)

### Port 111/2049 — NFS (`port_nfs.sh`)

| Tool | Purpose |
|------|---------|
| `showmount -e $TARGET` | List exported shares |
| `rpcinfo -p $TARGET` | List all registered RPC services |
| nmap `--script=nfs-ls,nfs-showmount,nfs-statfs` | NFS listing, stats, permissions |
| nmap `--script=rpcinfo` | RPC service enumeration |
| Mount + list | If export found: mount it, list files, check for `.ssh/`, config files |

**Deep enum flow:**
1. `rpcinfo -p` — list all RPC services (may reveal NFS, mountd, nlockmgr, etc.)
2. `showmount -e` — list NFS exports and who can mount them
3. nmap NFS scripts — get file listing without mounting, show permissions + disk stats
4. If exports found:
   - Show the mount command: `mount -t nfs $TARGET:/share /mnt/nfs`
   - Check export options: flag `no_root_squash` (allows root-level access → privesc)
   - nmap `nfs-ls` gives us a file listing without needing to actually mount
5. Also check for other RPC services that might be interesting (rusersd, ypserv/NIS)

- **Alert if:** NFS exports found, `no_root_squash` detected, interesting files visible
- **Save:** `recon/nfs-exports.txt`, `recon/rpcinfo.txt`, `recon/nfs-files.txt`
- **Priority:** Low-hanging (very common in OSCP — often leads to SSH key or privesc)

### Port 139/445 — SMB (`port_smb.sh`)

Existing logic — already solid. Extract to module as-is:

| Tool | Purpose |
|------|---------|
| `nxc smb` host discovery | Hostname, domain, /etc/hosts |
| `nxc smb` null/guest | Auth testing |
| `nxc smb --shares` | Share enumeration |
| `nxc smb --users` | User enumeration |
| `nxc smb --rid-brute` | RID cycling |
| `nxc smb -M spider_plus` | Download share files |
| `nxc smb --gen-relay-list` | Signing check |
| `nxc smb --pass-pol` | Password policy |

- Same alert logic as current
- **Priority:** Low-hanging (already done, just modularize)

### Port 161 — SNMP/UDP (`port_snmp.sh`)

| Tool | Purpose |
|------|---------|
| `onesixtyone $TARGET -c /usr/share/seclists/Discovery/SNMP/snmp.txt` | Community string brute force |
| `snmpwalk -v2c -c <community> $TARGET 1.3.6.1.2.1.25.1.6.0` | System processes (hrSWRunName) |
| `snmpwalk -v2c -c <community> $TARGET 1.3.6.1.4.1.77.1.2.25` | Windows user accounts |
| `snmpwalk -v2c -c <community> $TARGET 1.3.6.1.2.1.25.4.2.1.2` | Running processes with paths |
| `snmpwalk -v2c -c <community> $TARGET 1.3.6.1.2.1.6.13.1.3` | Open TCP ports (internal view) |
| `snmpwalk -v2c -c <community> $TARGET 1.3.6.1.2.1.25.6.3.1.2` | Installed software |
| `snmpwalk -v2c -c <community> $TARGET` (full) | Complete SNMP walk (save raw) |
| `snmp-check $TARGET -c <community>` | Formatted human-readable dump |
| nmap `--script=snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr,snmp-netstat` | NSE SNMP scripts |

**Deep enum flow:**
1. `onesixtyone` brute force community strings (public, private, manager, etc.)
2. Try both v1 and v2c — some devices only respond to one
3. If community string found → targeted walks on high-value OIDs:
   - **Users** (OID 1.3.6.1.4.1.77.1.2.25) → merge into `users.txt`
   - **Running processes** (OID 1.3.6.1.2.1.25.4.2.1.2) → look for interesting services, cron jobs, scripts with passwords in command line
   - **Installed software** (OID 1.3.6.1.2.1.25.6.3.1.2) → versions for CVE research
   - **Network interfaces** → internal IPs, routing info
   - **TCP connections** → see what's listening internally (ports not exposed to us)
4. Full `snmpwalk` dump saved raw for manual review
5. `snmp-check` for a pretty-printed summary
6. Parse output automatically: extract usernames, flag interesting processes

- **Alert if:** community string found (show which), users extracted, interesting processes
- **Save:** `recon/snmp-community.txt`, `recon/snmpwalk.txt`, `recon/snmp-users.txt`, `recon/snmp-processes.txt`, `recon/snmp-software.txt`
- **Merge:** extracted users into `recon/users.txt`
- **Priority:** Low-hanging (SNMP is a goldmine in OSCP — often leaks creds or process info)

### Port 389/636 — LDAP (`port_ldap.sh`)

Existing logic — already solid. Extract to module + add ldapsearch:

| Tool | Purpose |
|------|---------|
| `ldapsearch -x -H ldap://$TARGET -b '' -s base namingContexts` | Anonymous bind — get base DNs |
| `ldapsearch -x -H ldap://$TARGET -b '<base_dn>' '(objectClass=*)'` | Anonymous full dump (if allowed) |
| `nxc ldap --asreproast` | AS-REP roast |
| `nxc ldap --kerberoasting` | Kerberoast |
| `nxc ldap --users` | User enum fallback |
| `nxc ldap --find-delegation` | Delegation relationships |
| `nxc ldap --password-not-required` | PASSWD_NOTREQD flag |
| `nxc ldap --admin-count` | Admin accounts |
| nmap `--script=ldap-rootdse,ldap-search` | Root DSE info, anonymous search |

**Deep enum additions (new):**
1. `ldapsearch` anonymous bind first — get naming contexts (base DN)
2. If anonymous bind works → try full LDAP dump (gives you everything: users, groups, OUs, SPNs, descriptions)
3. Parse LDAP dump for description fields — admins sometimes put passwords in user descriptions
4. nmap `ldap-rootdse` — reveals domain functional level, FQDN, supported SASL mechanisms

- **Save (new):** `recon/ldap-rootdse.txt`, `recon/ldap-dump.txt`
- **Priority:** Low-hanging (already done, add ldapsearch + rootdse)

### Port 1433 — MSSQL (`port_mssql.sh`)

| Tool | Purpose |
|------|---------|
| `nxc mssql $TARGET -u '' -p ''` | Anonymous auth test |
| `nxc mssql $TARGET -u 'sa' -p ''` | SA no-password check |
| `nxc mssql $TARGET -u 'sa' -p 'sa'` | SA default creds check |
| `nxc mssql $TARGET -u '' -p '' --rid-brute` | RID brute (existing) |
| nmap `--script=ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password` | Version, NTLM domain leak, empty password |
| `nxc mssql $TARGET -u <user> -p <pass> -x 'SELECT @@version'` | If auth works: version query |
| `nxc mssql $TARGET -u <user> -p <pass> -x 'EXEC xp_cmdshell "whoami"'` | If auth works: check xp_cmdshell (RCE!) |

**Deep enum flow:**
1. Anonymous auth test
2. Default creds: `sa:""`, `sa:sa`
3. nmap `ms-sql-ntlm-info` — leaks internal domain, hostname, DNS name (works without auth)
4. nmap `ms-sql-info` — version, instance name, named pipes
5. If any auth works:
   - Check if `xp_cmdshell` is enabled (instant RCE)
   - Query linked servers: `EXEC sp_linkedservers`
   - Query databases: `SELECT name FROM master.dbo.sysdatabases`
6. RID brute via MSSQL (existing)

- **Alert if:** auth succeeds (any creds), xp_cmdshell enabled (CRITICAL), NTLM domain leaked
- **Save:** `recon/mssql-info.txt`, `recon/mssql-ntlm.txt`
- **Priority:** Low-hanging

### Port 3306 — MySQL (`port_mysql.sh`)

| Tool | Purpose |
|------|---------|
| `nxc mysql $TARGET -u root -p ''` | Root no-password |
| `nxc mysql $TARGET -u root -p 'root'` | Root default creds |
| `nxc mysql $TARGET -u root -p 'toor'` | Another common default |
| nmap `--script=mysql-info,mysql-enum,mysql-empty-password,mysql-databases` | Version, user enum, empty pass, list DBs |

**Deep enum flow:**
1. Try common default creds: `root:""`, `root:root`, `root:toor`, `mysql:mysql`
2. nmap `mysql-info` — version, protocol, capabilities
3. nmap `mysql-empty-password` — tests root and anonymous with no password
4. If auth works:
   - List databases: `SHOW DATABASES`
   - Check for UDF (User Defined Functions) that could give RCE
   - Check `secure_file_priv` — if empty, can read/write files (`LOAD_FILE`, `INTO OUTFILE`)

- **Alert if:** any default cred works, empty root password
- **Save:** `recon/mysql-info.txt`
- **Priority:** Mid-hanging

### Port 3389 — RDP (`port_rdp.sh`)

| Tool | Purpose |
|------|---------|
| `nxc rdp $TARGET -u '' -p ''` | Auth test (existing) |
| nmap `--script=rdp-ntlm-info` | Leaks domain, hostname, DNS name — works without auth |
| nmap `--script=rdp-enum-encryption` | Encryption level — flags weak/NLA-disabled (BlueKeep era) |

**Deep enum flow:**
1. nxc auth check (existing)
2. `rdp-ntlm-info` — this is gold: leaks internal domain name, NetBIOS hostname, DNS domain even with NLA enabled. Feed into DOMAIN variable.
3. `rdp-enum-encryption` — if CredSSP/NLA is disabled, note for operator (easier brute force, potential BlueKeep if old enough)

- **Alert if:** NTLM info leaks domain/hostname, NLA disabled
- **Save:** `recon/rdp-info.txt`
- **Priority:** Low-hanging

### Port 135 — MSRPC (`port_rpc.sh`) — NEW

| Tool | Purpose |
|------|---------|
| `rpcdump.py $TARGET` (impacket) | Dump all RPC endpoints — reveals services, interfaces, named pipes |
| `rpcinfo -p $TARGET` | List registered RPC programs |
| nmap `--script=msrpc-enum` | Enumerate Microsoft RPC services |

**Deep enum flow:**
1. `rpcdump.py` (impacket) — lists every RPC endpoint. Named pipes in the output reveal what services are running (e.g., `\pipe\epmapper`, `\pipe\samr`, `\pipe\srvsvc`). This also confirms AD services.
2. `rpcinfo` — broader, shows NFS/NIS/etc. RPC services too
3. Look for interesting named pipes: `\pipe\browser` (domain browsing), `\pipe\spoolss` (print spooler — PrintNightmare)

- **Alert if:** spoolss pipe found (PrintNightmare potential), unusual services
- **Save:** `recon/rpcdump.txt`, `recon/rpcinfo.txt`
- **Priority:** Mid-hanging

### Port 5432 — PostgreSQL (`port_postgresql.sh`) — NEW

| Tool | Purpose |
|------|---------|
| `nxc postgres $TARGET -u postgres -p postgres` | Default creds (most common) |
| `nxc postgres $TARGET -u postgres -p ''` | Empty password |
| `nxc postgres $TARGET -u admin -p admin` | Another common default |
| nmap `--script=pgsql-brute` | Brute with small default cred list |

**Deep enum flow:**
1. Try default creds: `postgres:postgres`, `postgres:""`, `admin:admin`
2. If auth works:
   - List databases: `\l`
   - Check superuser status
   - Check if `COPY TO/FROM PROGRAM` is available (= RCE as postgres user)
   - Check `pg_read_server_files` role
3. nmap pgsql-brute as fallback

- **Alert if:** default creds work, superuser access (CRITICAL if COPY PROGRAM available)
- **Save:** `recon/postgresql-info.txt`
- **Priority:** Mid-hanging (common in HTB, less so in OSCP)

### Port 5900 — VNC (`port_vnc.sh`) — NEW

| Tool | Purpose |
|------|---------|
| nmap `--script=vnc-info,vnc-title` | VNC version, desktop title (visible without auth sometimes) |
| `nxc vnc $TARGET` | Auth check (if nxc supports it) |
| nmap `--script=vnc-brute` | Small brute force with common VNC passwords |

**Deep enum flow:**
1. `vnc-info` — get version, check if auth is required
2. `vnc-title` — sometimes shows desktop title without authenticating (information leak)
3. No-auth check — some VNC servers are configured without a password
4. Small brute — VNC passwords are limited to 8 chars, common ones: `password`, `vnc`, `123456`

- **Alert if:** no auth required (CRITICAL — instant access), version with known CVE
- **Save:** `recon/vnc-info.txt`
- **Priority:** Mid-hanging

### Port 5985/5986 — WinRM (`port_winrm.sh`)

| Tool | Purpose |
|------|---------|
| `nxc winrm $TARGET -u '' -p ''` | Auth test (existing) |

- Not much to enumerate without creds — this one stays light
- **Priority:** Low-hanging (already implemented)

### Port 6379 — Redis (`port_redis.sh`) — NEW

| Tool | Purpose |
|------|---------|
| `redis-cli -h $TARGET INFO` | Server info (no auth check) |
| `redis-cli -h $TARGET CONFIG GET *` | Dump config (if no auth) |
| `redis-cli -h $TARGET KEYS *` | List all keys |
| `redis-cli -h $TARGET -a <password> INFO` | Try with common passwords |
| nmap `--script=redis-info` | Version + info |

**Deep enum flow:**
1. Try connecting without auth → `INFO` command
2. If no auth required:
   - `INFO` — server version, OS, memory, connected clients
   - `CONFIG GET dir` + `CONFIG GET dbfilename` — check where Redis writes (for webshell/SSH key write attacks)
   - `KEYS *` — list all keys, `GET` interesting ones
   - `CLIENT LIST` — who else is connected
3. If auth required → try common passwords: `password`, `redis`, `admin`
4. Note for operator: if `CONFIG SET` works, can write files (webshell, SSH authorized_keys)

- **Alert if:** no auth required (CRITICAL), data in keys, writable config
- **Save:** `recon/redis-info.txt`, `recon/redis-keys.txt`
- **Priority:** Low-hanging (very common HTB vector, usually no auth)

### Port 8009 — AJP/Tomcat (`port_ajp.sh`) — NEW

| Tool | Purpose |
|------|---------|
| nmap `--script=ajp-methods,ajp-request` | AJP methods, request test |
| Version check | Flag Ghostcat (CVE-2020-1938) if Tomcat < 9.0.31 / < 8.5.51 / < 7.0.100 |

**Deep enum flow:**
1. nmap `ajp-methods` — check allowed HTTP methods through AJP
2. nmap `ajp-request` — try to fetch `/` through AJP
3. Check Tomcat version (from nmap service detection) against Ghostcat CVE ranges
4. If Ghostcat-vulnerable: alert with exploit tool reference (`ajpShooter.py`)

- **Alert if:** Ghostcat-vulnerable version (CRITICAL), AJP connector accessible
- **Save:** `recon/ajp-info.txt`
- **Priority:** Mid-hanging (shows up in HTB occasionally)

### Port 27017 — MongoDB (`port_mongodb.sh`) — NEW

| Tool | Purpose |
|------|---------|
| nmap `--script=mongodb-info,mongodb-databases` | Version, list databases |
| `mongosh --host $TARGET --eval 'db.adminCommand({listDatabases:1})'` | List DBs (no auth) |
| `mongosh --host $TARGET --eval 'show users'` | List users (no auth) |

**Deep enum flow:**
1. nmap `mongodb-info` — version, whether auth is enabled
2. nmap `mongodb-databases` — if no auth, lists all databases
3. If no auth:
   - List databases
   - For each database: list collections
   - Look for `admin`, `users`, `credentials` collections
   - Dump interesting collections
4. `mongosh` as fallback/deeper enumeration

- **Alert if:** no auth required (CRITICAL), databases accessible, credentials collection found
- **Save:** `recon/mongodb-info.txt`, `recon/mongodb-databases.txt`
- **Priority:** Mid-hanging

---

## User Interface — Real-Time Notifications

### The `notify()` function

A standardized way to surface important findings immediately. Three levels:

```bash
# FINDING — something interesting the operator should see NOW
notify_finding "TITLE" "line1" "line2" ...
# Renders as a green box

# WARNING — something the operator should be aware of
notify_warning "TITLE" "line1" "line2" ...
# Renders as a yellow box  

# CRITICAL — high-value finding (AS-REP hash, zone transfer, writable share)
notify_critical "TITLE" "line1" "line2" ...
# Renders as a bold red/green box
```

### What triggers notifications (the user's requirements):

| Event | Level | What to show |
|-------|-------|-------------|
| Quick TCP scan done | FINDING | List of open ports |
| Full TCP scan done | FINDING | Paste the .nmap file contents |
| Domain detected | FINDING | `10.10.10.10 → box.htb (added to /etc/hosts)` |
| SMB shares accessible | FINDING | Share listing with READ/WRITE perms |
| Spider downloaded files | FINDING | File tree of downloaded loot |
| Vhosts discovered | FINDING | List of vhosts found |
| Directory enum results | FINDING | Interesting paths per domain/vhost |
| NFS exports found | FINDING | Export list |
| SNMP community found | FINDING | Community string + brief walk summary |
| DNS zone transfer | CRITICAL | Full zone records |
| AS-REP hash found | CRITICAL | Hash + crack command |
| Kerberoast hash found | CRITICAL | Hash + crack command |
| FTP anonymous + files listed | FINDING | File listing, writable dirs |
| FTP files downloaded | FINDING | File tree of loot/ftp/ |
| SSH vulnerable version | WARNING | Version + CVE reference |
| NFS exports visible | FINDING | Export list + mount command |
| RDP NTLM domain leaked | FINDING | Internal domain/hostname |
| MSSQL default creds | CRITICAL | Which creds worked, xp_cmdshell status |
| PostgreSQL default creds | CRITICAL | Which creds, superuser status |
| Redis no auth | CRITICAL | Server info, key count, writable config |
| MongoDB no auth | CRITICAL | Database list |
| VNC no auth | CRITICAL | Instant desktop access |
| AJP Ghostcat vulnerable | CRITICAL | Tomcat version + CVE |
| SMTP VRFY/relay open | WARNING | Enumerable users, relay status |
| SMB signing off | WARNING | Relay possible |
| Anonymous/guest auth | WARNING | What's accessible |
| UDP scan done | FINDING | Open UDP ports |

### Progress Line

Every module prints a progress header so the user always knows where the tool is:

```
[Phase 2/5] [Module 3/14: HTTP (80)] [Elapsed: 1m32s]
```

Implementation in `common.sh`:

```bash
TOTAL_MODULES=0    # set after port discovery
CURRENT_MODULE=0
CURRENT_PHASE=0
TOTAL_PHASES=5

progress() {
    local module_name="$1"
    (( CURRENT_MODULE++ ))
    echo
    echo -e "${DIM}[Phase ${CURRENT_PHASE}/${TOTAL_PHASES}] [Module ${CURRENT_MODULE}/${TOTAL_MODULES}: ${module_name}] [Elapsed: $(elapsed)]${RESET}"
}
```

Called at the start of every module: `progress "HTTP (80)"`, `progress "SMB (445)"`, etc.

Between modules, only notification boxes and the progress line are printed to the terminal. Verbose tool output (raw nxc lines, feroxbuster progress, etc.) goes to the log file only — unless it's a finding worth showing.

### Log File

All output is tee'd to `recon/zbulim.log`:

```bash
# In main zbulim script, right after creating dirs
LOGFILE="${RECONDIR}/zbulim.log"
exec > >(tee -a "$LOGFILE") 2>&1
```

This means:
- Terminal shows the clean output (progress lines + notification boxes)
- `recon/zbulim.log` has **everything** — every tool's raw output, every command run
- If the terminal closes, scrollback is lost, or the user walks away — nothing is lost
- The user can `grep` the log later: `grep -i "password\|credential\|secret" recon/zbulim.log`

### Ctrl+C Handling (Graceful Interrupt)

Trap SIGINT so the user can stop the tool cleanly at any time:

```bash
BACKGROUND_PIDS=()

cleanup() {
    echo
    warn "Interrupted — cleaning up..."

    # Kill background nmap/scans
    for pid in "${BACKGROUND_PIDS[@]}"; do
        kill "$pid" 2>/dev/null && info "Killed background process $pid"
    done

    # Print partial summary with whatever we have so far
    section "PARTIAL SUMMARY (interrupted)"
    print_summary   # reuse the same summary function

    info "Full log saved to: ${LOGFILE}"
    exit 130
}

trap cleanup INT TERM
```

Background PIDs are tracked in the `BACKGROUND_PIDS` array — nmap full scan, UDP scan, etc. get appended when launched. On Ctrl+C:
1. All background processes are killed (no orphan nmap eating CPU)
2. A partial summary is printed with whatever was found so far
3. The log file is still complete up to the interrupt point
4. Exit code 130 (standard for SIGINT)

### Quiet vs. Verbose Terminal Output

During the run, the terminal should be **scannable** — the user glances at it and immediately sees what matters. This means:

**Shown in terminal:**
- Banner
- Progress lines (`[Phase 2/5] [Module 3/14: HTTP]`)
- Notification boxes (FINDING / WARNING / CRITICAL)
- Final summary

**Hidden from terminal (log only):**
- Raw nxc output lines
- feroxbuster/ffuf progress bars
- nmap verbose output
- Individual grep/parse steps
- Debug-level info messages

Implementation: modules use `log_verbose()` for tool output (goes to log file only) and `notify_*()` for findings (goes to both terminal and log):

```bash
log_verbose() {
    echo "$@" >> "$LOGFILE"
}
```

This keeps the terminal clean even when 20+ modules run. The user sees a stream of progress lines and notification boxes — nothing else. If they want the raw output, it's in `recon/zbulim.log`.

### Nmap output display

When the full TCP scan completes, we cat the `.nmap` file directly:

```bash
echo -e "${CYAN}── Full TCP Scan Results (.nmap) ──${RESET}"
cat "${OUTDIR}/tcp-allports.nmap"
```

This gives the user exactly what they asked for — the raw nmap output — while the tool continues to Phase 3.

### Final Summary

At the end, a consolidated summary that shows everything at a glance:

```
╔═══════════════════════════════════════════════════════╗
║                 ZBULIM — SCAN SUMMARY                 ║
╠═══════════════════════════════════════════════════════╣
║  Target    : 10.10.10.10                              ║
║  Hostname  : box                                      ║
║  Domain    : box.htb                                  ║
║  TCP Ports : 22, 80, 445                              ║
║  UDP Ports : 161                                      ║
║                                                       ║
║  ── HTTP ─────────────────────────────────────────    ║
║  Domain      : box.htb                                ║
║  Vhosts      : dev.box.htb, admin.box.htb             ║
║  Dirs (box.htb)       : /login, /api, /uploads        ║
║  Dirs (dev.box.htb)   : /upload, /git                 ║
║  Dirs (admin.box.htb) : /dashboard, /config           ║
║  Tech        : Apache 2.4.52, PHP 8.1                 ║
║                                                       ║
║  ── SMB ──────────────────────────────────────────    ║
║  Auth        : null session                           ║
║  Shares      : Public (RW), Data (R)                  ║
║  Loot        : 3 files → loot/                        ║
║  Signing     : NOT REQUIRED (relay possible)          ║
║                                                       ║
║  ── FTP ──────────────────────────────────────────    ║
║  Anonymous   : YES (READ + WRITE on /upload)          ║
║  Files       : 4 downloaded → loot/ftp/               ║
║                                                       ║
║  ── DNS ──────────────────────────────────────────    ║
║  Zone Xfer   : SUCCESS — 23 records                   ║
║  Subdomains  : ns1, mail, dev, staging                ║
║                                                       ║
║  ── NFS ──────────────────────────────────────────    ║
║  Exports     : /home (no_root_squash!)                ║
║  mount -t nfs 10.10.10.10:/home /mnt/nfs              ║
║                                                       ║
║  ── SNMP ─────────────────────────────────────────    ║
║  Community   : public (v2c)                           ║
║  Users       : root, www-data, admin                  ║
║  Processes   : apache2, mysql, cron (3 interesting)   ║
║                                                       ║
║  ── Redis ────────────────────────────────────────    ║
║  Auth        : NONE (no password!)                    ║
║  Keys        : 14 keys in db0                         ║
║  Writable    : CONFIG SET works                       ║
║                                                       ║
║  ── MSSQL ────────────────────────────────────────    ║
║  Auth        : sa:"" (empty password)                 ║
║  xp_cmdshell : ENABLED                                ║
║                                                       ║
║  ── Users (merged) ───────────────────────────────    ║
║  12 unique → recon/users.txt                          ║
║  Sources: SMB, SNMP, SMTP, LDAP                       ║
║                                                       ║
║  ── Hashes ───────────────────────────────────────    ║
║  AS-REP  : 1 hash → recon/asreproast.txt              ║
║  Kerberos: 2 hashes → recon/kerberoast.txt            ║
║                                                       ║
║  ── Files Generated ──────────────────────────────    ║
║  recon/users.txt             (12 users)               ║
║  recon/shares-null.txt                                ║
║  recon/vhosts.txt            (2 vhosts)               ║
║  recon/ferox-80.txt          (47 paths)               ║
║  recon/ferox-dev.box.htb.txt (23 paths)               ║
║  recon/dns-axfr.txt          (zone transfer)          ║
║  recon/snmpwalk.txt          (full walk)              ║
║  recon/snmp-users.txt        (extracted users)        ║
║  recon/redis-keys.txt        (key dump)               ║
║  recon/nfs-exports.txt                                ║
║  loot/                       (3 SMB + 4 FTP files)    ║
║  nmap/                       (all scans)              ║
║                                                       ║
║  Elapsed: 4m32s                                       ║
╚═══════════════════════════════════════════════════════╝
```

---

## Implementation Priority

### Phase 1 — Low-Hanging (implement first)

These are the modules that matter most and have the highest ROI:

1. **Modularize existing code** — extract common.sh, scan.sh, port_smb.sh, port_ldap.sh, port_kerberos.sh from current monolith
2. **Quick scan → full scan flow** — add top-1000 foreground scan before the background full scan
3. **`port_http.sh`** — the biggest gap:
   - Domain extraction from nmap redirect/SSL cert
   - Auto /etc/hosts update for domain
   - ffuf vhost enumeration
   - feroxbuster per vhost
   - Auto /etc/hosts update for vhosts
4. **`port_dns.sh`** — zone transfer, basic queries, subdomain brute
5. **`port_snmp.sh`** — community brute + targeted OID walks + auto-parse users/processes
6. **`port_nfs.sh`** — showmount + rpcinfo + nmap nfs-ls
7. **`port_ftp.sh`** — anon check + file listing + auto-download + writable check
8. **`port_ssh.sh`** — auth methods + version flagging
9. **`port_rdp.sh`** — add rdp-ntlm-info (domain leak) + rdp-enum-encryption
10. **`port_mssql.sh`** — add default creds + ms-sql-ntlm-info + xp_cmdshell check
11. **`port_redis.sh`** — no-auth check, INFO, KEYS, CONFIG (very common HTB vector)
12. **Notification system** — `notify_finding`, `notify_warning`, `notify_critical`
13. **Progress line** — `[Phase X/5] [Module Y/N: name] [Elapsed]` before each module
14. **Log file** — tee all output to `recon/zbulim.log`, verbose tool output goes to log only
15. **Ctrl+C trap** — kill background processes, print partial summary, clean exit
16. **Quiet terminal** — only progress lines + notification boxes shown; raw output in log
17. **Enhanced summary** — the consolidated report at the end
18. **`install.sh`** — apt install all dependencies

### Phase 2 — Mid-Hanging (implement second)

1. **`port_smtp.sh`** — VRFY/RCPT/EXPN user enum, open relay, NTLM info
2. **`port_mysql.sh`** — default creds, UDF check, file read/write check
3. **`port_postgresql.sh`** — default creds, superuser check, COPY PROGRAM RCE check
4. **`port_rpc.sh`** — rpcdump, interesting named pipes (spoolss/PrintNightmare)
5. **`port_vnc.sh`** — no-auth check, version, small brute
6. **`port_ajp.sh`** — Ghostcat detection, AJP methods
7. **`port_mongodb.sh`** — no-auth check, list databases/collections
8. **Better domain detection** — handle edge cases (multiple domains, subdomains in cert SAN)
9. **`--web-only`, `--smb-only` flags** — for targeted re-runs on specific services
10. **Resume capability** — detect existing output files, skip completed modules
11. **Configurable wordlists via env vars or flags** — `ZBULIM_DIR_WORDLIST`, `ZBULIM_VHOST_WORDLIST`

### Phase 3 — High-Hanging (only if needed)

1. Parallel module execution (multiple port modules in background)
2. Config file (`~/.zbulim.conf`) for persistent settings
3. `--aggressive` flag for deeper scans (nikto, longer wordlists)
4. Automatic CVE suggestion based on service versions

---

## Default Wordlists (Kali paths)

| Purpose | Default Path |
|---------|-------------|
| Dir enum | `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` |
| Vhost enum | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt` |
| Users (kerbrute) | `/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt` |
| SNMP community | `/usr/share/seclists/Discovery/SNMP/snmp.txt` |
| Dir enum fallback | `/usr/share/wordlists/dirb/common.txt` |

All wordlists should be overridable via env vars:
```bash
ZBULIM_WL_DIRS="/path/to/custom.txt" zbulim 10.10.10.10
```

---

## Domain Detection — Detailed Logic

This is the most important new piece. The function `detect_domain()` in `port_http.sh`:

```
Input: TARGET IP, PORT, nmap output files
Output: DOMAIN variable (e.g., "box.htb"), or empty

Priority order:
1. Parse nmap .nmap file for redirect:
   grep -oP 'redirect to https?://\K[^/:\s]+' tcp-targeted.nmap
   → Matches: "Did not follow redirect to http://box.htb/"
   → Matches: "Requested resource was https://box.htb/login"

2. Parse nmap .nmap file for SSL cert:
   grep -oP 'commonName=\K[^\s/]+' tcp-targeted.nmap
   grep -oP 'DNS:\K[^\s,]+' tcp-targeted.nmap
   → Matches: "Subject: CN=box.htb"
   → Matches: "Subject Alternative Name: DNS:box.htb, DNS:*.box.htb"

3. Use DOMAIN from SMB module (if already detected via nxc):
   → Already set by port_smb.sh

4. Check whatweb output for domain:
   grep -oP 'RedirectLocation\[https?://\K[^/]+' whatweb-PORT.txt

5. No domain found:
   → Dir enum on http://TARGET:PORT (IP only)
   → Skip vhost enum (can't vhost-brute without a domain)
   → warn user: "No domain detected. Add manually to /etc/hosts and re-run with --skip-nmap"
```

---

## /etc/hosts Management

The current tool already manages /etc/hosts for SMB. Extend this:

```bash
# In common.sh
add_to_hosts() {
    local ip="$1"
    local names="$2"  # space-separated: "box.htb dev.box.htb"

    # Check each name — only add if not already present
    local to_add=""
    for name in $names; do
        if ! grep -qP "\\b${name}\\b" /etc/hosts 2>/dev/null; then
            to_add="$to_add $name"
        fi
    done

    if [[ -n "$to_add" ]]; then
        # Check if IP line already exists → append names to it
        if grep -qP "^${ip}\\s" /etc/hosts 2>/dev/null; then
            # Append new names to existing line
            sed -i "s/^${ip}\\s.*$/& ${to_add}/" /etc/hosts
        else
            echo "${ip}    ${to_add}" | sudo tee -a /etc/hosts > /dev/null
        fi
        notify_finding "/etc/hosts updated" "${ip} → ${to_add}"
    fi
}
```

This prevents duplicate entries and consolidates all names for one IP on a single line.

---

## Key Design Decisions

1. **Stay in bash** — no Python, no external frameworks. OSCP-friendly, stock Kali.
2. **Port-based, not OS-based** — modules fire based on open ports, period.
3. **Quick scan first** — start enumerating in ~10 seconds, not 2+ minutes.
4. **Show, don't wait** — notify findings as they happen, continue working.
5. **Don't replace the operator** — surface findings, let the human think.
6. **One hosts line per IP** — consolidate domain + vhosts on one /etc/hosts line.
7. **Modules are self-contained** — each can be tested/run independently.
8. **Existing SMB/LDAP/Kerberos logic is kept** — it's already solid, just needs to be extracted into modules.

---

## install.sh — Dependencies

```bash
#!/usr/bin/env bash
set -e

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo ./install.sh"
    exit 1
fi

echo "[*] Installing zbulim dependencies..."

# Core tools (apt)
apt-get update
apt-get install -y \
    nmap \
    netexec \
    seclists \
    feroxbuster \
    ffuf \
    whatweb \
    dnsrecon \
    snmp \
    snmp-mibs-downloader \
    onesixtyone \
    nfs-common \
    ntpdate \
    nikto \
    smtp-user-enum \
    redis-tools \
    python3-impacket \
    gobuster \
    mongosh

# Download SNMP MIBs (makes snmpwalk output human-readable)
download-mibs 2>/dev/null || true
# Fix snmp.conf to allow MIB loading
sed -i 's/^mibs :$/# mibs :/' /etc/snmp/snmp.conf 2>/dev/null || true

# kerbrute (not in apt — install from GitHub releases)
if ! command -v kerbrute &>/dev/null; then
    echo "[*] Installing kerbrute..."
    KERB_URL="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64"
    curl -sL "$KERB_URL" -o /usr/local/bin/kerbrute
    chmod +x /usr/local/bin/kerbrute
fi

# Install zbulim + modules
DEST="/usr/local/bin/zbulim"
cp zbulim "$DEST"
chmod +x "$DEST"

MODDIR="/usr/local/share/zbulim/modules"
mkdir -p "$MODDIR"
cp modules/*.sh "$MODDIR/"

echo "[+] zbulim installed → $DEST"
echo "[+] Modules installed → $MODDIR"
echo "[+] Dependencies installed. Run: zbulim <target>"
```

---

## Testing Strategy (on Kali, not here)

1. **Unit test each module** — run against a known HTB retired box with predictable ports
2. **Test domain detection** — use a box with HTTP redirect (e.g., any HTB box with `.htb` domain)
3. **Test vhost workflow end-to-end** — detect domain → ffuf → feroxbuster per vhost → verify /etc/hosts
4. **Test on pure Linux box** (only SSH+HTTP) — confirm no errors, SMB/AD modules gracefully skip
5. **Test on pure AD box** — confirm existing functionality preserved
6. **Test --skip-nmap** — verify resume behavior works
7. **Test multi-target** — `zbulim 10.10.10.1 10.10.10.2` still works with per-target dirs

---

## What NOT to Do (rabbit holes to avoid)

- No interactive mode — keep it fire-and-forget
- No web dashboard or HTML reports — text output is fine for OSCP
- No automatic exploitation — recon only
- No custom nmap scripts — use existing NSE scripts
- No proxy/tor support — not needed for OSCP labs
- No parallel module execution in Phase 1 — get it working sequentially first, optimize later
- No credential spraying — that's a separate tool's job
