# Fail2Ban Implementation & Configuration Guide

**Comprehensive Multi-Distribution, Multi-Service Reference for Linux Servers**

---

## Table of Contents

1. [Introduction to Fail2Ban](#1-introduction-to-fail2ban)
2. [How Fail2Ban Works](#2-how-fail2ban-works)
3. [Supported Distributions & Package Managers](#3-supported-distributions--package-managers)
4. [Prerequisites](#4-prerequisites)
5. [Installation](#5-installation)
6. [Core Configuration Files](#6-core-configuration-files)
7. [Firewall Backend Configuration](#7-firewall-backend-configuration)
8. [Global Daemon & Jail Defaults](#8-global-daemon--jail-defaults)
9. [SSH Protection](#9-ssh-protection)
10. [Web Server Protection (NGINX & Apache)](#10-web-server-protection-nginx--apache)
11. [FTP Protection](#11-ftp-protection)
12. [Mail Server Protection (Postfix, Dovecot, Exim)](#12-mail-server-protection-postfix-dovecot-exim)
13. [Database Protection (MySQL/MariaDB)](#13-database-protection-mysqlmariadb)
14. [WordPress Protection](#14-wordpress-protection)
15. [cPanel/WHM Protection](#15-cpanelwhm-protection)
16. [Docker Considerations](#16-docker-considerations)
17. [VPN Service Considerations](#17-vpn-service-considerations)
18. [Custom Jails & Filter Writing](#18-custom-jails--filter-writing)
19. [Email & Alert Notifications](#19-email--alert-notifications)
20. [Log File Requirements & Distro Path Reference](#20-log-file-requirements--distro-path-reference)
21. [Testing and Verification](#21-testing-and-verification)
22. [Troubleshooting Common Issues](#22-troubleshooting-common-issues)
23. [Best Practices, Security & Production Hardening](#23-best-practices-security--production-hardening)
24. [Maintenance & Ongoing Operations](#24-maintenance--ongoing-operations)
25. [Quick Reference: Common Commands](#25-quick-reference-common-commands)
26. [Appendix A: Full Reference `jail.local` (UFW backend)](#26-appendix-a-full-reference-jaillocal-ufw-backend)
27. [Appendix B: Full Reference `jail.local` (firewalld backend)](#27-appendix-b-full-reference-jaillocal-firewalld-backend)

---

## 1. Introduction to Fail2Ban

Fail2Ban is an intrusion-prevention framework written in Python that monitors log files for malicious activity — repeated failed logins, automated scanning, brute-force attempts, and similar abuse patterns. When it detects a matching pattern a configurable number of times within a defined time window, it automatically instructs the system firewall to block the offending IP address for a set duration.

**Key benefits:**
- Reduces brute-force attack surface automatically, without manual intervention
- Ships with ready-made filters for dozens of services (SSH, web servers, mail servers, FTP, databases, and more)
- Works across all major Linux distributions and firewall backends
- Supports progressive/escalating ban times for repeat offenders
- Integrates with existing firewall tooling rather than replacing it
- Can alert administrators by email when bans occur

This guide covers deployment across **Debian, Ubuntu, RHEL, CentOS, Rocky Linux, AlmaLinux, Fedora, and openSUSE**, protecting **SSH, NGINX, Apache, FTP daemons, mail servers, databases, WordPress, cPanel, Docker hosts, and VPN services**, using **iptables, UFW, firewalld, or nftables** as the enforcement backend.

---

## 2. How Fail2Ban Works

Fail2Ban's architecture is built from three cooperating pieces:

| Component | Role |
|---|---|
| **Filter** | A regex pattern (in `/etc/fail2ban/filter.d/`) that identifies a failed-attempt log line |
| **Jail** | Binds a filter to a service, a log path, and thresholds (`maxretry`, `findtime`, `bantime`) |
| **Action** | The script (in `/etc/fail2ban/action.d/`) executed when a jail's threshold is crossed — a firewall ban, optionally combined with an email alert |

```text
Attacker or bot makes repeated failed login/auth attempts
                    │
                    ▼
Log file (auth.log, secure, nginx error.log, journald, ...)
                    │   Fail2Ban tails the log continuously
                    ▼
Filter — regex match against known failure patterns
                    │   match count tracked per source IP
                    ▼
Jail — `maxretry` exceeded within `findtime` window
                    │
                    ▼
Action — firewall rule inserted (iptables / ufw / firewalld / nftables)
         optionally: email alert sent
                    │
                    ▼
IP blocked for `bantime` (or longer, if bantime.increment is set)
```

Fail2Ban keeps a persistent record of bans in a local SQLite database (`/var/lib/fail2ban/fail2ban.sqlite3`), letting it restore active bans after the **Fail2Ban service** restarts. This is separate from whether firewall rules persist across a **full server reboot** — that depends on the firewall backend's own persistence mechanism (covered per-backend in [§7](#7-firewall-backend-configuration)).

---

## 3. Supported Distributions & Package Managers

| Distribution Family | Package Manager | Default Firewall Tool | Notes |
|---|---|---|---|
| Debian, Ubuntu | `apt` | `ufw` (Ubuntu) / raw `iptables`-nft (Debian) | Fail2Ban is in the default repos |
| RHEL, CentOS Stream, Rocky Linux, AlmaLinux (8/9) | `dnf` | `firewalld` (nftables-backed) | Requires **EPEL** repository |
| CentOS 7 | `yum` | `firewalld` or `iptables` | Requires EPEL |
| Fedora | `dnf` | `firewalld` | In default repos |
| openSUSE / SLES | `zypper` | `firewalld` or SuSEfirewall2 (legacy) | In default repos |

This guide gives the equivalent command for each step on every family. Where a step is identical across distributions (most `fail2ban-client` and `systemctl` usage), it is shown once.

---

## 4. Prerequisites

| Requirement | Details |
|---|---|
| Access | Root or `sudo`/`wheel` group privileges |
| Firewall | One of `iptables`, `ufw`, `firewalld`, or `nftables` installed and active |
| Services | The services you intend to protect (SSH, NGINX, Apache, FTP, mail, DB, etc.) already installed and running |
| Logging | `rsyslog` or `systemd-journald` operational; Fail2Ban needs log read access |
| Network | Your own trusted/management IP address(es), known in advance |
| Out-of-band access | Console, VNC, or IPMI/iDRAC/iLO access independent of SSH, in case of misconfiguration |
| RHEL-family only | EPEL repository enabled (`dnf install epel-release` / `yum install epel-release`) |

> ⚠️ **Critical safety note:** Confirm you have an access method that doesn't depend on SSH (cloud console, VNC, physical/IPMI access) before enabling aggressive SSH jails on **any** distribution. This is the single most common cause of accidental admin lockouts, regardless of OS.

---

## 5. Installation

### 5.1 Debian / Ubuntu

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install fail2ban -y
```

### 5.2 RHEL / CentOS Stream / Rocky Linux / AlmaLinux (8 & 9)

```bash
sudo dnf install epel-release -y
sudo dnf install fail2ban fail2ban-firewalld -y
```

### 5.3 CentOS 7

```bash
sudo yum install epel-release -y
sudo yum install fail2ban -y
```

### 5.4 Fedora

```bash
sudo dnf install fail2ban fail2ban-firewalld -y
```

### 5.5 openSUSE / SLES

```bash
sudo zypper install fail2ban -y
```

### 5.6 Verify installation (all distributions)

```bash
systemctl status fail2ban
```

### 5.7 Create local configuration overrides

Fail2Ban ships with `.conf` files that are **overwritten on package updates**, on every distribution. Never edit `.conf` files directly — always copy them to `.local` equivalents, which take precedence and survive upgrades.

```bash
sudo cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

### 5.8 Enable and start the service (all distributions)

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
sudo systemctl status fail2ban
```

---

## 6. Core Configuration Files

```bash
sudo ls -l /etc/fail2ban/
```

| Path | Purpose |
|---|---|
| `fail2ban.conf` / `fail2ban.local` | Daemon-level settings: log level, log target, socket/pid paths, database |
| `jail.conf` / `jail.local` | Jail definitions — which services are protected and how |
| `jail.d/` | Drop-in directory for per-service jail overrides (recommended over editing `jail.local` directly) |
| `filter.d/` | Regex filters used to match failure patterns per service |
| `action.d/` | Scripts defining what happens on ban/unban (firewall rule, email, etc.) — includes backend-specific actions like `firewallcmd-ipset.conf`, `ufw.conf`, `iptables-multiport.conf`, `nftables-multiport.conf` |
| `paths-debian.conf`, `paths-fedora.conf`, `paths-opensuse.conf`, `paths-common.conf` | OS-specific default log path definitions, auto-selected by Fail2Ban based on detected distro |

**Recommended convention (all distros):** keep global defaults in `jail.local`, and put each service's jail in its own file under `jail.d/` (e.g. `jail.d/sshd.conf`, `jail.d/nginx.conf`). This keeps changes isolated and easier to review or roll back, and avoids large merge conflicts in a single monolithic file.

---

## 7. Firewall Backend Configuration

Fail2Ban doesn't implement its own firewall — it drives whichever backend you already use. Pick the section matching your environment and set `banaction` accordingly in `jail.local`'s `[DEFAULT]` section.

### 7.1 iptables (classic, any distro)

```ini
[DEFAULT]
banaction          = iptables-multiport
banaction_allports = iptables-allports
```

- `iptables-multiport`: efficient for jails restricted to specific ports (SSH, HTTP/S)
- `iptables-allports`: blocks the offending IP on **all** ports — appropriate for `recidive` or high-confidence jails
- Rules inserted by Fail2Ban are **not persistent across reboot** unless you separately save them with `iptables-save`/`netfilter-persistent` (Debian/Ubuntu) — Fail2Ban itself re-applies bans from its database on service restart, which is usually sufficient.

### 7.2 UFW (Ubuntu default, also usable on Debian)

```ini
[DEFAULT]
banaction          = ufw
banaction_allports = ufw
```

- Requires `ufw` to be installed and **enabled** (`sudo ufw enable`) before Fail2Ban can insert rules.
- UFW already persists its own ruleset across reboot; Fail2Ban-inserted bans are dynamic and are re-applied from Fail2Ban's database when the service restarts, not from UFW's saved rules.

### 7.3 firewalld (RHEL/CentOS/Rocky/Alma/Fedora default)

```ini
[DEFAULT]
banaction          = firewallcmd-ipset
banaction_allports = firewallcmd-ipset
```

- `firewallcmd-ipset` is the **recommended** action — it uses an `ipset` for ban storage, which scales far better than `firewallcmd-rich-rules` when ban counts grow into the hundreds or thousands.
- Install the `fail2ban-firewalld` package (see [§5.2](#52-rhel--centos-stream--rocky-linux--almalinux-8--9)) for tighter integration.
- Confirm firewalld is running: `sudo firewall-cmd --state`.
- Bans are added to firewalld's runtime configuration; firewalld's own persistence settings determine reboot survival, but as with other backends, Fail2Ban reconciles active bans from its own database on service start regardless.

### 7.4 nftables (modern Debian/Ubuntu default substrate, or standalone)

```ini
[DEFAULT]
banaction          = nftables-multiport
banaction_allports = nftables-allports
```

- Recent Debian (11+) and Ubuntu (20.04+) implement `iptables` as a compatibility shim over `nftables` (`iptables-nft`) — the `iptables-multiport` action still works in this case. Use the native `nftables-multiport` action only if you manage rules with `nft` directly rather than through the `iptables` command.
- RHEL 8/9's `firewalld` also uses an nftables backend internally — in that case, prefer the `firewallcmd-ipset` action from [§7.3](#73-firewalld-rhelcentosrockyalmafedora-default) rather than driving `nftables` directly, to avoid the two tools fighting over the same rule tables.

### 7.5 Choosing a backend

| Scenario | Recommended `banaction` |
|---|---|
| Ubuntu/Debian, UFW already in use | `ufw` |
| Ubuntu/Debian, no UFW, managing iptables directly | `iptables-multiport` |
| RHEL/CentOS/Rocky/Alma/Fedora | `firewallcmd-ipset` |
| Pure nftables shop (no firewalld/ufw layer) | `nftables-multiport` |
| Docker host (any distro) | See [§16](#16-docker-considerations) — standard actions above often need adjustment |

---

## 8. Global Daemon & Jail Defaults

### 8.1 Daemon settings — `fail2ban.local`

```ini
[Definition]
loglevel     = INFO
logtarget    = /var/log/fail2ban.log
syslogsocket = auto
socket       = /var/run/fail2ban/fail2ban.sock
pidfile      = /var/run/fail2ban/fail2ban.pid

# Persistent ban database — lets Fail2Ban restore active bans
# after the service restarts, on any distro/backend
dbfile       = /var/lib/fail2ban/fail2ban.sqlite3
dbpurgeage   = 1d
dbmaxmatches = 10
```

| Option | Purpose |
|---|---|
| `loglevel` | Verbosity: `CRITICAL`, `ERROR`, `WARNING`, `NOTICE`, `INFO`, `DEBUG` |
| `logtarget` | Where Fail2Ban writes its own log |
| `dbfile` | Set to `:memory:` to disable persistence (not recommended in production) |
| `dbpurgeage` | How long ban history is retained in the database |

### 8.2 Jail-wide defaults — `jail.local`

```ini
[DEFAULT]
# ---------------------------
# BASIC SAFETY
# ---------------------------
allowipv6 = auto

# IMPORTANT: prevent locking out trusted networks
ignoreip  = 127.0.0.1/8 ::1 YOUR_TRUSTED_IP_OR_RANGE

backend     = systemd
usedns      = warn
logencoding = auto

# ---------------------------
# GLOBAL BAN POLICY
# ---------------------------
bantime  = 24h
findtime = 10m
maxretry = 3

# Progressive banning — doubles ban time per repeat offense, up to a cap
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 7d

# ---------------------------
# FIREWALL BACKEND — pick the line matching your environment (see §7)
# ---------------------------
banaction          = ufw
banaction_allports = ufw
```

| Option | Purpose |
|---|---|
| `ignoreip` | Space-separated list of IPs/CIDRs/hostnames Fail2Ban will never ban |
| `backend` | Log-reading method: `auto`, `systemd`, `polling`, `pyinotify`. `systemd` works on all journald-based distros (Debian 9+, Ubuntu 16.04+, all current RHEL/Fedora/openSUSE) |
| `usedns` | `yes`/`no`/`warn`/`raw` — whether to resolve hostnames in log lines to IPs; set `no` for performance if not needed |
| `bantime.increment` | Enables escalating ban durations for repeat offenders |
| `banaction` | Which action script handles the actual firewall block — see [§7](#7-firewall-backend-configuration) |

> Replace `YOUR_TRUSTED_IP_OR_RANGE` with your real admin/VPN/CI IP(s) **before** restarting the service, on every server you deploy this to.

---

## 9. SSH Protection

Create a dedicated drop-in file:

```bash
sudo nano /etc/fail2ban/jail.d/sshd.conf
```

```ini
[sshd]
enabled  = true
port     = ssh
filter   = sshd
mode     = aggressive
maxretry = 3
findtime = 10m
bantime  = 7d
```

**Field reference:**

| Option | Purpose |
|---|---|
| `port` | Service name or port associated with the ban action |
| `filter` | Regex filter file (in `filter.d/`) used to match log lines |
| `mode` | `normal`, `ddos`, `extra`, or `aggressive` — `aggressive` catches more patterns (invalid users, protocol errors) at the cost of slightly more false positives |
| `maxretry` | Failures allowed before a ban |
| `findtime` | Time window in which `maxretry` failures must occur |
| `bantime` | Duration of the ban once triggered |

**Distro-specific `logpath`** (omit entirely if using `backend = systemd`, which works everywhere):

| Distribution | SSH log path |
|---|---|
| Debian, Ubuntu | `/var/log/auth.log` |
| RHEL, CentOS, Rocky, AlmaLinux, Fedora | `/var/log/secure` |
| openSUSE / SLES | `/var/log/messages` (or journal) |

```ini
# Example for RHEL-family with a flat log file instead of journald:
[sshd]
enabled  = true
port     = ssh
filter   = sshd
mode     = aggressive
logpath  = /var/log/secure
maxretry = 3
findtime = 10m
bantime  = 7d
```

---

## 10. Web Server Protection (NGINX & Apache)

### 10.1 NGINX

NGINX-specific filters ship with Fail2Ban but are **disabled by default**. They guard against credential brute-forcing on auth-protected locations, bot/vulnerability scanning, and malformed/oversized requests.

```bash
sudo nano /etc/fail2ban/jail.d/nginx.conf
```

```ini
[nginx-http-auth]
enabled  = true
port     = http,https
maxretry = 3
findtime = 10m
bantime  = 1d

[nginx-botsearch]
enabled  = true
port     = http,https
maxretry = 2
findtime = 10m
bantime  = 7d

[nginx-bad-request]
enabled  = true
port     = http,https
maxretry = 10
findtime = 10m
bantime  = 1d

[nginx-limit-req]
enabled  = true
port     = http,https
maxretry = 10
findtime = 10m
bantime  = 1d
```

| Jail | Protects against |
|---|---|
| `nginx-http-auth` | Repeated failed logins on HTTP Basic Auth-protected locations |
| `nginx-botsearch` | Automated bots probing common exploit paths (`/wp-login.php`, `/phpmyadmin`, etc.) |
| `nginx-bad-request` | Malformed, oversized, or malicious-looking HTTP requests |
| `nginx-limit-req` | Clients exceeding a configured `limit_req` rate-limiting zone (zone must already be defined in your NGINX config) |

**Log paths:** `/var/log/nginx/error.log` and `/var/log/nginx/access.log` on all distributions (NGINX uses the same path convention everywhere it's packaged). Multi-vhost setups should consolidate `logpath` with a glob (`/var/log/nginx/*/error.log`) or run separate jail instances per log.

### 10.2 Apache

Apache filters also ship disabled by default.

```bash
sudo nano /etc/fail2ban/jail.d/apache.conf
```

```ini
[apache-auth]
enabled  = true
port     = http,https
maxretry = 3
findtime = 10m
bantime  = 1d

[apache-badbots]
enabled  = true
port     = http,https
maxretry = 2
findtime = 10m
bantime  = 7d

[apache-noscript]
enabled  = true
port     = http,https
maxretry = 6
findtime = 10m
bantime  = 1d

[apache-overflows]
enabled  = true
port     = http,https
maxretry = 2
findtime = 10m
bantime  = 7d
```

| Distribution | Apache log path |
|---|---|
| Debian, Ubuntu | `/var/log/apache2/error.log` |
| RHEL, CentOS, Rocky, AlmaLinux, Fedora | `/var/log/httpd/error_log` |
| openSUSE / SLES | `/var/log/apache2/error_log` |

```ini
# Example logpath override for RHEL-family:
[apache-auth]
enabled  = true
logpath  = /var/log/httpd/error_log
maxretry = 3
```

---

## 11. FTP Protection

| Daemon | Jail name | Typical log path |
|---|---|---|
| vsftpd | `vsftpd` | `/var/log/vsftpd.log` |
| ProFTPD | `proftpd` | `/var/log/proftpd/proftpd.log` |
| Pure-FTPd | `pure-ftpd` | `/var/log/syslog` (Debian/Ubuntu) or `/var/log/messages` (RHEL-family) |

```bash
sudo nano /etc/fail2ban/jail.d/ftp.conf
```

```ini
[vsftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
filter   = vsftpd
logpath  = /var/log/vsftpd.log
maxretry = 3
bantime  = 1d

[proftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
filter   = proftpd
logpath  = /var/log/proftpd/proftpd.log
maxretry = 3
bantime  = 300

[pure-ftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
filter   = pure-ftpd
logpath  = /var/log/syslog
maxretry = 3
bantime  = 1d
```

---

## 12. Mail Server Protection (Postfix, Dovecot, Exim)

| Service | Jail name | Debian/Ubuntu log path | RHEL-family log path |
|---|---|---|---|
| Postfix (SMTP) | `postfix`, `postfix-sasl` | `/var/log/mail.log` | `/var/log/maillog` |
| Dovecot (IMAP/POP3) | `dovecot` | `/var/log/mail.log` | `/var/log/maillog` |
| Exim | `exim` | `/var/log/exim4/mainlog` | `/var/log/exim/main.log` |

```bash
sudo nano /etc/fail2ban/jail.d/mail.conf
```

```ini
[postfix]
enabled  = true
port     = smtp,465,submission
filter   = postfix
logpath  = /var/log/mail.log
maxretry = 3
bantime  = 1d

[postfix-sasl]
enabled  = true
port     = smtp,465,submission,imap,imaps,pop3,pop3s
filter   = postfix-sasl
logpath  = /var/log/mail.log
maxretry = 3
bantime  = 1d

[dovecot]
enabled  = true
port     = imap,imaps,pop3,pop3s
filter   = dovecot
logpath  = /var/log/mail.log
maxretry = 3
bantime  = 1d
```

> On RHEL-family systems, change `logpath` to `/var/log/maillog` in each jail above.

---

## 13. Database Protection (MySQL/MariaDB)

Fail2Ban doesn't ship a default MySQL/MariaDB filter in all distributions, so this typically requires a small custom filter. First, ensure failed-login logging is enabled in your database's error log (`log_error_verbosity` / `log_warnings` settings in `my.cnf`).

```bash
sudo nano /etc/fail2ban/filter.d/mysqld-auth.conf
```

```ini
[Definition]
failregex = ^.*\[Warning\] Access denied for user .* from '<HOST>'.*$
ignoreregex =
```

```bash
sudo nano /etc/fail2ban/jail.d/mysql.conf
```

```ini
[mysqld-auth]
enabled  = true
port     = 3306
filter   = mysqld-auth
logpath  = /var/log/mysql/error.log
maxretry = 5
findtime = 10m
bantime  = 1h
```

| Distribution | Typical MySQL/MariaDB error log path |
|---|---|
| Debian, Ubuntu | `/var/log/mysql/error.log` |
| RHEL, CentOS, Rocky, AlmaLinux, Fedora (MariaDB) | `/var/log/mariadb/mariadb.log` |

> **Test the filter with `fail2ban-regex` before enabling the jail** (see [§18.3](#183-testing-a-custom-filter)) — database log formats vary noticeably between versions of MySQL and MariaDB.
>
> If the database is only ever accessed from application servers on a private network, prefer firewall rules or `bind-address` restrictions over Fail2Ban as the primary control — Fail2Ban here is a supplementary layer, not a substitute for not exposing the DB port publicly.

---

## 14. WordPress Protection

Two approaches, in order of reliability:

### 14.1 Recommended: the `wp-fail2ban` plugin

Install the `wp-fail2ban` plugin on the WordPress site itself. It logs authentication events directly to syslog with proper context (distinguishing real login failures from unrelated 200/404 traffic on `wp-login.php`), which is far more reliable than regex-parsing the web server's access log.

```bash
sudo nano /etc/fail2ban/jail.d/wordpress.conf
```

```ini
[wordpress-hard]
enabled  = true
port     = http,https
filter   = wordpress-hard
logpath  = /var/log/auth.log
maxretry = 3
findtime = 10m
bantime  = 1d

[wordpress-soft]
enabled  = true
port     = http,https
filter   = wordpress-soft
logpath  = /var/log/auth.log
maxretry = 10
findtime = 1h
bantime  = 1d
```

(The `wp-fail2ban` plugin ships its own `wordpress-hard.conf` / `wordpress-soft.conf` filter files for `filter.d/` — install per the plugin's documentation, as exact filenames vary by plugin version.)

### 14.2 Fallback: access-log based filter

If you can't install a plugin (e.g., managed hosting), a simpler filter against the web server's access log catches obvious brute-force patterns, at the cost of more false positives:

```ini
[Definition]
failregex = ^<HOST> -.*"POST /wp-login\.php.*" 200
ignoreregex =
```

This matches successful HTTP responses (200) to `wp-login.php` POSTs — a 200 here doesn't always mean a successful *login*, so tune `maxretry` generously and verify with `fail2ban-regex` before relying on it.

---

## 15. cPanel/WHM Protection

cPanel/WHM servers ship with their own native brute-force protection, **cPHulk**, which can conflict with Fail2Ban if both are banning the same IPs through different mechanisms.

- **If cPHulk is already active:** generally prefer it for cPanel-specific services (cPanel login, webmail, FTP via cPanel) and use Fail2Ban only for services cPHulk doesn't cover, to avoid duplicate/competing ban logic.
- **If running Fail2Ban instead of (or alongside) cPHulk:** disable cPHulk for the services you're handing to Fail2Ban (WHM → Security Center → cPHulk Brute Force Protection) to prevent the two systems fighting over the same firewall rules.

Example jails for cPanel-specific logs, if you choose the Fail2Ban route:

```bash
sudo nano /etc/fail2ban/jail.d/cpanel.conf
```

```ini
[cpanel]
enabled  = true
port     = 2082,2083,2086,2087
filter   = cpanel
logpath  = /usr/local/cpanel/logs/login_log
maxretry = 5
findtime = 10m
bantime  = 1d

[exim]
enabled  = true
port     = smtp,465,submission
filter   = exim
logpath  = /var/log/exim_mainlog
maxretry = 3
bantime  = 1d
```

A minimal custom filter for the cPanel login log, if no built-in filter matches your cPanel version:

```ini
[Definition]
failregex = ^.*\[<HOST>\].*Failed login.*$
ignoreregex =
```

> Always test against your specific cPanel version's actual log format with `fail2ban-regex` (§18.3) — cPanel log formats have changed across major versions.

---

## 16. Docker Considerations

Running Fail2Ban on a host that also runs Docker introduces two distinct problems:

### 16.1 Docker bypasses the standard `INPUT` chain

Docker manipulates `iptables`/`nftables` rules directly, inserting its own `DOCKER`, `DOCKER-USER`, and `DOCKER-ISOLATION` chains. Traffic to a container's **published port** (`-p` flag) is often routed through these chains *before* it reaches the host's normal `INPUT` chain — meaning a ban inserted into `INPUT` by Fail2Ban's default `iptables` action may simply be bypassed for containerized services.

**Fixes:**
- Direct Fail2Ban's ban rule into the `DOCKER-USER` chain specifically, which Docker guarantees not to overwrite (this requires a custom action file based on `iptables-multiport.conf` with the chain changed from `INPUT` to `DOCKER-USER`).
- Alternatively, use the community `ufw-docker` script if running UFW, which patches this exact gap.
- If using `firewalld` (RHEL-family Docker hosts), recent Docker versions integrate more cleanly via firewalld zones — verify with `firewall-cmd --list-all` that container traffic is actually subject to the zone rules you expect.

### 16.2 Don't containerize Fail2Ban itself unless necessary

Fail2Ban needs to (a) read host log files and (b) modify the host's firewall. If you do run it in a container:

```bash
docker run -d --name fail2ban \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v /var/log:/var/log:ro \
  -v /etc/fail2ban:/etc/fail2ban \
  crazymax/fail2ban
```

Running it directly on the host OS (not containerized) remains the simpler and more reliable approach for most setups, since it avoids the host-namespace and capability complications entirely.

---

## 17. VPN Service Considerations

### 17.1 OpenVPN

OpenVPN logs authentication failures when configured with sufficient verbosity (`verb 3` or higher) and using `--auth-user-pass-verify` or a similar auth plugin.

```bash
sudo nano /etc/fail2ban/filter.d/openvpn.conf
```

```ini
[Definition]
failregex = ^.*AUTH_FAILED.*,client.*<HOST>.*$
ignoreregex =
```

```ini
[openvpn]
enabled  = true
port     = 1194
protocol = udp
filter   = openvpn
logpath  = /var/log/openvpn.log
maxretry = 3
bantime  = 1d
```

### 17.2 WireGuard — Fail2Ban is generally not applicable

WireGuard authenticates via cryptographic keys at the network layer before any "login attempt" is logged in the traditional sense — there's no per-attempt failure log line for Fail2Ban to match against by design. For WireGuard, prefer:
- Firewall-level rate limiting on the WireGuard UDP port (e.g., `iptables`/`nftables` connection-rate rules) to blunt scanning/flooding
- Port-knocking or `fwknop` if you want to hide the WireGuard port entirely until a pre-authenticated knock sequence is received
- Restricting the WireGuard port to known source IPs/ranges at the firewall level where feasible

---

## 18. Custom Jails & Filter Writing

### 18.1 Identify a representative log line

Find an actual failed-attempt line from the service's log file you want to protect.

### 18.2 Write the filter

```ini
# /etc/fail2ban/filter.d/myapp.conf
[Definition]
failregex = ^.*Failed login attempt from <HOST>.*$
ignoreregex =
```

### 18.3 Testing a custom filter

**Always dry-run a new or modified filter against real logs before enabling the jail** — this is the most commonly skipped step, and the most common cause of jails that silently do nothing:

```bash
fail2ban-regex /var/log/myapp/app.log /etc/fail2ban/filter.d/myapp.conf
```

This reports how many lines matched, without banning anyone.

### 18.4 Create the jail

```ini
[myapp]
enabled  = true
filter   = myapp
logpath  = /var/log/myapp/app.log
maxretry = 5
findtime = 10m
bantime  = 1d
```

---

## 19. Email & Alert Notifications

### 19.1 Global mail settings — `jail.local` `[DEFAULT]`

```ini
destemail = admin@example.com
sender    = fail2ban@example.com
mta       = sendmail
action    = %(action_mwl)s
```

### 19.2 Built-in action shortcuts

| Shortcut | Behavior |
|---|---|
| `%(action_)s` | Ban only, no email (default) |
| `%(action_mw)s` | Ban + email with a WHOIS lookup of the offending IP |
| `%(action_mwl)s` | Ban + email with WHOIS lookup + matched log lines included |
| `%(action_xarf)s` | Ban + send an X-ARF abuse report to the IP's network provider |

### 19.3 Per-jail override

```ini
[sshd]
enabled = true
...
action  = %(action_mwl)s
```

> Requires a working local MTA (`sendmail`, `postfix`, `msmtp`) or an external relay configured via `mta`. Test mail delivery independently before relying on it for incident alerting.

---

## 20. Log File Requirements & Distro Path Reference

| Service | Debian / Ubuntu | RHEL / CentOS / Rocky / Alma / Fedora | openSUSE / SLES |
|---|---|---|---|
| SSH | `/var/log/auth.log` | `/var/log/secure` | `/var/log/messages` |
| NGINX | `/var/log/nginx/{access,error}.log` | same | same |
| Apache | `/var/log/apache2/error.log` | `/var/log/httpd/error_log` | `/var/log/apache2/error_log` |
| Postfix / Dovecot | `/var/log/mail.log` | `/var/log/maillog` | `/var/log/mail` |
| MySQL/MariaDB | `/var/log/mysql/error.log` | `/var/log/mariadb/mariadb.log` | `/var/log/mysql/mysqld.log` |
| vsftpd | `/var/log/vsftpd.log` | `/var/log/vsftpd.log` | `/var/log/vsftpd.log` |
| Fail2Ban itself | `/var/log/fail2ban.log` (all distros) | | |

**Permissions:** Fail2Ban runs as root and generally has read access to standard `/var/log/` paths by default on every distribution. If logs are relocated or owned by a non-standard user, confirm access:

```bash
sudo ls -l /var/log/auth.log /var/log/nginx/error.log
```

**Log rotation:** confirm `logrotate` (or `journald`'s own rotation settings) covers every log a jail depends on, so Fail2Ban doesn't lose track of file handles after rotation and silently stop matching:

```bash
cat /etc/logrotate.d/fail2ban
```

---

## 21. Testing and Verification

### 21.1 Validate configuration syntax before restarting

```bash
sudo fail2ban-client -t
```

Catches misconfigured `.local`/`jail.d` files before they break the running service. **Run this before every restart, on every distro.**

### 21.2 Restart and check status

```bash
sudo systemctl restart fail2ban
sudo systemctl status fail2ban --no-pager -l
```

### 21.3 Confirm jails are active

```bash
fail2ban-client status
```

```text
Status
|- Number of jail:	5
`- Jail list:	sshd, recidive, nginx-http-auth, nginx-botsearch, nginx-bad-request
```

### 21.4 Inspect an individual jail

```bash
fail2ban-client status sshd
```

```text
Status for the jail: sshd
|- Filter
|  |- Currently failed:	10
|  |- Total failed:	511
|  `- File list:	/var/log/auth.log
`- Actions
   |- Currently banned:	9
   |- Total banned:	77
   `- Banned IP list:	...
```

### 21.5 Test a filter regex against real logs (no bans applied)

```bash
fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf
```

### 21.6 Watch live activity

```bash
sudo tail -f /var/log/fail2ban.log
```

### 21.7 Confirm the ban actually landed at the firewall level

Fail2Ban reporting a ban and the firewall actually enforcing it are two different things — verify both, using the command matching your backend:

```bash
sudo ufw status numbered                 # UFW
sudo iptables -L -n | grep f2b            # iptables (chains typically prefixed f2b-)
sudo firewall-cmd --direct --get-all-rules    # firewalld
sudo nft list ruleset | grep -A2 f2b      # nftables
```

### 21.8 Controlled end-to-end test

From a non-trusted machine or VM, deliberately fail SSH login attempts past your `maxretry` threshold, then confirm the IP appears banned in both `fail2ban-client status sshd` and the firewall rule list above.

---

## 22. Troubleshooting Common Issues

### 22.1 Service fails to start after editing config

```bash
sudo fail2ban-client -t
journalctl -xeu fail2ban --no-pager
```

Common causes: duplicate `[jail]` section headers across files, mismatched indentation, or a `filter =` referencing a file that doesn't exist in `filter.d/`.

### 22.2 Locked out of your own server

```bash
sudo fail2ban-client set sshd unbanip YOUR_IP_ADDRESS
sudo fail2ban-client set recidive unbanip YOUR_IP_ADDRESS
```

If SSH itself is blocked at the firewall level and `fail2ban-client` isn't reachable, use console/VNC/IPMI access to log in locally, then unban via the command above, or temporarily remove the rule directly:

```bash
sudo ufw delete reject from YOUR_IP_ADDRESS              # UFW
sudo firewall-cmd --remove-rich-rule='rule family="ipv4" source address="YOUR_IP_ADDRESS" reject'  # firewalld
```

**Prevention:** always add your own static IP or VPN range to `ignoreip` in `[DEFAULT]` *before* enabling aggressive jails, on every server.

### 22.3 Jail shows 0 failed / 0 banned despite ongoing attacks

- Check `logpath` matches where the service *actually* writes logs on **this specific distro** — this is the single most common cross-distro mistake (e.g. assuming `/var/log/auth.log` on a RHEL-family host where it's `/var/log/secure`).
- Check `backend` isn't silently overriding how the filter reads logs (`systemd` backend ignoring a flat-file `logpath`).
- Run `fail2ban-regex` (§21.5) against the live log to confirm the filter matches current log formatting — formats sometimes change after a service/distro upgrade.

### 22.4 Bans aren't actually blocking traffic

- Confirm `banaction` matches the firewall tool **actually active and enforcing** on this host (§7) — a `firewalld`-default RHEL host with `banaction = ufw` will silently fail.
- Conflicting firewall tools (e.g. both `firewalld` and hand-written `iptables` rules, or Docker's chains per §16) can cause the ban action to no-op or be overridden by a higher-priority `ACCEPT` rule.

### 22.5 Action or filter file not found

```bash
ls /etc/fail2ban/action.d/firewallcmd-ipset.conf   # adjust to your backend's action file
ls /etc/fail2ban/filter.d/
```

If a referenced `.conf` doesn't exist, the jail fails to load — check for typos in `banaction =` or `filter =`, and confirm any required sub-package (e.g. `fail2ban-firewalld` on RHEL-family) is installed.

### 22.6 Email notifications aren't arriving

- Confirm `mta` matches what's actually installed and configured.
- Test mail delivery independently: `echo "test" | mail -s "test" admin@example.com`.
- Check `mail.log`/`maillog` or `journalctl -u postfix` for delivery errors.

---

## 23. Best Practices, Security & Production Hardening

- **Always use `.local`/`jail.d` overrides** — never edit `.conf` files directly, on any distribution.
- **Whitelist trusted IPs first**, before enabling aggressive jails — the single most common cause of accidental lockouts everywhere.
- **Use progressive ban times** (`bantime.increment`) to discourage persistent attackers without permanently banning IPs later reassigned to legitimate users on dynamic-IP networks.
- **Layer the `recidive` jail** to catch attackers spreading attempts thinly across multiple services to dodge individual thresholds.
- **Validate before restarting** — `fail2ban-client -t` before every `systemctl restart fail2ban`, without exception.
- **Confirm out-of-band access** before tightening SSH jail aggressiveness, especially multi-day `bantime` values.
- **Match `maxretry`/`findtime` to the threat model** — public-facing admin panels and SSH warrant tighter thresholds than general web traffic.
- **Test filters before trusting them**, with `fail2ban-regex`, for every custom filter and especially after distro/package upgrades that may change log formats.
- **Pick the correct `banaction` for your actual firewall backend** (§7) — this is the most common cross-distro configuration error.
- **Avoid double-banning systems on the same host.** Don't run Fail2Ban and another brute-force tool (cPHulk, CSF/LFD, DenyHosts) targeting the same service without explicitly deciding which one owns which jail.
- **On Docker hosts**, verify bans actually reach containerized services (§16) — don't assume a default `iptables` action works unmodified.
- **Restrict access to Fail2Ban's own config and socket files** — keep `jail.local`/`fail2ban.local` root-owned with restrictive permissions (`chmod 640`), since they can contain `destemail` and whitelist details.
- **Pair, don't replace** — Fail2Ban complements strong authentication (SSH key-only auth, MFA on web logins, not exposing databases publicly), regular patching, and a properly configured firewall; it isn't a substitute for any of them.
- **Review jail effectiveness periodically.** An idle jail with `Currently failed: 0` over a long period may indicate a misconfigured `logpath` for *this distro* rather than an absence of attacks.
- **Disable SSH password authentication where feasible** (`PasswordAuthentication no` + key-based auth) — Fail2Ban is a mitigating control, not a primary defense, on every OS.

---

## 24. Maintenance & Ongoing Operations

- **After OS or Fail2Ban package upgrades:** re-run `fail2ban-client -t` and check `fail2ban-client status` for every jail — upgrades occasionally change default filter behavior or log format assumptions.
- **Periodically audit `ignoreip`:** remove stale entries (former employees' home IPs, decommissioned VPN ranges) and confirm current trusted ranges are still accurate.
- **Rotate and archive `/var/log/fail2ban.log`** per your organization's log-retention policy; this log is also what feeds the `recidive` jail, so don't disable rotation entirely.
- **Review ban statistics monthly** (`fail2ban-client status <jail>`) to catch jails that have gone quiet due to a broken `logpath`, versus genuinely low attack volume.
- **Re-validate firewall-backend assumptions after infrastructure changes** — migrating a host from bare-metal `iptables` to a `firewalld`-managed setup (or onto a Docker host) requires revisiting `banaction` per §7/§16, not just leaving the old config in place.
- **Keep a documented baseline `jail.local`** per distro/role combination in your infrastructure (e.g., version-controlled in your configuration-management repo) so new hosts are provisioned consistently rather than hand-tuned each time.

---

## 25. Quick Reference: Common Commands

| Task | Command |
|---|---|
| Check overall status | `fail2ban-client status` |
| Check a specific jail | `fail2ban-client status <jail-name>` |
| Validate config syntax | `fail2ban-client -t` |
| Reload config without restart | `fail2ban-client reload` |
| Restart service | `systemctl restart fail2ban` |
| Unban an IP from a jail | `fail2ban-client set <jail> unbanip <IP>` |
| Test a filter against a log (dry run) | `fail2ban-regex <logfile> <filterfile>` |
| View live ban log | `tail -f /var/log/fail2ban.log` |
| List action configs | `ls /etc/fail2ban/action.d/` |
| List filter configs | `ls /etc/fail2ban/filter.d/` |
| Check rules — UFW | `ufw status numbered` |
| Check rules — iptables | `iptables -L -n` |
| Check rules — firewalld | `firewall-cmd --list-all` |
| Check rules — nftables | `nft list ruleset` |

---

## 26. Appendix A: Full Reference `jail.local` (UFW backend)

```ini
[DEFAULT]
allowipv6 = auto
ignoreip  = 127.0.0.1/8 ::1 YOUR_TRUSTED_IP_OR_RANGE

backend     = systemd
usedns      = warn
logencoding = auto

bantime  = 24h
findtime = 10m
maxretry = 3

bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 7d

banaction          = ufw
banaction_allports = ufw

destemail = admin@example.com
sender    = fail2ban@example.com
mta       = sendmail
action    = %(action_mwl)s


[sshd]
enabled  = true
port     = ssh
filter   = sshd
mode     = aggressive
maxretry = 3
findtime = 10m
bantime  = 7d

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
backend  = auto
bantime  = 30d
findtime = 7d
maxretry = 5
banaction = ufw

[nginx-http-auth]
enabled  = true
port     = http,https
maxretry = 3
findtime = 10m
bantime  = 1d

[nginx-botsearch]
enabled  = true
port     = http,https
maxretry = 2
findtime = 10m
bantime  = 7d

[nginx-bad-request]
enabled  = true
port     = http,https
maxretry = 10
findtime = 10m
bantime  = 1d
```

---

## 27. Appendix B: Full Reference `jail.local` (firewalld backend)

For RHEL / CentOS / Rocky Linux / AlmaLinux / Fedora, the same logical jails using `firewalld` instead:

```ini
[DEFAULT]
allowipv6 = auto
ignoreip  = 127.0.0.1/8 ::1 YOUR_TRUSTED_IP_OR_RANGE

backend     = systemd
usedns      = warn
logencoding = auto

bantime  = 24h
findtime = 10m
maxretry = 3

bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 7d

banaction          = firewallcmd-ipset
banaction_allports = firewallcmd-ipset

destemail = admin@example.com
sender    = fail2ban@example.com
mta       = sendmail
action    = %(action_mwl)s


[sshd]
enabled  = true
port     = ssh
filter   = sshd
mode     = aggressive
logpath  = /var/log/secure
maxretry = 3
findtime = 10m
bantime  = 7d

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
backend  = auto
bantime  = 30d
findtime = 7d
maxretry = 5
banaction = firewallcmd-ipset

[nginx-http-auth]
enabled  = true
port     = http,https
maxretry = 3
findtime = 10m
bantime  = 1d

[apache-auth]
enabled  = true
port     = http,https
logpath  = /var/log/httpd/error_log
maxretry = 3
findtime = 10m
bantime  = 1d
```

> In both appendices, replace `YOUR_TRUSTED_IP_OR_RANGE` and `admin@example.com` with real values, run `fail2ban-client -t`, then `systemctl restart fail2ban` and verify with `fail2ban-client status`.

---

*Distribution and path details in this guide reflect common defaults as of mid-2026; always confirm exact log paths and package names against your specific OS release, since minor version differences (especially around log file naming and journald-only configurations) do occur.*
