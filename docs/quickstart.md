# Quick start: from a server to verified SSH protection

[Start here](../README.md) · [Configuration](configuration.md) · [Troubleshooting](recovery.md)

Follow these steps in order on the Ubuntu server you want to protect. Start with a disposable VM: this prototype has no completed live enforcement test. Allow time for the external test, not just package installation.

## 1. Prepare access and the firewall

You need Ubuntu 22.04 or 24.04, running systemd, Python 3.10+, sudo access, OpenSSH, and an active UFW firewall. Keep an administrator session open and have a provider/VM console available. You also need a separate test machine whose source address is outside your trusted ranges.

Download and extract [this repository](https://github.com/vivek-rob-mec/fail2ban-implementation-guide) onto the server, or clone it with Git. Enter the folder containing `README.md` and `bin/`. All toolkit commands below run from that folder.

If Git is installed:

```bash
git clone https://github.com/vivek-rob-mec/fail2ban-implementation-guide.git
cd fail2ban-implementation-guide
```

For a ZIP download, use `cd` to enter the extracted folder instead. Confirm the host and access details:

```bash
pwd
ls bin/f2b-tool
cat /etc/os-release
python3 --version
sudo /usr/sbin/sshd -T | grep '^port '
sudo ss -ltnp
sudo ufw status numbered
printf '%s\n' "$SSH_CONNECTION"
```

The first value in `SSH_CONNECTION` is the client address **as this server sees it**; the fourth is the server port for that connection. The client address may be a VPN or NAT address. An empty value is normal at a console: obtain your trusted source address from your network setup. Confirm all administrative sources, including IPv6 if used. Never enter the example address from a guide as your real trusted address.

UFW must report `Status: active`, with rules allowing your actual SSH port/source. Compare `sshd -T` with the listeners; resolve socket overrides or port forwarding before proceeding. The toolkit does not configure SSH or cloud firewall rules.

If UFW is inactive on an otherwise standard host, prepare it from the console. The following is an example **only for SSH on port 22**; replace `22` with the verified port, repeat for other SSH ports, and add rules for any other required services before enabling UFW:

```bash
sudo ufw allow 22/tcp
sudo ufw enable
sudo ufw status numbered
```

Enabling UFW changes access for the entire host; an omitted service rule can interrupt traffic. Open a fresh SSH session successfully before continuing. If UFW/OpenSSH is missing, or another firewall manages the host, complete that host setup first using [Ubuntu's firewall documentation](https://documentation.ubuntu.com/server/how-to/security/firewalls/index.html). `install-deps` requires active UFW and does not install or enable it.

## 2. Inspect and install dependencies

```bash
sudo python3 bin/f2b-tool doctor
```

Expected: Ubuntu version, firewall state, configured SSH ports, journal availability and Fail2Ban checks. On a fresh host, missing Fail2Ban or journal bindings can produce `FAIL` lines. Install those dependencies, then inspect again:

```bash
sudo python3 bin/f2b-tool install-deps
sudo python3 bin/f2b-tool doctor
```

Installation requests confirmation and can take several minutes; output appears on completion or failure. Ubuntu package scripts may start Fail2Ban. Rollback does not uninstall packages.

Resolve other failed checks using [troubleshooting](recovery.md). Doctor always checks journal input. If you intentionally use an actively written `/var/log/auth.log`, the polling option below can work even when the journal check fails.

## 3. Create your plan

For the standard policy and journal input:

```bash
sudo python3 bin/f2b-tool configure
```

At the prompt, enter your actual trusted administrator IPs or CIDRs, separated by spaces. The tool detects configured SSH ports. A trusted range is exempt from this jail's bans; choose it narrowly. The current SSH client must be trusted when `SSH_CONNECTION` is available, but sudo may remove that variable, so review the list yourself.

If SSH actually writes to `/var/log/auth.log`, use this command **instead**:

```bash
sudo python3 bin/f2b-tool configure --backend polling
```

Expected: `Saved .f2b-toolkit/plan.json`. This creates the directory and file automatically; server configuration has not changed. Inspect the plan:

```bash
sudo cat .f2b-toolkit/plan.json
```

Check `trusted_ips`, `ports`, and `backend`. Defaults are `maxretry: 5`, `findtime: 600`, and `bantime: 600`: five matching failures from one untrusted source in ten minutes trigger a ten-minute ban. A connection is not necessarily one matching failure. This jail uses normal SSH matching and a UFW source-wide ban, affecting ports beyond SSH.

For custom values or an edit command, use [configuration](configuration.md). **Running `configure` again replaces the plan; omitted options revert to defaults, and omitted ports are detected again.**

## 4. Preview and apply

```bash
sudo python3 bin/f2b-tool plan
sudo python3 bin/f2b-tool apply
```

`plan` shows the difference for `/etc/fail2ban/jail.d/90-toolkit-sshd.local`. Confirm your trusted addresses, ports, backend and timings. It is a preview; the complete configuration validation occurs during `apply`.

`apply` checks prerequisites and asks for confirmation. It validates a staged copy of the full Fail2Ban configuration, saves the previous managed file and service state, writes the new file, validates again, enables Fail2Ban at boot, restarts it and checks the SSH jail. Other enabled jails are also restarted.

Expected: `SSH jail applied` and a backup path. An identical configuration reports that it already matches. If activation fails, the tool attempts recovery; if an operation is interrupted, follow [rollback instructions](recovery.md#restore-the-previous-deployment) before applying again.

## 5. Verify monitoring and actual blocking

On the protected server:

```bash
sudo python3 bin/f2b-tool status
sudo systemctl is-enabled fail2ban
sudo fail2ban-client -t
sudo fail2ban-client get sshd ignoreip
```

Expected: an active service, an enabled boot setting, a jail named `sshd`, active UFW, successful configuration validation, and your trusted addresses in `ignoreip`. Zero bans is normal before a test. These checks alone do not prove that traffic is blocked.

For the controlled external test:

1. Keep the console and trusted administrator session available. Use a test machine you control with a different source IP. Two machines behind the same NAT/VPN may share one source; do not ban your shared administrator address.
2. From that machine, attempt SSH authentication with deliberately invalid credentials against your test server until enough matching failures accumulate within `findtime`. Do not change the server's authentication policy just for this test. Watch the SSH logs to confirm that the chosen attempts match the filter.
3. From the trusted session, run the commands below. The test source must appear in both the jail's banned list and UFW rules.

```bash
sudo fail2ban-client status sshd
sudo ufw status numbered
```

4. Try a **new connection** from the banned source: it should fail. Also open a fresh login from your trusted administrator source: it should succeed. An already established connection is not a reliable blocking test.
5. In the trusted session, replace `TEST_SOURCE_IP` with the actual banned address and unban it:

```bash
sudo fail2ban-client set sshd unbanip TEST_SOURCE_IP
sudo fail2ban-client status sshd
sudo ufw status numbered
```

6. Confirm that the test ban/rule disappeared and a new connection from the test machine works again. Test each address family used to reach the server. A manual `banip` checks the action only; it does not replace the failed-login test of log monitoring and filtering.

If a check fails, use [troubleshooting](recovery.md). If a separate test source is unavailable, record enforcement as **not verified**.

## 6. Finish and maintain

The initial implementation is complete for your tested environment when:

- Fail2Ban is active and enabled at boot, and the `sshd` jail is loaded.
- The trusted addresses and log backend match your server.
- Failed authentication leads to a visible ban and a blocked new connection.
- Unbanning restores access, and a fresh trusted administrator login works.

Record the OS, Fail2Ban version (`sudo fail2ban-client --version`), backend, source address family and test result in your operations notes. Keep trusted addresses and backups private. During a planned reboot test, repeat status and access checks afterward to confirm startup behavior.

For later changes, follow [editing the policy](configuration.md#edit-the-policy), then repeat verification. Check status after package, SSH, firewall, logging or administrator IP changes. Run toolkit commands from the same checkout, or consistently specify a custom plan path. Keep `/var/lib/f2b-toolkit/` for recovery.

**You can stop reading here after successful verification.** Configuration and recovery are references for subsequent changes and problems; contributor and changelog files are not setup steps.
