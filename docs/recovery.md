# Recovery and troubleshooting

[Start here](../README.md) · [Setup walkthrough](quickstart.md) · [Edit settings](configuration.md#edit-the-policy)

Run toolkit commands from the repository directory on the Ubuntu server. If SSH access is lost, use the provider/VM console.

## Start with these checks

```bash
sudo python3 bin/f2b-tool doctor
sudo python3 bin/f2b-tool status
sudo fail2ban-client -t
sudo systemctl status fail2ban --no-pager
sudo journalctl -u fail2ban -n 50 --no-pager
```

For Fail2Ban event/action errors, also inspect its configured log destination:

```bash
sudo fail2ban-client get logtarget
sudo tail -n 100 /var/log/fail2ban.log
```

The file command applies when that file is the configured destination. If the daemon is down, inspect `/etc/fail2ban/fail2ban.conf`, any `fail2ban.local` and `fail2ban.d/` overrides for `logtarget`. A quiet systemd journal does not mean the application's log is empty.

| Symptom | Likely cause / consequence | Next step |
| --- | --- | --- |
| Cannot open `bin/f2b-tool` or cannot read plan | Wrong directory, missing plan or incorrect `--plan` position | Run `pwd`, `ls bin/f2b-tool`, `sudo ls .f2b-toolkit/plan.json`; return to the checkout or use `--plan /absolute/path` before the command |
| Plan JSON/schema/value error | Invalid edit; deployment cannot proceed | Run `sudo python3 -m json.tool .f2b-toolkit/plan.json`, then correct the file using the [schema and ranges](configuration.md) |
| Unsupported platform / no systemd | Host is outside the toolkit's supported environment | Use Ubuntu 22.04/24.04 with running systemd; Windows only supports help/unit tests |
| UFW missing/inactive or firewalld also active | Firewall prerequisite fails; bans cannot be assumed to work | Resolve firewall ownership and follow [host preparation](quickstart.md#1-prepare-access-and-the-firewall) |
| Fail2Ban or systemd Python module missing | Dependency unavailable | Run `sudo python3 bin/f2b-tool install-deps`, then `doctor` |
| Current SSH client is not trusted | Plan could ban the administrative source | Verify the observed client address, then [edit trusted IPs](configuration.md#edit-the-policy) |
| Another toolkit operation is running | Apply/rollback holds the lock | Let that operation finish; do not delete the lock or recovery records |
| Interrupted deployment needs recovery | An operation left a pending record | Use [rollback](#restore-the-previous-deployment) before another apply |
| Configuration already matches, but service is stopped | Identical apply does not restart the service | Validate with `sudo fail2ban-client -t`; if stopping was unintentional, run `sudo systemctl start fail2ban` and check status |

## Restore the previous deployment

An activation failure automatically attempts to restore the prior managed file and service state. If recovery also fails, the error reports a backup location and keeps `pending.json`. To recover an interrupted operation or undo the latest deployment:

```bash
sudo python3 bin/f2b-tool rollback
sudo fail2ban-client -t
sudo systemctl status fail2ban --no-pager
sudo ufw status numbered
```

Expected: `Previous toolkit configuration and Fail2Ban service state restored`. On a first-deployment rollback, the toolkit file is removed if it did not previously exist; the service may be stopped or disabled if that was its prior state. That result is intentional. Repeated rollback walks earlier recorded deployments; it is not a redo command.

Rollback works without healthy UFW or SSH logging, but still needs a supported Ubuntu/systemd host, readable recovery data and valid restored configuration. If it fails, inspect the reported error, backup record and logs. Preserve recovery records.

Rollback does **not** uninstall packages, restore a UFW rule snapshot, restore historical logs/database contents, undo other administrators' changes, or restore the local `plan.json`. Reconcile the plan before applying again or you can redeploy the policy you just undid. Runtime bans can change when Fail2Ban restarts.

## Administrator address was banned

From the independent console, replace `YOUR_ACTUAL_IP` with the address observed by the server:

```bash
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip YOUR_ACTUAL_IP
```

Edit `trusted_ips` in the plan, run `plan` and `apply`, then verify a fresh SSH login. A VPN/NAT change or missing IPv6 address can explain why an administrator was not exempt.

If Fail2Ban is unavailable, inspect the firewall from the console:

```bash
sudo ufw status numbered
```

Identify the exact blocking rule for that source and remove only that rule with `sudo ufw delete RULE_NUMBER`, replacing the placeholder with its current number. List rules again after every deletion because numbers change. This is temporary access recovery: fix the jail/trusted list before restarting Fail2Ban, which may restore a saved ban. Avoid resetting the entire firewall to solve one ban.

## Existing configuration or managed-file conflict

For an SSH/default/include conflict, inspect the file named in the error. For example, if it is `jail.local`:

```bash
sudo cat /etc/fail2ban/jail.local
sudo cp /etc/fail2ban/jail.local /root/jail.local.before-toolkit
sudo nano /etc/fail2ban/jail.local
```

These commands apply only if that file exists and is the reported conflict. Reconcile overlapping settings with the intended plan before editing. Preserve unrelated jails; migrate needed policy deliberately. The toolkit refuses all global defaults in administrator jail overrides, so an existing shared policy may be better kept under its current management.

If the **managed file** was changed externally, inspect it and the record:

```bash
sudo cat /etc/fail2ban/jail.d/90-toolkit-sshd.local
sudo cat /var/lib/f2b-toolkit/state.json
sudo ls /var/lib/f2b-toolkit/deployments
```

Use the deployment ID to inspect the corresponding `record.json`. Its `after` value is the applied content and `before` is the previous content. Preserve external changes separately and decide which policy to retain. Returning the managed file to the exact recorded applied content allows normal ownership checks to pass; transfer desired changes into the plan. Do not delete state records or alter digests to force deployment. An untracked target file likewise requires a deliberate migration.

Validate reconciled policy with `sudo fail2ban-client -t`, then run `plan` and `apply`. A conflict can involve production policy; there is no universal delete command that safely resolves it.

## Journal checks fail or auth.log is missing

Check the same journal selection the toolkit uses:

```bash
sudo journalctl --no-pager -n 30 '_SYSTEMD_UNIT=ssh.service' + '_COMM=sshd'
sudo /usr/bin/python3 -c 'import systemd.journal'
```

Missing Python bindings are addressed by `install-deps`. If there are no journal entries, make a fresh legitimate SSH connection and check again. Inspect SSH logging if entries remain absent.

For file logging:

```bash
sudo ls -l /var/log/auth.log
sudo tail -n 30 /var/log/auth.log
```

Use `"backend": "polling"` in the existing plan only when this file receives actual SSH events, then `plan`, `apply` and verify. Creating an empty file does not configure logging. Doctor always checks the journal, so its journal failure can remain on a correctly configured polling host.

## Jail is active but failures or bans stay at zero

Possible causes include a trusted test source, an incorrect log source, attempts that do not match normal SSH filtering, or fewer matching failures within the configured time window.

```bash
sudo fail2ban-client get sshd ignoreip
sudo fail2ban-client get sshd maxretry
sudo fail2ban-client get sshd findtime
sudo fail2ban-client status sshd
```

Inspect the journal or auth.log during the attempts. For the polling backend, test existing log lines against the same filter without creating bans:

```bash
sudo fail2ban-regex /var/log/auth.log 'sshd[mode=normal]'
```

Matches show that the sampled lines fit the filter, not that the daemon is watching the correct source or that the firewall blocks traffic. Check Fail2Ban's logs for action errors. Fix the source or test conditions before reducing the threshold.

## Source is banned but connections still work

```bash
sudo fail2ban-client status sshd
sudo ufw status numbered
sudo ufw show raw
```

Confirm that the address in the ban matches the client's source **as seen by the server** and that UFW has a corresponding rule. Test a fresh TCP connection; an existing session may survive. Check whether the client retries through another IPv4/IPv6 address and whether traffic actually crosses this host's firewall.

A jail ban with no firewall rule points to an action failure; inspect Fail2Ban's log. A rule with no blocking can indicate firewall order or a different network path. Docker forwarding, proxies and port translation require separate analysis and are outside this toolkit's host-SSH setup. See the [upstream UFW action](https://github.com/fail2ban/fail2ban/blob/1.0.2/config/action.d/ufw.conf) for its rule and established-connection behavior.

## SSH ports differ or the service cannot start

```bash
sudo /usr/sbin/sshd -T | grep '^port '
sudo ss -ltnp
sudo systemctl status ssh.service ssh.socket --no-pager
sudo fail2ban-client -t
```

The plan must match configured SSH ports exactly. Changing a plan port does not change SSH or open a firewall port. Resolve any SSH/socket/firewall changes first, then edit the plan to match. Socket activation overrides, forwarded ports and containers can differ from `sshd -T`; resolve those differences before deploying.

For a Fail2Ban startup failure, fix the file/line reported by validation or use rollback if the toolkit change caused the failure. Full validation includes other enabled jails, so an unrelated invalid jail can block apply. A masked or transitional service state also needs investigation before the toolkit will deploy.

Client command syntax is documented in the [Fail2Ban client manual](https://github.com/fail2ban/fail2ban/blob/1.0.2/man/fail2ban-client.1). When reporting a problem, include the command, sanitized error, OS/package versions, backend and validation results; remove credentials and private log details.
