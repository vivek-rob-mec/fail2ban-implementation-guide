# Fail2Ban Toolkit

Set up SSH protection on **Ubuntu 22.04/24.04 with UFW**. The toolkit inspects the server, generates configuration, previews changes, validates and deploys them, and provides rollback.

Fail2Ban watches authentication logs. A **filter** identifies failed logins; a **jail** combines that filter, a log source, a failure threshold and a firewall action. Here, five matching failures from an untrusted source within ten minutes trigger a ten-minute UFW ban. The UFW action blocks that source across ports, so other services can also become unreachable from the banned address.

**Version 0.1 is a prototype.** Configuration parsing and simulated recovery have been tested; live deployment and firewall enforcement have not. Start in a disposable Ubuntu VM. See [platform and testing status](docs/supported-platforms.md). This setup covers host SSH; web, mail, Docker forwarding, other distributions and other firewall backends need their own implementation.

## Start here and finish here

**Start with this README, then follow [the quick start](docs/quickstart.md) from step 1 through step 6.** Finish when the jail is active, a controlled external test confirms blocking and unblocking, and a fresh administrator login still works. Installation or an `active` status alone is not the finish line.

| Document | When to read it |
| --- | --- |
| [Quick start](docs/quickstart.md) | Your main walkthrough: prepare, install, configure, apply, verify and maintain |
| [Configuration](docs/configuration.md) | Understand settings, files, edit commands and the consequences of changes |
| [Recovery and troubleshooting](docs/recovery.md) | A command fails, a ban does not work, access is lost, or you need rollback |
| [Platform and testing status](docs/supported-platforms.md) | Check whether the environment fits and what has actually been tested |

The command sequence, from the repository directory on the Ubuntu server, is:

```text
doctor → install-deps (if needed) → doctor → configure → plan → apply → status
                                                                       ↓
                                                      external ban/unban test
```

Use the quick start for executable commands and expected results. No pip packages are needed; the toolkit uses Python 3.10+ and Ubuntu's Fail2Ban package.

The original [comprehensive guide](fail2ban-comprehensive-guide.md) is preserved unchanged as an optional reference.

## What do I create or edit?

**No configuration file needs to be created manually for the default setup.** You supply your trusted administrator addresses and choose the policy; the tool writes the files.

| File | Created by | Your responsibility |
| --- | --- | --- |
| `.f2b-toolkit/plan.json` in this checkout | `configure` | Review it; optionally edit it with `sudo nano .f2b-toolkit/plan.json` before `plan` and `apply` |
| `/etc/fail2ban/jail.d/90-toolkit-sshd.local` | `apply` | Inspect it; update through the plan because direct edits cause later apply/rollback to refuse overwriting it |
| `/var/lib/f2b-toolkit/` | Deployment/recovery commands | Keep recovery records private and available for rollback |

You do not need to create `jail.local`, copy `jail.conf`, write a filter, or edit `templates/sshd.local.tpl` for this workflow. SSH access and an active UFW firewall are prerequisites; the quick start explains how to check them.

## What changes on the server?

`install-deps` installs `fail2ban` and `python3-systemd`; package scripts may start Fail2Ban. `configure` only writes the local plan. `plan` previews the generated configuration. `apply` validates the complete Fail2Ban configuration, saves recovery data, writes the managed file, enables Fail2Ban at boot and restarts it, including other enabled jails. Applying identical configuration does not restart the service.

`rollback` restores the previous toolkit file and Fail2Ban enabled/running state. Packages and UFW policy are outside rollback. The toolkit refuses conflicting existing SSH/global overrides and external edits to its managed file.

## For maintainers

Code lives in `f2b_toolkit/`, the entry point is `bin/f2b-tool`, and the generated jail uses `templates/sshd.local.tpl`. See [contributing](CONTRIBUTING.md) for checks and publishing, and the [changelog](CHANGELOG.md) for changes. These are not required reading for server setup.

This project is available under the [MIT License](LICENSE), copyright 2026 Vivek Saroj. It is an independent toolkit using [Fail2Ban](https://github.com/fail2ban/fail2ban), which is separately licensed by its authors.
