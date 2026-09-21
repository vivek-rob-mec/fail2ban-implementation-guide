# Platform and testing status

[Start here](../README.md) · [Setup walkthrough](quickstart.md) · [Troubleshooting](recovery.md)

Version 0.1 targets Ubuntu 22.04 and 24.04 with systemd, OpenSSH and an already active UFW firewall. Other distributions and firewall backends are rejected by server commands.

| Environment | Unit/recovery tests | Real configuration parsing | Live apply/rollback and firewall enforcement |
| --- | --- | --- | --- |
| Ubuntu 24.04 WSL, Python 3.12 | Passed | Passed with Ubuntu Fail2Ban 1.0.2-3ubuntu0.1, systemd and polling | Not tested |
| Ubuntu 22.04 GitHub Actions | Passed | Passed with distribution packages, systemd and polling | Not tested |
| Ubuntu 24.04 GitHub Actions | Passed | Passed with distribution packages, systemd and polling | Not tested |
| Windows, Python 3.14 | Passed; Linux symlink test skipped | Not applicable | Unsupported |

The earlier WSL package checks downloaded and extracted packages into a temporary directory; they did not install them, start a daemon, or change firewall rules. GitHub Actions installs distribution packages on disposable runners and stops Fail2Ban before parsing the configurations. The parser test checks that both generated configurations enable the expected SSH jail, use the intended backend and UFW action, and retain the specified trusted address.

Both Ubuntu CI jobs passed on 2026-09-21 for commit `fd3b2d4`: [test results](https://github.com/vivek-rob-mec/fail2ban-implementation-guide/actions/runs/35626274563). These checks did not exercise toolkit deployment or verify firewall enforcement.

The unit tests exercise repeated deployment, staged validation failure, activation failure, failed recovery, interrupted operations, external changes, conflicts, and rollback history using fake service commands. They do not establish that real systemd/UFW behavior matches every simulated failure.

Before a stable release, complete the [quick-start enforcement test](quickstart.md) in disposable VMs, including fresh install, existing configuration, reboot, IPv4/IPv6 and recovery scenarios. GitHub Actions checks are defined in [.github/workflows/checks.yml](../.github/workflows/checks.yml) and run on pushes and pull requests.
