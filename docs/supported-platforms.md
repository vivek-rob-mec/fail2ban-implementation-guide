# Platform and testing status

[Start here](../README.md) · [Setup walkthrough](quickstart.md) · [Troubleshooting](recovery.md)

Version 0.1 targets Ubuntu 22.04 and 24.04 with systemd, OpenSSH and an already active UFW firewall. Other distributions and firewall backends are rejected by server commands.

| Environment | Unit/recovery tests | Real configuration parsing | Live apply/rollback and firewall enforcement |
| --- | --- | --- | --- |
| Ubuntu 24.04 WSL, Python 3.12 | Passed | Passed with Ubuntu Fail2Ban 1.0.2-3ubuntu0.1, systemd and polling | Not tested |
| Ubuntu 22.04 | CI configured; not yet run | CI configured; not yet run | Not tested |
| Windows, Python 3.14 | Passed; Linux symlink test skipped | Not applicable | Unsupported |

The Ubuntu package checks downloaded and extracted packages into a temporary directory; they did not install them, start a daemon, or change firewall rules. The parser test checks that both generated configurations enable the expected SSH jail, use the intended backend and UFW action, and retain the specified trusted address.

The unit tests exercise repeated deployment, staged validation failure, activation failure, failed recovery, interrupted operations, external changes, conflicts, and rollback history using fake service commands. They do not establish that real systemd/UFW behavior matches every simulated failure.

Before a stable release, complete the [quick-start enforcement test](quickstart.md) in disposable VMs, including fresh install, existing configuration, reboot, IPv4/IPv6 and recovery scenarios. GitHub Actions checks are defined in [.github/workflows/checks.yml](../.github/workflows/checks.yml) and require publishing the repository before they can run on GitHub.
