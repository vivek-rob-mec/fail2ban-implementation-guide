# Contributing

Start with the [README](README.md) and follow the [quick start](docs/quickstart.md) to understand the supported user flow.

For a correction, identify the guide section, explain the observed problem, and link to an upstream source or provide a reproducible example. Keep changes focused and distinguish a documentation review from an actual runtime test.

Correct the relevant document directly. Keep one setup walkthrough in `docs/quickstart.md`, settings and edit instructions in `docs/configuration.md`, and symptoms, causes and recovery commands in `docs/recovery.md`. Avoid adding a second competing installation guide.

For configuration or filter examples, include:

- Distribution, version, and Fail2Ban package version.
- Service, firewall backend, and log source.
- Sanitized configuration and representative log samples.
- Expected behavior and actual validation results.

Replace real user names, hostnames, email addresses, and public IP addresses in examples. Do not include credentials or raw production logs.

For documentation changes, check relative links and fenced code blocks. For operational examples, run configuration and regex checks in a disposable Linux environment and record whether firewall enforcement was tested. Never claim a distribution is supported based only on a syntax check.

## Toolkit changes

Use Python 3.10-compatible standard-library code. Keep host commands in `f2b_toolkit/system.py`, validate plan inputs before rendering, and invoke subprocesses with argument arrays rather than a shell.

Run `python3 -m unittest discover -s tests -v`. On Linux with the distribution's Fail2Ban and `python3-systemd` packages, also run `python3 tests/validate_linux.py`; that check parses temporary configurations without starting a daemon. Add failure-path tests for changes affecting deployment or recovery, and update the [testing matrix](docs/supported-platforms.md) only with observed results.

Use disposable VMs for service and firewall tests. Do not test apply/rollback against the workstation's real configuration as part of ordinary unit tests.

## Publishing (maintainers only)

This project uses the [MIT License](LICENSE). Review the staged files for private plans, logs and credentials; `.f2b-toolkit/` and `.validation/` are ignored. Commit the reviewed files and push to the repository below, preserving any existing remote history.

The repository URL is https://github.com/vivek-rob-mec/fail2ban-implementation-guide. After publishing, check rendered documentation links and issue/PR templates, and review the Ubuntu CI results. Keep live support claims limited to observed tests in the [testing matrix](docs/supported-platforms.md).
