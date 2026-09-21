"""Command interface for an explicitly scoped Ubuntu/UFW setup."""
import argparse
import difflib
import os
import sys
from pathlib import Path

from . import __version__
from .config import Settings, ToolkitError
from .deployment import Deployment
from .system import Host, check_conflicts


def parser():
    result = argparse.ArgumentParser(description="SSH protection setup for Ubuntu 22.04/24.04 with active UFW.")
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--plan", type=Path, default=Path(".f2b-toolkit/plan.json"), help="local plan file (default: .f2b-toolkit/plan.json)")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="inspect server prerequisites without changing them")
    install = commands.add_parser("install-deps", help="install fail2ban and python3-systemd using apt")
    install.add_argument("--yes", action="store_true")
    configure = commands.add_parser("configure", help="generate a local plan; does not change server configuration")
    configure.add_argument("--trusted-ip", action="append", help="trusted IP/CIDR; repeat for multiple ranges")
    configure.add_argument("--port", type=int, action="append", help="SSH port; repeat for multiple ports; otherwise detect")
    configure.add_argument("--backend", choices=("systemd", "polling"), default="systemd")
    configure.add_argument("--bantime", type=int, default=600, help="seconds (default: 600)")
    configure.add_argument("--findtime", type=int, default=600, help="seconds (default: 600)")
    configure.add_argument("--maxretry", type=int, default=5)
    commands.add_parser("plan", help="show the generated configuration and host differences")
    apply = commands.add_parser("apply", help="validate, back up and deploy the plan")
    apply.add_argument("--yes", action="store_true", help="accept the displayed changes without a prompt")
    commands.add_parser("status", help="show service, SSH jail and UFW status")
    rollback = commands.add_parser("rollback", help="restore the previous toolkit configuration and service state")
    rollback.add_argument("--yes", action="store_true")
    return result


def confirm(message, yes):
    if yes:
        return
    if not sys.stdin.isatty():
        raise ToolkitError("Interactive confirmation required; use --yes after reviewing the plan.")
    if input(message + " [y/N] ").strip().lower() not in {"y", "yes"}:
        raise ToolkitError("Cancelled; no deployment changes made.")


def preview(deployment, settings):
    check_conflicts(deployment.config, deployment.target)
    old, _ = deployment.check_owned()
    new = settings.render()
    print(f"Target: {deployment.target}\n")
    diff = "".join(difflib.unified_diff((old or "").splitlines(True), new.splitlines(True), fromfile="current", tofile="planned"))
    print(diff or "Configuration already matches.")
    print("Action: UFW source-wide ban (not restricted to SSH ports).")
    print("Apply validates all jails, enables Fail2Ban at boot and restarts Fail2Ban, including other active jails.")
    print("UFW and SSH settings are not changed. Existing UFW rules are not backed up.")


def doctor(host):
    print(f"Ubuntu {host.platform_check()} / toolkit {__version__}")
    host.require_root()
    failures = []
    checks = [
        ("Firewall", host.ufw_check),
        ("SSH configured ports", host.ports),
        ("SSH journal", lambda: host.check_log_source("systemd")),
        ("Fail2Ban version", lambda: host.run("fail2ban-client", "--version").stdout.strip()),
        ("Fail2Ban service", host.service_state),
    ]
    for label, check in checks:
        try:
            result = check()
            print(f"OK   {label}: {result if result is not None else 'available'}")
        except ToolkitError as exc:
            failures.append(label)
            print(f"FAIL {label}: {exc}")
    print("SSH listeners (verify socket activation and any port forwarding):")
    print(host.run("ss", "-ltnp", check=False).stdout.strip())
    print("No settings were changed. Firewall enforcement has not been tested.")
    if failures:
        print("Resolve the failed checks; for missing packages use install-deps.")
    return 1 if failures else 0


def main(argv=None):
    args = parser().parse_args(argv)
    host = Host()
    deployment = Deployment(host)
    try:
        if args.command == "doctor":
            return doctor(host)
        if args.command == "configure":
            host.platform_check()
            trusted = args.trusted_ip
            if not trusted:
                if not sys.stdin.isatty():
                    raise ToolkitError("Supply --trusted-ip for non-interactive configuration.")
                trusted = input("Trusted administrator IPs/CIDRs, separated by spaces: ").split()
            ports = args.port or host.ports()
            settings = Settings(trusted, ports, args.backend, args.bantime, args.findtime, args.maxretry)
            settings.check_connection(os.environ.get("SSH_CONNECTION", ""))
            settings.save(args.plan)
            print(f"Saved {args.plan}. SSH ports: {settings.ports}; log backend: {settings.backend}.")
            print("No server settings changed. Next run plan, then apply.")
            return 0
        host.platform_check()
        host.require_root()
        if args.command == "install-deps":
            host.ufw_check()
            confirm("Install fail2ban and python3-systemd? Ubuntu package scripts may start Fail2Ban.", args.yes)
            host.run("apt-get", "update", timeout=600)
            host.run("apt-get", "install", "-y", "fail2ban", "python3-systemd", timeout=600)
            print("Dependencies installed. Package changes are not part of toolkit rollback. Run doctor next.")
        elif args.command == "plan":
            settings = Settings.load(args.plan)
            preview(deployment, settings)
        elif args.command == "apply":
            settings = Settings.load(args.plan)
            host.prerequisites(settings)
            with deployment.lock():
                preview(deployment, settings)
                confirm("Apply these changes?", args.yes)
                print(deployment.apply(settings))
        elif args.command == "rollback":
            # Recovery must work even if UFW/log-source prerequisites have since failed.
            with deployment.lock():
                confirm("Restore the previous toolkit configuration and Fail2Ban service state?", args.yes)
                print(deployment.rollback())
        elif args.command == "status":
            failed = False
            for command in (("systemctl", "is-active", "fail2ban"), ("fail2ban-client", "status", "sshd"), ("ufw", "status", "numbered")):
                result = host.run(*command, check=False)
                print(f"$ {' '.join(command)}\n{result.stdout.strip() or result.stderr.strip()}\n")
                failed |= result.returncode != 0
                if command[0] == "ufw" and not result.stdout.startswith("Status: active"):
                    failed = True
            print("Status does not prove firewall enforcement; complete the external test in docs/quickstart.md.")
            return int(failed)
        return 0
    except (ToolkitError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Cancelled.", file=sys.stderr)
        return 130
