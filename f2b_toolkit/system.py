"""Host inspection and fixed-argument commands. Never invokes a shell."""
import configparser
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

from .config import ToolkitError


class Host:
    def run(self, *args, check=True, timeout=60):
        env = {**os.environ, "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
        try:
            result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolkitError(f"Cannot run {args[0]}: {exc}") from exc
        if check and result.returncode:
            raise ToolkitError(f"{' '.join(args)} failed:\n{result.stderr.strip() or result.stdout.strip()}")
        return result

    def platform_check(self):
        if platform.system() != "Linux":
            raise ToolkitError("Server commands require Ubuntu Linux. Help and unit tests work on Windows.")
        release = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep:
                release[key] = value.strip('"')
        if release.get("ID") != "ubuntu" or release.get("VERSION_ID") not in {"22.04", "24.04"}:
            raise ToolkitError("This version targets Ubuntu 22.04 and 24.04 only.")
        if not Path("/run/systemd/system").is_dir():
            raise ToolkitError("A running systemd environment is required.")
        return release["VERSION_ID"]

    def require_root(self):
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise ToolkitError("Run this server command with sudo.")

    def ufw_check(self):
        if not shutil.which("ufw", path="/usr/sbin:/usr/bin:/sbin:/bin"):
            raise ToolkitError("UFW must already be installed and configured for this server.")
        output = self.run("ufw", "status").stdout
        if not output.startswith("Status: active"):
            raise ToolkitError("UFW is inactive. Configure SSH access and enable UFW separately first.")
        if self.run("systemctl", "is-active", "firewalld", check=False).returncode == 0:
            raise ToolkitError("Both UFW and firewalld are active; resolve firewall ownership first.")

    def ports(self):
        result = self.run("/usr/sbin/sshd", "-T", check=False)
        ports = sorted({int(line.split()[1]) for line in result.stdout.splitlines() if line.startswith("port ")})
        if result.returncode or not ports:
            raise ToolkitError("Could not detect SSH ports. Run configure with sudo or specify --port.")
        return ports

    def check_log_source(self, backend):
        if backend == "polling":
            log = Path("/var/log/auth.log")
            if not log.is_file() or not os.access(log, os.R_OK):
                raise ToolkitError("Polling requires a readable /var/log/auth.log.")
        else:
            result = self.run("journalctl", "--no-pager", "-n", "1", "-o", "json", "_SYSTEMD_UNIT=ssh.service", "+", "_COMM=sshd")
            if not result.stdout.strip():
                raise ToolkitError("No SSH journal entries found. Verify SSH logging before applying.")
            self.run("/usr/bin/python3", "-c", "import systemd.journal")

    def service_state(self):
        active = self.run("systemctl", "is-active", "fail2ban", check=False).stdout.strip()
        enabled = self.run("systemctl", "is-enabled", "fail2ban", check=False).stdout.strip()
        if active not in {"active", "inactive", "failed"} or enabled not in {"enabled", "disabled"}:
            raise ToolkitError(f"Unsupported Fail2Ban service state: {active}/{enabled}. Resolve it first.")
        return {"active": active == "active", "enabled": enabled == "enabled"}

    def prerequisites(self, settings):
        self.platform_check()
        self.require_root()
        self.ufw_check()
        for name in ("fail2ban-client",):
            if not shutil.which(name):
                raise ToolkitError("Fail2Ban is missing. Run: sudo python3 bin/f2b-tool install-deps")
        if not any(self.run("systemctl", "is-active", name, check=False).returncode == 0 for name in ("ssh.service", "ssh.socket")):
            raise ToolkitError("Neither ssh.service nor ssh.socket is active.")
        settings.check_connection(os.environ.get("SSH_CONNECTION", ""))
        # sshd -T does not describe all socket activation overrides; display those in doctor.
        detected = self.ports()
        if detected != settings.ports:
            raise ToolkitError(f"Plan ports {settings.ports} differ from sshd ports {detected}; reconfigure.")
        self.check_log_source(settings.backend)
        self.service_state()

    def validate(self, directory):
        self.run("fail2ban-client", "-c", str(directory), "-t")

    def activate(self):
        self.run("systemctl", "enable", "fail2ban")
        self.run("systemctl", "restart", "fail2ban")
        self.wait_ready()
        self.run("fail2ban-client", "status", "sshd")

    def wait_ready(self):
        for _ in range(20):
            if self.run("fail2ban-client", "ping", check=False, timeout=5).returncode == 0:
                return
            time.sleep(0.25)
        raise ToolkitError("Fail2Ban did not become ready after the service operation.")

    def restore_service(self, state):
        self.run("systemctl", "enable" if state["enabled"] else "disable", "fail2ban")
        self.run("systemctl", "restart" if state["active"] else "stop", "fail2ban")
        if state["active"]:
            self.wait_ready()


def check_conflicts(directory: Path, managed: Path):
    """Refuse ambiguous administrator overrides instead of silently replacing policy."""
    paths = [directory / "jail.local", *sorted((directory / "jail.d").glob("*.conf")), *sorted((directory / "jail.d").glob("*.local"))]
    for path in paths:
        if path == managed or not path.exists():
            continue
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(path.read_text(encoding="utf-8"))
        except (OSError, configparser.Error) as exc:
            raise ToolkitError(f"Cannot inspect {path}: {exc}") from exc
        # Ubuntu's package enables SSH and may set nftables defaults for other jails.
        # Our explicit SSH action overrides those defaults for this jail only.
        package_defaults = ({}, {"backend": "systemd"}, {
            "backend": "systemd", "banaction": "nftables",
            "banaction_allports": "nftables[type=allports]",
        })
        if path.name == "defaults-debian.conf" and parser.defaults() in package_defaults and parser.sections() == ["sshd"]:
            values = dict(parser["sshd"])
            expected = {**parser.defaults(), "enabled": "true"}
            if values in (expected, {**expected, "backend": "systemd"}):
                continue
        if parser.defaults() or parser.has_section("sshd") or parser.has_section("INCLUDES"):
            raise ToolkitError(f"Existing SSH/default/include overrides in {path}. Reconcile them manually first; nothing was overwritten.")
