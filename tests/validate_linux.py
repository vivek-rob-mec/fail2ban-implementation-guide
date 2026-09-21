"""Parse generated configurations with real Fail2Ban without starting a daemon.

Requires the Ubuntu Fail2Ban package and python3-systemd. Uses only temporary
configuration/log files; does not change the host firewall or /etc/fail2ban.
"""
import argparse
import ast
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from f2b_toolkit.config import Settings
from f2b_toolkit.system import check_conflicts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, default=Path("/etc/fail2ban"))
    parser.add_argument("--client", default="fail2ban-client")
    args = parser.parse_args()
    for backend in ("polling", "systemd"):
        with tempfile.TemporaryDirectory(prefix="f2b-parse-") as temporary:
            root = Path(temporary)
            config = root / "config"
            shutil.copytree(args.config_dir, config)
            check_conflicts(config, config / "jail.d" / "90-toolkit-sshd.local")
            log = root / "auth.log"
            log.touch()
            text = Settings(["192.0.2.10", "2001:db8::/64"], [22, 2222], backend).render()
            # Use an isolated fixture for polling; no host log access required.
            text = text.replace("/var/log/auth.log", str(log))
            (config / "jail.d" / "90-toolkit-sshd.local").write_text(text)
            for flag in ("-t", "-d"):
                result = subprocess.run([args.client, "-c", str(config), flag], text=True, capture_output=True)
                if result.returncode:
                    raise RuntimeError(result.stdout + result.stderr)
                if flag == "-d":
                    commands = [ast.literal_eval(line) for line in result.stdout.splitlines() if line.startswith("[")]
                    assert ["add", "sshd", backend] in commands, commands
                    assert any(command[:4] == ["set", "sshd", "addaction", "ufw"] for command in commands), commands
                    assert ["start", "sshd"] in commands, commands
                    assert any(command[:3] == ["set", "sshd", "addignoreip"] and "192.0.2.10/32" in command for command in commands), commands
            print(f"PASS: {backend} SSH configuration parsed with real Fail2Ban; expected jail and UFW action present.")
    print("No daemon was started and no firewall rules were changed.")


if __name__ == "__main__":
    main()
