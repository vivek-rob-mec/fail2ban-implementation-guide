import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from f2b_toolkit.config import Settings, ToolkitError
from f2b_toolkit.deployment import Deployment, digest, regular_path
from f2b_toolkit.system import check_conflicts


class SettingsTests(unittest.TestCase):
    def test_invalid_values_cannot_become_configuration(self):
        for value in ["bad-host", "1.2.3.4\naction = malicious", "0.0.0.0/0", "::/0", "fe80::1%eth0", 12]:
            with self.subTest(value=value), self.assertRaises(ToolkitError):
                Settings([value], [22])
        for ports in [[], [0], [65536], [True], ["22"]]:
            with self.subTest(ports=ports), self.assertRaises(ToolkitError):
                Settings(["192.0.2.1"], ports)

    def test_normalizes_and_deduplicates(self):
        settings = Settings(["192.0.2.5/24", "192.0.2.0/24"], [2222, 22, 22])
        self.assertEqual(settings.trusted_ips, ["192.0.2.0/24"])
        self.assertEqual(settings.ports, [22, 2222])

    def test_current_ssh_connection_must_be_covered(self):
        settings = Settings(["192.0.2.0/24", "2001:db8::/64"], [2222])
        settings.check_connection("192.0.2.10 55555 198.51.100.1 2222")
        settings.check_connection("2001:db8::10 55555 2001:db8:1::1 2222")
        for connection in ["198.51.100.10 1 192.0.2.1 2222", "192.0.2.10 1 192.0.2.1 22", "malformed"]:
            with self.subTest(connection=connection), self.assertRaises(ToolkitError):
                settings.check_connection(connection)

    def test_backends_do_not_mix_log_sources(self):
        journal = Settings(["192.0.2.1"], [22]).render()
        file = Settings(["192.0.2.1"], [22], "polling").render()
        self.assertNotIn("logpath", journal)
        self.assertIn("backend = polling\nlogpath = /var/log/auth.log", file)
        self.assertIn("action = ufw", file)

    def test_strict_plan_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            settings = Settings(["192.0.2.1"], [22])
            settings.save(path)
            self.assertEqual(Settings.load(path), settings)
            data = json.loads(path.read_text())
            data["settings"]["action"] = "arbitrary-command"
            path.write_text(json.dumps(data))
            with self.assertRaises(ToolkitError):
                Settings.load(path)


class FakeHost:
    def __init__(self):
        self.service = {"active": False, "enabled": False}
        self.fail_activate = False
        self.fail_validate = False
        self.fail_restore = False
        self.activations = 0
        self.validations = []

    def run(self, *args):
        return None

    def service_state(self):
        return self.service.copy()

    def validate(self, directory):
        self.validations.append(directory)
        if self.fail_validate:
            raise ToolkitError("Invalid configuration")
        if not (directory / "jail.conf").exists():
            raise ToolkitError("Missing full configuration")

    def activate(self):
        self.activations += 1
        self.service = {"active": True, "enabled": True}
        if self.fail_activate:
            raise ToolkitError("Simulated restart failure")

    def restore_service(self, state):
        if self.fail_restore:
            raise ToolkitError("Simulated recovery failure")
        self.service = state.copy()


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "etc" / "fail2ban"
        (self.config / "jail.d").mkdir(parents=True)
        (self.config / "jail.conf").write_text("[DEFAULT]\nbantime = 600\n[sshd]\nenabled = false\n")
        self.host = FakeHost()
        self.deploy = Deployment(self.host, self.config, self.root / "state")
        self.settings = Settings(["192.0.2.1"], [22])

    def test_apply_is_idempotent_and_rollback_removes_only_own_file(self):
        unrelated = self.config / "jail.d" / "web.local"
        unrelated.write_text("[nginx-http-auth]\nenabled = false\n")
        self.deploy.apply(self.settings)
        self.assertTrue(self.host.service["active"])
        self.deploy.apply(self.settings)
        self.assertEqual(self.host.activations, 1)
        self.deploy.rollback()
        self.assertFalse(self.deploy.target.exists())
        self.assertTrue(unrelated.exists())
        self.assertEqual(self.host.service, {"active": False, "enabled": False})

    def test_updates_can_be_rolled_back_in_order(self):
        self.deploy.apply(self.settings)
        original = self.deploy.current()
        self.deploy.apply(Settings(["192.0.2.2"], [22]))
        self.deploy.rollback()
        self.assertEqual(self.deploy.current(), original)
        self.assertTrue(self.host.service["active"])
        self.deploy.rollback()
        self.assertIsNone(self.deploy.current())

    def test_stage_failure_does_not_touch_live_files(self):
        self.host.fail_validate = True
        with self.assertRaises(ToolkitError):
            self.deploy.apply(self.settings)
        self.assertFalse(self.deploy.target.exists())
        self.assertEqual(self.host.activations, 0)
        self.assertFalse(self.deploy.pending_path.exists())

    def test_activation_failure_restores_prior_deployment_and_service(self):
        self.deploy.apply(self.settings)
        original = self.deploy.current()
        state = self.deploy.state_path.read_bytes()
        self.host.fail_activate = True
        with self.assertRaisesRegex(ToolkitError, "previous configuration and service state restored"):
            self.deploy.apply(Settings(["192.0.2.2"], [22]))
        self.assertEqual(self.deploy.current(), original)
        self.assertEqual(self.deploy.state_path.read_bytes(), state)
        self.assertTrue(self.host.service["active"])
        self.assertFalse(self.deploy.pending_path.exists())

    def test_first_activation_failure_restores_disabled_service(self):
        self.host.fail_activate = True
        with self.assertRaises(ToolkitError):
            self.deploy.apply(self.settings)
        self.assertFalse(self.deploy.target.exists())
        self.assertFalse(self.host.service["enabled"])
        self.assertFalse(self.deploy.state_path.exists())

    def test_failed_recovery_keeps_journal_and_can_be_retried(self):
        self.host.fail_activate = self.host.fail_restore = True
        with self.assertRaisesRegex(ToolkitError, "Recovery also failed"):
            self.deploy.apply(self.settings)
        self.assertTrue(self.deploy.pending_path.exists())
        self.host.fail_restore = False
        self.deploy.rollback()
        self.assertFalse(self.deploy.pending_path.exists())

    def test_interrupt_after_live_write_can_be_recovered(self):
        with patch.object(self.host, "activate", side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                self.deploy.apply(self.settings)
        self.assertTrue(self.deploy.pending_path.exists())
        with self.assertRaisesRegex(ToolkitError, "interrupted"):
            self.deploy.apply(self.settings)
        self.deploy.rollback()
        self.assertIsNone(self.deploy.current())

    def test_external_edits_are_preserved(self):
        self.deploy.apply(self.settings)
        self.deploy.target.write_text("[sshd]\nenabled = false\n")
        for operation in [lambda: self.deploy.apply(self.settings), self.deploy.rollback]:
            with self.assertRaisesRegex(ToolkitError, "changed outside"):
                operation()
        self.assertIn("enabled = false", self.deploy.current())

    def test_untracked_target_is_not_overwritten(self):
        self.deploy.target.write_text("custom file")
        with self.assertRaisesRegex(ToolkitError, "not tracked"):
            self.deploy.apply(self.settings)
        self.assertEqual(self.deploy.current(), "custom file")

    def test_conflicting_admin_settings_are_rejected(self):
        override = self.config / "jail.local"
        for text in ["[sshd]\nenabled = true\n", "[DEFAULT]\naction = custom\n", "[INCLUDES]\nbefore = custom.conf\n"]:
            override.write_text(text)
            with self.subTest(text=text), self.assertRaises(ToolkitError):
                self.deploy.apply(self.settings)
        self.assertFalse(self.deploy.target.exists())

    def test_ubuntu_package_default_is_allowed_but_custom_additions_are_not(self):
        path = self.config / "jail.d" / "defaults-debian.conf"
        for text in ("[sshd]\nenabled = true\nbackend = systemd\n", "[DEFAULT]\nbackend = systemd\n[sshd]\nenabled = true\n", "[DEFAULT]\nbanaction = nftables\nbanaction_allports = nftables[type=allports]\nbackend = systemd\n[sshd]\nenabled = true\n"):
            path.write_text(text)
            check_conflicts(self.config, self.deploy.target)
        path.write_text(path.read_text() + "action = custom\n")
        with self.assertRaises(ToolkitError):
            check_conflicts(self.config, self.deploy.target)

    @unittest.skipUnless(os.name == "posix", "Linux symlink behavior")
    def test_symlink_target_is_refused(self):
        other = self.root / "other"
        other.write_text("keep")
        self.deploy.target.symlink_to(other)
        with self.assertRaises(ToolkitError):
            self.deploy.apply(self.settings)
        self.assertEqual(other.read_text(), "keep")


class CLITests(unittest.TestCase):
    def test_help_from_another_working_directory(self):
        launcher = Path(__file__).resolve().parents[1] / "bin" / "f2b-tool"
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(launcher), "--help"], cwd=directory, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in ("doctor", "configure", "plan", "apply", "rollback"):
            self.assertIn(command, result.stdout)


if __name__ == "__main__":
    unittest.main()
