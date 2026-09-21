"""Atomic file replacement, durable recovery records, and managed-file rollback."""
import contextlib
import hashlib
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from .config import ToolkitError
from .system import check_conflicts

MANAGED_NAME = "90-toolkit-sshd.local"


def digest(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def regular_path(path):
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ToolkitError(f"Refusing symlink path: {parent}")
    if path.exists() and not path.is_file():
        raise ToolkitError(f"Expected a regular file: {path}")


def atomic_write(path, text, mode=0o600):
    regular_path(path)
    fd, temporary = tempfile.mkstemp(prefix=".f2b-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Deployment:
    def __init__(self, host, config_dir=Path("/etc/fail2ban"), state_dir=Path("/var/lib/f2b-toolkit")):
        self.host = host
        self.config = config_dir
        self.root = state_dir
        self.target = config_dir / "jail.d" / MANAGED_NAME
        self.state_path = state_dir / "state.json"
        self.pending_path = state_dir / "pending.json"

    def read_json(self, path):
        regular_path(path)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Expected an object")
            return data
        except ValueError as exc:
            raise ToolkitError(f"Invalid recovery data in {path}; inspect the saved backups.") from exc

    def write_json(self, path, data):
        atomic_write(path, json.dumps(data, indent=2) + "\n")

    def current(self):
        regular_path(self.target)
        return self.target.read_text(encoding="utf-8") if self.target.exists() else None

    def prepare(self):
        regular_path(self.state_path)
        regular_path(self.pending_path)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            info = self.root.stat()
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ToolkitError(f"{self.root} must be owned by the current user with mode 0700.")

    @contextlib.contextmanager
    def lock(self):
        import fcntl
        self.prepare()
        path = self.root / "lock"
        regular_path(path)
        with path.open("a") as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ToolkitError("Another toolkit operation is running.") from exc
            yield

    def check_owned(self):
        current = self.current()
        state = self.read_json(self.state_path)
        if state is not None and (set(state) != {"id", "digest"} or not all(isinstance(state[key], str) for key in state)):
            raise ToolkitError("Invalid state.json; inspect the saved backups.")
        if state is None and current is not None:
            raise ToolkitError(f"{self.target} exists but is not tracked by this toolkit.")
        if state is not None and (current is None or digest(current) != state["digest"]):
            raise ToolkitError("Managed configuration was changed outside the toolkit. Reconcile it before applying or rolling back.")
        return current, state

    def stage(self, content):
        # -t parses a copy of the complete configuration, including other jails.
        with tempfile.TemporaryDirectory(prefix="f2b-stage-", dir=self.root) as temp:
            staged = Path(temp) / "fail2ban"
            shutil.copytree(self.config, staged)
            target = staged / "jail.d" / MANAGED_NAME
            if content is None:
                target.unlink(missing_ok=True)
            else:
                target.write_text(content, encoding="utf-8")
            self.host.validate(staged)

    def set_content(self, content):
        regular_path(self.target)
        if content is None:
            self.target.unlink(missing_ok=True)
        else:
            atomic_write(self.target, content, mode=0o640)

    def restore(self, record):
        self.set_content(record["before"])
        self.host.validate(self.config)
        self.host.restore_service(record["service"])
        if record["previous_state"] is None:
            self.state_path.unlink(missing_ok=True)
        else:
            self.write_json(self.state_path, record["previous_state"])
        self.pending_path.unlink(missing_ok=True)

    def apply(self, settings):
        self.prepare()
        if self.pending_path.exists():
            raise ToolkitError("An interrupted deployment needs recovery. Run rollback first.")
        check_conflicts(self.config, self.target)
        before, state = self.check_owned()
        content = settings.render()
        self.stage(content)
        if content == before:
            self.host.run("fail2ban-client", "status", "sshd")
            return "Configuration already matches; no files or service settings changed."
        identifier = uuid.uuid4().hex
        backup = self.root / "deployments" / identifier
        backup.mkdir(parents=True, mode=0o700)
        record = {"id": identifier, "before": before, "after": content,
                  "service": self.host.service_state(), "previous_state": state}
        self.write_json(backup / "record.json", record)
        # Journal before changing the live configuration, including before first deployment.
        self.write_json(self.pending_path, record)
        try:
            self.set_content(content)
            self.host.validate(self.config)
            self.host.activate()
            self.write_json(self.state_path, {"id": identifier, "digest": digest(content)})
            self.pending_path.unlink()
        except (Exception, KeyboardInterrupt) as exc:
            try:
                self.restore(record)
            except Exception as recovery:
                raise ToolkitError(f"Deployment failed: {exc}\nRecovery also failed: {recovery}\nBackup: {backup}. Run rollback from the console.") from exc
            raise ToolkitError(f"Deployment failed; previous configuration and service state restored: {exc}") from exc
        return f"SSH jail applied. Backup: {backup}\nJail is active; firewall enforcement still needs a controlled external test."

    def rollback(self):
        self.prepare()
        record = self.read_json(self.pending_path)
        if record is not None:
            if self.current() not in (record["before"], record["after"]):
                raise ToolkitError("Configuration changed after the interrupted operation; inspect the backup before manual recovery.")
        else:
            _, state = self.check_owned()
            if state is None:
                raise ToolkitError("No toolkit deployment to roll back.")
            identifier = state["id"]
            if not isinstance(identifier, str) or len(identifier) != 32 or any(c not in "0123456789abcdef" for c in identifier):
                raise ToolkitError("Invalid deployment identifier in state.json.")
            record = self.read_json(self.root / "deployments" / identifier / "record.json")
            if record is None:
                raise ToolkitError("Deployment backup is missing.")
        self.stage(record["before"])
        self.write_json(self.pending_path, record)
        self.restore(record)
        return "Previous toolkit configuration and Fail2Ban service state restored. Installed packages remain installed."
