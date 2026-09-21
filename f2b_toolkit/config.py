"""Validated data and deterministic configuration rendering; no shell evaluation."""
import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from string import Template


class ToolkitError(Exception):
    """An actionable user-facing failure."""


@dataclass(frozen=True)
class Settings:
    trusted_ips: list[str]
    ports: list[int]
    backend: str = "systemd"
    bantime: int = 600
    findtime: int = 600
    maxretry: int = 5

    def __post_init__(self):
        if not isinstance(self.trusted_ips, list) or not self.trusted_ips:
            raise ToolkitError("Supply at least one trusted administrator IP or CIDR.")
        networks = []
        for value in self.trusted_ips:
            if not isinstance(value, str) or "%" in value:
                raise ToolkitError("Trusted addresses must be IP addresses or CIDRs.")
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ToolkitError(f"Invalid trusted IP/CIDR: {value!r}") from exc
            if net.prefixlen == 0 or net.is_multicast or net.is_unspecified:
                raise ToolkitError("A trusted range must not cover every address or be multicast/unspecified.")
            networks.append(str(net))
        object.__setattr__(self, "trusted_ips", sorted(set(networks)))
        if not isinstance(self.ports, list) or not self.ports or any(
            type(p) is not int or not 1 <= p <= 65535 for p in self.ports
        ):
            raise ToolkitError("SSH ports must be integers between 1 and 65535.")
        object.__setattr__(self, "ports", sorted(set(self.ports)))
        if self.backend not in ("systemd", "polling"):
            raise ToolkitError("Backend must be systemd or polling.")
        for key, low, high in (("bantime", 60, 604800), ("findtime", 60, 86400), ("maxretry", 1, 100)):
            value = getattr(self, key)
            if type(value) is not int or not low <= value <= high:
                raise ToolkitError(f"{key} must be an integer between {low} and {high}.")

    def check_connection(self, connection: str):
        if not connection:
            return
        try:
            client, _, _, server_port = connection.split()
            address = ipaddress.ip_address(client)
            port = int(server_port)
        except ValueError as exc:
            raise ToolkitError("Cannot parse SSH_CONNECTION; verify access from the server console.") from exc
        if not any(address in ipaddress.ip_network(net) for net in self.trusted_ips):
            raise ToolkitError(f"Current SSH client {address} is not in the trusted ranges.")
        if port not in self.ports:
            raise ToolkitError(f"Current SSH server port {port} is absent from the plan.")

    def render(self) -> str:
        template = Path(__file__).resolve().parents[1] / "templates" / "sshd.local.tpl"
        return Template(template.read_text(encoding="utf-8")).substitute(
            ports=",".join(map(str, self.ports)),
            trusted_ips=" ".join(dict.fromkeys(["127.0.0.0/8", "::1/128", *self.trusted_ips])),
            backend=self.backend,
            log_source="journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd" if self.backend == "systemd" else "logpath = /var/log/auth.log\njournalmatch =",
            bantime=self.bantime, findtime=self.findtime, maxretry=self.maxretry,
        )

    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"version": 1, "settings": asdict(self)}, indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or set(data) != {"version", "settings"} or type(data["version"]) is not int or data["version"] != 1:
                raise ValueError("Unsupported plan schema")
            if not isinstance(data["settings"], dict) or set(data["settings"]) != set(cls.__dataclass_fields__):
                raise ValueError("Unexpected settings fields")
            return cls(**data["settings"])
        except (OSError, ValueError, TypeError) as exc:
            raise ToolkitError(f"Cannot read plan {path}: {exc}") from exc
