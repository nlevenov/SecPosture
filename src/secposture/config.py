"""Settings loaded from YAML with ${ENV_VAR} / ${ENV_VAR:-default} expansion.

A missing config file is fine - the defaults audit a standard Linux server.
Unknown keys are errors so a typo never silently disables a control group.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml

_ENV = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")
PROFILES = ("server", "workstation")


@dataclass
class SshSettings:
    port: int = 22
    connect_timeout: float = 15.0
    command_timeout: float = 30.0
    # Path to a known_hosts file. Host keys are verified against it and an
    # unknown key is refused (no blind trust-on-first-use).
    known_hosts: str = ""
    key_file: str = ""              # private key path; else agent / password
    allow_agent: bool = True


@dataclass
class AdvisorySettings:
    enabled: bool = True
    # directory of OSV-format advisory JSON files; empty = the bundled sample
    local_dir: str = ""
    use_osv_api: bool = False       # query https://api.osv.dev in addition
    api_timeout: float = 20.0


@dataclass
class ScoringSettings:
    # A..F cut-offs on the 0-100 posture score.
    grade_a: int = 90
    grade_b: int = 80
    grade_c: int = 70
    grade_d: int = 60


@dataclass
class DashboardSettings:
    password_hash: str = ""
    results_dir: str = "results"
    session_minutes: int = 720
    allowed_hosts: list[str] = field(default_factory=list)

    def allowed_hosts_ok(self, host: str) -> bool:
        return bool(self.allowed_hosts)


@dataclass
class Settings:
    profile: str = "server"
    # Controls to skip (by id or category), e.g. accepted risks.
    disabled_controls: list[str] = field(default_factory=list)
    # SUID/SGID binaries and listening ports known-good for this host, so the
    # report highlights only the unexpected ones.
    allowed_suid: list[str] = field(default_factory=list)
    allowed_listen_ports: list[int] = field(default_factory=list)
    signing_key: str = ""           # HMAC key for signed results / baselines
    ssh: SshSettings = field(default_factory=SshSettings)
    advisories: AdvisorySettings = field(default_factory=AdvisorySettings)
    scoring: ScoringSettings = field(default_factory=ScoringSettings)
    dashboard: DashboardSettings = field(default_factory=DashboardSettings)

    def validate(self) -> Settings:
        if self.profile not in PROFILES:
            raise ValueError(f"profile must be one of {PROFILES}")
        if not (self.scoring.grade_a > self.scoring.grade_b > self.scoring.grade_c
                > self.scoring.grade_d > 0):
            raise ValueError("scoring grade cut-offs must be strictly decreasing")
        if not 0 < self.ssh.port < 65536:
            raise ValueError("ssh.port out of range")
        for port in self.allowed_listen_ports:
            if not 0 < int(port) < 65536:
                raise ValueError(f"invalid allowed_listen_port {port}")
        return self


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def _coerce(value: str, type_name: str) -> Any:
    if type_name == "bool":
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if type_name == "int":
        return int(value)
    if type_name == "float":
        return float(value)
    if type_name.startswith("list"):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


def _build(cls: type, data: dict[str, Any], section: str = "") -> Any:
    if not isinstance(data, dict):
        raise ValueError(f"section '{section or 'root'}' must be a mapping")
    known = {f.name: f for f in fields(cls)}
    kwargs: dict[str, Any] = {}
    for key, value in data.items():
        if key not in known:
            raise ValueError(f"unknown setting '{section}{key}'")
        default = (known[key].default_factory() if callable(known[key].default_factory)
                   else None)
        if is_dataclass(default):
            value = _build(type(default), value or {}, f"{section}{key}.")
        elif isinstance(value, str):
            value = _coerce(value, str(known[key].type))
        kwargs[key] = value
    return cls(**kwargs)


def _default_advisories() -> str:
    """The advisory directory bundled with the package (used when none is set)."""
    bundled = Path(__file__).parent / "data" / "advisories"
    return str(bundled) if bundled.is_dir() else ""


def load_settings(path: str | os.PathLike[str] | None = None) -> Settings:
    candidate = path or os.environ.get("SECPOSTURE_CONFIG") or "config/settings.yaml"
    config_path = Path(candidate)
    if not config_path.exists():
        if path or os.environ.get("SECPOSTURE_CONFIG"):
            raise FileNotFoundError(config_path)
        settings = Settings()
    else:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        settings = _build(Settings, _expand(raw))
    if not settings.advisories.local_dir:
        settings.advisories.local_dir = _default_advisories()
    return settings.validate()
