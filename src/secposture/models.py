"""Core data model shared across collection, evaluation and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return ("info", "low", "medium", "high", "critical").index(self.value)

    @property
    def weight(self) -> int:
        """How much an open finding of this severity costs the posture score."""
        return {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}[self.value]


class Status(str, Enum):
    PASS = "pass"  # nosec B105 - control status value, not a credential
    FAIL = "fail"
    WARN = "warn"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"           # the control could not be evaluated (missing data)
    MANUAL = "manual"         # requires a human decision; reported, not scored


# Control categories, used for grouping in reports.
class Category(str, Enum):
    SSH = "ssh"
    ACCOUNTS = "accounts"
    FILESYSTEM = "filesystem"
    KERNEL = "kernel"
    NETWORK = "network"
    SERVICES = "services"
    PACKAGES = "packages"


@dataclass(frozen=True)
class Control:
    """A single hardening check. Pure metadata; the logic lives in a registered
    function (see ``controls``)."""

    id: str                       # e.g. "SSH-01"
    title: str
    category: Category
    severity: Severity
    rationale: str
    remediation: str
    profiles: tuple[str, ...] = ("server", "workstation")
    references: tuple[str, ...] = ()

    def applies_to(self, profile: str) -> bool:
        return profile in self.profiles


@dataclass
class Finding:
    control_id: str
    title: str
    category: Category
    severity: Severity
    status: Status
    detail: str = ""              # human-readable result, already sanitized
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: tuple[str, ...] = ()
    fix_commands: list[str] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        """A finding that counts against the score and needs attention."""
        return self.status in (Status.FAIL, Status.WARN)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        data["references"] = list(self.references)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            control_id=data["control_id"], title=data["title"],
            category=Category(data["category"]), severity=Severity(data["severity"]),
            status=Status(data["status"]), detail=data.get("detail", ""),
            evidence=data.get("evidence", {}), remediation=data.get("remediation", ""),
            references=tuple(data.get("references", [])),
            fix_commands=list(data.get("fix_commands", [])),
        )


@dataclass
class HostInfo:
    hostname: str = "localhost"
    transport: str = "local"      # local | ssh
    target: str = ""              # user@host for ssh
    os_name: str = ""
    os_version: str = ""
    kernel: str = ""
    package_manager: str = ""     # dpkg | rpm | ""
    privileged: bool = False      # ran as root / could read root-only files
    collected_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditResult:
    host: HostInfo
    profile: str
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    grade: str = "?"
    collection_errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    tool_version: str = ""

    def by_status(self, status: Status) -> list[Finding]:
        return [f for f in self.findings if f.status == status]

    @property
    def open_findings(self) -> list[Finding]:
        order = {Status.FAIL: 0, Status.WARN: 1}
        return sorted(
            (f for f in self.findings if f.is_open),
            key=lambda f: (order[f.status], -f.severity.rank, f.control_id),
        )

    def counts(self) -> dict[str, int]:
        result = {s.value: 0 for s in Status}
        for finding in self.findings:
            result[finding.status.value] += 1
        return result

    def severity_counts(self) -> dict[str, int]:
        result = {s.value: 0 for s in Severity}
        for finding in self.open_findings:
            result[finding.severity.value] += 1
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_version": self.tool_version,
            "profile": self.profile,
            "host": self.host.to_dict(),
            "score": self.score,
            "grade": self.grade,
            "duration_seconds": round(self.duration_seconds, 2),
            "counts": self.counts(),
            "severity_counts": self.severity_counts(),
            "collection_errors": self.collection_errors,
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditResult:
        host = HostInfo(**data["host"])
        result = cls(
            host=host, profile=data["profile"],
            findings=[Finding.from_dict(f) for f in data["findings"]],
            score=data["score"], grade=data["grade"],
            collection_errors=data.get("collection_errors", []),
            duration_seconds=data.get("duration_seconds", 0.0),
            tool_version=data.get("tool_version", ""),
        )
        return result
