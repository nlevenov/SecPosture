"""Hardening control catalog and evaluation engine.

Each control is pure: a function of the collected :class:`HostFacts` plus a
:class:`CheckContext`, returning a :class:`CheckOutcome`. No control touches
the target - evaluation happens entirely on already-collected data, which
makes the whole catalog unit-testable with fixtures and guarantees the audit
never changes the system it looks at.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..collectors.base import HostFacts
from ..models import Category, Control, Finding, HostInfo, Severity, Status
from ..sanitize import clean, clean_block


def q(value: object) -> str:
    """Shell-quote a target-derived value before it goes into a fix command.

    Filenames, usernames and package names come from the audited host and
    could contain shell metacharacters; quoting them keeps the generated
    remediation script from being turned into an injection vector.
    """
    return shlex.quote(str(value))


@dataclass
class CheckContext:
    profile: str = "server"
    host: HostInfo = field(default_factory=HostInfo)
    allowed_suid: frozenset[str] = frozenset()
    allowed_listen_ports: frozenset[int] = frozenset()


@dataclass
class CheckOutcome:
    status: Status
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    fix_commands: list[str] = field(default_factory=list)


CheckFn = Callable[[HostFacts, CheckContext], CheckOutcome]
REGISTRY: list[tuple[Control, CheckFn]] = []
_SEEN_IDS: set[str] = set()


def control(id: str, title: str, category: Category, severity: Severity, rationale: str,
            remediation: str, profiles: tuple[str, ...] = ("server", "workstation"),
            references: tuple[str, ...] = ()) -> Callable[[CheckFn], CheckFn]:
    if id in _SEEN_IDS:
        raise ValueError(f"duplicate control id {id}")
    _SEEN_IDS.add(id)
    ctrl = Control(id=id, title=title, category=category, severity=severity,
                   rationale=rationale, remediation=remediation, profiles=profiles,
                   references=references)

    def register(fn: CheckFn) -> CheckFn:
        REGISTRY.append((ctrl, fn))
        return fn

    return register


# ------------------------------------------------------------ outcome helpers
def ok(detail: str = "", **evidence: Any) -> CheckOutcome:
    return CheckOutcome(Status.PASS, detail, evidence)


def fail(detail: str, fix: list[str] | None = None, **evidence: Any) -> CheckOutcome:
    return CheckOutcome(Status.FAIL, detail, evidence, fix or [])


def warn(detail: str, fix: list[str] | None = None, **evidence: Any) -> CheckOutcome:
    return CheckOutcome(Status.WARN, detail, evidence, fix or [])


def not_applicable(detail: str = "", **evidence: Any) -> CheckOutcome:
    return CheckOutcome(Status.NOT_APPLICABLE, detail, evidence)


def manual(detail: str, **evidence: Any) -> CheckOutcome:
    return CheckOutcome(Status.MANUAL, detail, evidence)


def error(detail: str, **evidence: Any) -> CheckOutcome:
    return CheckOutcome(Status.ERROR, detail, evidence)


def _sanitize_evidence(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "..."
    if isinstance(value, str):
        return clean_block(value, 4096)
    if isinstance(value, dict):
        return {clean(str(k), 80): _sanitize_evidence(v, depth + 1)
                for k, v in list(value.items())[:200]}
    if isinstance(value, (list, tuple)):
        return [_sanitize_evidence(v, depth + 1) for v in list(value)[:200]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return clean(str(value))


def evaluate(facts: HostFacts, ctx: CheckContext,
             disabled: set[str] | None = None) -> list[Finding]:
    disabled = disabled or set()
    findings: list[Finding] = []
    for ctrl, fn in REGISTRY:
        if ctrl.id in disabled or ctrl.category.value in disabled:
            continue
        if not ctrl.applies_to(ctx.profile):
            continue
        try:
            outcome = fn(facts, ctx)
        except Exception as exc:  # a broken check must not sink the whole audit
            outcome = CheckOutcome(Status.ERROR, f"check raised {type(exc).__name__}: {exc}")
        findings.append(Finding(
            control_id=ctrl.id, title=ctrl.title, category=ctrl.category, severity=ctrl.severity,
            status=outcome.status, detail=clean(outcome.detail, 2000),
            evidence=_sanitize_evidence(outcome.evidence), remediation=ctrl.remediation,
            references=ctrl.references,
            fix_commands=[clean(c, 500) for c in outcome.fix_commands[:20]],
        ))
    return findings


def all_controls() -> list[Control]:
    return [ctrl for ctrl, _ in REGISTRY]


def load_catalog() -> None:
    """Import every control module so the registry is populated."""
    from . import accounts, filesystem, kernel, network, services, ssh  # noqa: F401
