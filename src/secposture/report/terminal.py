"""Rich (but dependency-free) terminal rendering of an audit result."""

from __future__ import annotations

import os
import sys

from ..models import AuditResult
from ..scoring import pass_rate

_RESET = "\033[0m"
_SEV_COLOR = {"critical": "\033[91m", "high": "\033[31m", "medium": "\033[33m",
              "low": "\033[36m", "info": "\033[90m"}
_STATUS_COLOR = {"pass": "\033[32m", "fail": "\033[91m", "warn": "\033[33m",
                 "not_applicable": "\033[90m", "error": "\033[35m", "manual": "\033[34m"}
_GRADE_COLOR = {"A": "\033[92m", "B": "\033[32m", "C": "\033[33m", "D": "\033[31m",
                "F": "\033[91m"}


def _use_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, color: str) -> str:
    return f"{color}{text}{_RESET}" if _use_color() else text


def render_terminal(result: AuditResult, show: str = "open") -> str:
    out: list[str] = []
    host = result.host
    passed, applicable = pass_rate(result)
    out.append("=" * 72)
    out.append(f"  SecPosture audit  -  {host.hostname or host.target or 'localhost'}  "
               f"({host.transport})")
    out.append("=" * 72)
    target = host.os_name or "unknown OS"
    out.append(f"  {target} {host.os_version}  kernel {host.kernel}  "
               f"{'root' if host.privileged else 'unprivileged'}")
    grade = _c(f" {result.grade} ", _GRADE_COLOR.get(result.grade, ""))
    out.append(f"  Posture score: {result.score}/100   Grade: {grade}   "
               f"Controls passed: {passed}/{applicable}   Profile: {result.profile}")

    sev = result.severity_counts()
    chips = "  ".join(_c(f"{k}:{v}", _SEV_COLOR[k]) for k, v in sev.items() if v)
    out.append(f"  Open findings by severity:  {chips or 'none'}")
    if not host.privileged:
        out.append(_c("  note: running unprivileged - some checks could not read "
                      "root-only files", _SEV_COLOR["info"]))
    out.append("")

    findings = result.open_findings if show == "open" else result.findings
    if show != "open":
        findings = sorted(findings, key=lambda f: (f.status.value, -f.severity.rank, f.control_id))
    if not findings:
        out.append(_c("  No open findings. ", _STATUS_COLOR["pass"]))
    for f in findings:
        badge = _c(f"{f.status.value.upper():<5}", _STATUS_COLOR[f.status.value])
        sev_badge = _c(f"{f.severity.value:<8}", _SEV_COLOR[f.severity.value])
        out.append(f"  {badge} [{sev_badge}] {f.control_id:<8} {f.title}")
        if f.detail:
            out.append(f"         {f.detail}")
    out.append("")
    if result.collection_errors:
        out.append(_c(f"  {len(result.collection_errors)} collection note(s) "
                      "(run with --verbose to see them)", _SEV_COLOR["info"]))
    out.append(f"  Completed in {result.duration_seconds:.1f}s")
    return "\n".join(out)
