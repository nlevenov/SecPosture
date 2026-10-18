"""Posture score and letter grade.

The score is the share of severity-weighted controls a host passes, so a
single critical failure costs far more than several low-severity ones. A
warning (partial / needs-review) earns half credit. Package vulnerabilities
are scored like any other failed control of the same severity.
"""

from __future__ import annotations

from .config import ScoringSettings
from .models import AuditResult, Finding, Status

# Scoring weight per severity (info counts a little so it is not free).
_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 1}


def _weight(finding: Finding) -> int:
    return _WEIGHT[finding.severity.value]


def score(result: AuditResult, settings: ScoringSettings | None = None) -> AuditResult:
    settings = settings or ScoringSettings()
    scored = [f for f in result.findings
              if f.status in (Status.PASS, Status.FAIL, Status.WARN)]
    possible = sum(_weight(f) for f in scored)
    if possible == 0:
        result.score, result.grade = 100, "A"
        return result
    earned = sum(_weight(f) for f in scored if f.status == Status.PASS)
    earned += sum(_weight(f) * 0.5 for f in scored if f.status == Status.WARN)
    result.score = round(100 * earned / possible)
    result.grade = grade_for(result.score, settings)
    return result


def grade_for(value: int, settings: ScoringSettings) -> str:
    if value >= settings.grade_a:
        return "A"
    if value >= settings.grade_b:
        return "B"
    if value >= settings.grade_c:
        return "C"
    if value >= settings.grade_d:
        return "D"
    return "F"


def pass_rate(result: AuditResult) -> tuple[int, int]:
    """(passed, applicable) control count, ignoring not-applicable/manual/error."""
    applicable = [f for f in result.findings
                  if f.status in (Status.PASS, Status.FAIL, Status.WARN)]
    passed = sum(1 for f in applicable if f.status == Status.PASS)
    return passed, len(applicable)
