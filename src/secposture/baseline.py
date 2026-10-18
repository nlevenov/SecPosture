"""Compare an audit against a saved baseline to track posture over time."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import AuditResult, Finding, Status


@dataclass
class BaselineDiff:
    score_before: int
    score_after: int
    new_failures: list[Finding] = field(default_factory=list)   # regressions
    resolved: list[Finding] = field(default_factory=list)       # fixed since baseline
    still_open: list[Finding] = field(default_factory=list)
    new_controls: list[str] = field(default_factory=list)       # controls added to catalog

    @property
    def score_delta(self) -> int:
        return self.score_after - self.score_before

    @property
    def regressed(self) -> bool:
        return bool(self.new_failures) or self.score_after < self.score_before

    def summary(self) -> dict[str, int]:
        return {"score_before": self.score_before, "score_after": self.score_after,
                "score_delta": self.score_delta, "new_failures": len(self.new_failures),
                "resolved": len(self.resolved), "still_open": len(self.still_open)}


def diff(baseline: AuditResult, current: AuditResult) -> BaselineDiff:
    before = {f.control_id: f for f in baseline.findings}
    after = {f.control_id: f for f in current.findings}

    result = BaselineDiff(score_before=baseline.score, score_after=current.score)
    for control_id, finding in after.items():
        was = before.get(control_id)
        if finding.is_open and (was is None or not was.is_open):
            result.new_failures.append(finding)
        elif finding.is_open:
            result.still_open.append(finding)
        if was is None:
            result.new_controls.append(control_id)
    for control_id, finding in before.items():
        now = after.get(control_id)
        if finding.is_open and (now is None or not now.is_open):
            result.resolved.append(finding)

    order = {Status.FAIL: 0, Status.WARN: 1}
    result.new_failures.sort(key=lambda f: (order.get(f.status, 2), -f.severity.rank))
    result.resolved.sort(key=lambda f: -f.severity.rank)
    return result
