"""Minimal, deterministic CVSS v3.1 base-score calculator.

Advisories carry a CVSS vector but not always a numeric score. Computing the
base score from the vector (per the CVSS v3.1 specification) gives a stable
severity without depending on a scoring field that may be absent.
"""

from __future__ import annotations

import math

_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},        # adjusted for S:C below
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(value: float) -> float:
    return math.ceil(value * 10) / 10


def base_score(vector: str) -> float | None:
    """Return the CVSS v3.x base score for a vector string, or None if unparseable."""
    parts = {}
    for item in vector.strip().split("/"):
        key, _, val = item.partition(":")
        parts[key] = val
    # accept an explicit 3.x header, or a bare vector that still has the metrics
    if not parts.get("CVSS", "").startswith(("3.0", "3.1")) and "AV" not in parts:
        return None
    try:
        scope_changed = parts.get("S") == "C"
        pr = (_PR_CHANGED if scope_changed else _METRICS["PR"])[parts["PR"]]
        iss = 1 - (1 - _METRICS["C"][parts["C"]]) * (1 - _METRICS["I"][parts["I"]]) * \
            (1 - _METRICS["A"][parts["A"]])
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed
                  else 6.42 * iss)
        exploitability = 8.22 * _METRICS["AV"][parts["AV"]] * _METRICS["AC"][parts["AC"]] * \
            pr * _METRICS["UI"][parts["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)
    return _roundup(raw)


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"
