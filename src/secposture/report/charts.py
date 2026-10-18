"""Inline SVG charts for the HTML report.

Charts are generated from numeric counts only (no target-supplied text), so
the SVG can be embedded directly. The report ships no external assets, which
keeps it usable in air-gapped audit environments.
"""

from __future__ import annotations

import math

SEVERITY_COLORS = {"critical": "#d11149", "high": "#e8702a", "medium": "#e8c21d",
                   "low": "#3aa0d1", "info": "#9aa4b2"}
STATUS_COLORS = {"pass": "#2f9e44", "fail": "#d11149", "warn": "#e8a81d"}
GRADE_COLORS = {"A": "#2f9e44", "B": "#5aa02f", "C": "#e8a81d", "D": "#e8702a", "F": "#d11149"}


def score_gauge(score: int, grade: str) -> str:
    radius, stroke = 54, 12
    circ = 2 * math.pi * radius
    filled = circ * min(max(score, 0), 100) / 100
    color = GRADE_COLORS.get(grade, "#9aa4b2")
    return f"""<svg viewBox="0 0 140 140" width="140" height="140" role="img"
 aria-label="Posture score {score} out of 100, grade {grade}">
  <circle cx="70" cy="70" r="{radius}" fill="none" stroke="var(--track)" stroke-width="{stroke}"/>
  <circle cx="70" cy="70" r="{radius}" fill="none" stroke="{color}" stroke-width="{stroke}"
   stroke-linecap="round" stroke-dasharray="{filled:.2f} {circ:.2f}"
   transform="rotate(-90 70 70)"/>
  <text x="70" y="64" text-anchor="middle" font-size="30" font-weight="700"
   fill="var(--fg)">{score}</text>
  <text x="70" y="86" text-anchor="middle" font-size="13" fill="var(--muted)">/ 100</text>
  <text x="70" y="108" text-anchor="middle" font-size="18" font-weight="700"
   fill="{color}">Grade {grade}</text>
</svg>"""


def severity_donut(counts: dict[str, int]) -> str:
    items = [(k, v) for k, v in counts.items() if v > 0]
    total = sum(v for _, v in items)
    if total == 0:
        return ('<svg viewBox="0 0 140 140" width="140" height="140"><text x="70" y="74" '
                'text-anchor="middle" fill="var(--muted)">no open findings</text></svg>')
    radius, cx, cy = 54, 70, 70
    circ = 2 * math.pi * radius
    offset = 0.0
    segments = []
    for key, value in items:
        length = circ * value / total
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" '
            f'stroke="{SEVERITY_COLORS[key]}" stroke-width="20" '
            f'stroke-dasharray="{length:.2f} {circ - length:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>')
        offset += length
    return (f'<svg viewBox="0 0 140 140" width="140" height="140" role="img" '
            f'aria-label="{total} open findings by severity">{"".join(segments)}'
            f'<text x="70" y="66" text-anchor="middle" font-size="26" font-weight="700" '
            f'fill="var(--fg)">{total}</text>'
            f'<text x="70" y="84" text-anchor="middle" font-size="11" '
            f'fill="var(--muted)">open</text></svg>')


def category_bars(rows: list[tuple[str, int, int]]) -> str:
    """rows: (category, passed, applicable). Horizontal pass-rate bars."""
    if not rows:
        return ""
    bar_w, row_h, label_w = 260, 26, 110
    height = len(rows) * row_h + 10
    out = [f'<svg viewBox="0 0 {label_w + bar_w + 50} {height}" width="100%" '
           f'height="{height}" role="img" aria-label="pass rate by category">']
    for i, (name, passed, total) in enumerate(rows):
        y = i * row_h + 8
        rate = passed / total if total else 1.0
        fill = "#2f9e44" if rate >= 0.9 else "#e8a81d" if rate >= 0.6 else "#d11149"
        out.append(f'<text x="0" y="{y + 14}" font-size="12" fill="var(--fg)">{name}</text>')
        out.append(f'<rect x="{label_w}" y="{y + 3}" width="{bar_w}" height="14" rx="3" '
                   f'fill="var(--track)"/>')
        out.append(f'<rect x="{label_w}" y="{y + 3}" width="{bar_w * rate:.1f}" height="14" '
                   f'rx="3" fill="{fill}"/>')
        out.append(f'<text x="{label_w + bar_w + 8}" y="{y + 14}" font-size="11" '
                   f'fill="var(--muted)">{passed}/{total}</text>')
    out.append("</svg>")
    return "".join(out)
