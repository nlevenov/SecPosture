"""Self-contained HTML report (no external assets)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import AuditResult, Status
from ..scoring import pass_rate
from .charts import SEVERITY_COLORS, category_bars, score_gauge, severity_donut

_TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(str(_TEMPLATES)),
                   autoescape=select_autoescape(["html"]))

_CATEGORY_ORDER = ("ssh", "accounts", "filesystem", "kernel", "network", "services", "packages")
_TRANSPORT = {"local": "local scan", "ssh": "remote scan over SSH"}


def _category_rows(result: AuditResult) -> list[tuple[str, int, int]]:
    buckets: dict[str, list[int]] = {}
    for f in result.findings:
        if f.status in (Status.PASS, Status.FAIL, Status.WARN):
            entry = buckets.setdefault(f.category.value, [0, 0])
            entry[1] += 1
            if f.status == Status.PASS:
                entry[0] += 1
    return [(cat, buckets[cat][0], buckets[cat][1])
            for cat in _CATEGORY_ORDER if cat in buckets]


def render_html(result: AuditResult) -> str:
    passed, applicable = pass_rate(result)
    open_findings = result.open_findings
    other = sorted((f for f in result.findings if not f.is_open),
                   key=lambda f: (f.status.value, f.control_id))
    for f in list(open_findings) + other:
        f.evidence_json = json.dumps(f.evidence, indent=2) if f.evidence else ""  # type: ignore
    template = _env.get_template("report.html")
    return template.render(
        host=result.host, profile=result.profile, tool_version=result.tool_version,
        transport_label=_TRANSPORT.get(result.host.transport, result.host.transport),
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        counts=result.counts(), severity_counts=result.severity_counts(),
        passed=passed, applicable=applicable, open_findings=open_findings,
        other_findings=other, collection_errors=result.collection_errors,
        sev_colors=SEVERITY_COLORS,
        gauge=score_gauge(result.score, result.grade),
        donut=severity_donut(result.severity_counts()),
        bars=category_bars(_category_rows(result)),
    )


def write_html(result: AuditResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result), encoding="utf-8")
    return path
