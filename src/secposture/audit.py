"""Orchestrates a full audit: collect -> evaluate -> score."""

from __future__ import annotations

import time

from . import __version__
from .advisories import scan_packages
from .collectors import Collector, gather, host_info
from .config import Settings
from .controls import CheckContext, evaluate, load_catalog
from .models import AuditResult
from .scoring import score


def run_audit(collector: Collector, settings: Settings) -> AuditResult:
    load_catalog()
    started = time.monotonic()

    info = host_info(collector)
    facts, errors = gather(collector)
    ctx = CheckContext(
        profile=settings.profile, host=info,
        allowed_suid=frozenset(settings.allowed_suid),
        allowed_listen_ports=frozenset(int(p) for p in settings.allowed_listen_ports),
    )
    findings = evaluate(facts, ctx, disabled=set(settings.disabled_controls))

    if settings.advisories.enabled and "PKG" not in settings.disabled_controls \
            and "packages" not in settings.disabled_controls:
        try:
            findings += scan_packages(
                facts, info, settings.advisories.local_dir,
                use_api=settings.advisories.use_osv_api,
                api_timeout=settings.advisories.api_timeout)
        except Exception as exc:  # advisory feed problems must not fail the audit
            errors.append(f"advisory scan: {type(exc).__name__}: {exc}")

    info.collected_at = facts.now
    result = AuditResult(
        host=info, profile=settings.profile, findings=findings,
        collection_errors=errors, tool_version=__version__,
        duration_seconds=time.monotonic() - started,
    )
    return score(result, settings.scoring)
