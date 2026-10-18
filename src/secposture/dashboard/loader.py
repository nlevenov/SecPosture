"""Load saved audit results for the dashboard, verifying signatures."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from ..models import AuditResult
from ..results import load_result

log = logging.getLogger(__name__)


@dataclass
class LoadedResult:
    path: Path
    result: AuditResult
    trusted: bool


def load_results(directory: str, signing_key: str) -> tuple[list[LoadedResult], list[str]]:
    loaded: list[LoadedResult] = []
    skipped: list[str] = []
    base = Path(directory)
    for path in sorted(base.glob("*.sp.json")):
        try:
            result = load_result(path, signing_key, require_valid=True)
            loaded.append(LoadedResult(path, result, trusted=True))
        except ValueError:
            # signature failed: keep it but flag it, never silently drop
            try:
                result = load_result(path, signing_key, require_valid=False)
                loaded.append(LoadedResult(path, result, trusted=False))
            except (OSError, ValueError, KeyError) as exc:
                skipped.append(f"{path.name}: {exc}")
        except (OSError, KeyError) as exc:
            skipped.append(f"{path.name}: {exc}")
    return loaded, skipped


def latest_per_host(loaded: list[LoadedResult]) -> dict[str, LoadedResult]:
    latest: dict[str, LoadedResult] = {}
    for item in loaded:
        key = item.result.host.hostname or item.result.host.target or item.path.stem
        current = latest.get(key)
        if current is None or item.result.host.collected_at > current.result.host.collected_at:
            latest[key] = item
    return latest
