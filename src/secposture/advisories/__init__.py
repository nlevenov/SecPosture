"""Known-vulnerability scanning of installed packages (OSV advisories)."""

from __future__ import annotations

import shlex

from ..collectors.base import HostFacts
from ..models import Category, Finding, HostInfo, Status
from ..sanitize import clean
from .osv import AdvisoryDatabase, VulnMatch, detect_scheme, query_osv_api

__all__ = ["AdvisoryDatabase", "VulnMatch", "scan_packages"]


def scan_packages(facts: HostFacts, host: HostInfo, local_dir: str, *,
                  use_api: bool = False, api_timeout: float = 20.0) -> list[Finding]:
    """Return one finding per vulnerable installed package (highest severity wins)."""
    if not facts.packages:
        return []
    scheme, families = detect_scheme(host)
    matches: list[VulnMatch] = []
    if local_dir:
        matches += AdvisoryDatabase.load(local_dir, host).match(facts.packages)
    if use_api:
        seen = {(m.package, m.advisory_id) for m in matches}
        matches += [m for m in query_osv_api(facts.packages, families, scheme, api_timeout)
                    if (m.package, m.advisory_id) not in seen]

    by_package: dict[str, list[VulnMatch]] = {}
    for match in matches:
        by_package.setdefault(match.package, []).append(match)

    findings: list[Finding] = []
    for package, package_matches in sorted(by_package.items()):
        worst = max(package_matches, key=lambda m: m.severity.rank)
        ids = sorted({m.advisory_id for m in package_matches})
        fixed = sorted({m.fixed_version for m in package_matches if m.fixed_version})
        installed = package_matches[0].installed_version
        remediation = (f"Update {package} to {fixed[-1]} or later."
                       if fixed else f"Update {package} to a patched release.")
        findings.append(Finding(
            control_id=f"PKG-{clean(package, 60)}",
            title=f"{package} has known vulnerabilities",
            category=Category.PACKAGES, severity=worst.severity, status=Status.FAIL,
            detail=f"{package} {installed}: {len(ids)} advisory(ies) "
                   f"({', '.join(ids[:6])}{'...' if len(ids) > 6 else ''})",
            evidence={"package": clean(package, 60), "installed": clean(installed, 60),
                      "advisories": [clean(i, 60) for i in ids],
                      "fixed_version": clean(fixed[-1], 60) if fixed else "",
                      "summaries": [clean(m.summary, 300) for m in package_matches[:10]]},
            remediation=remediation,
            references=tuple(clean(r, 300) for m in package_matches for r in m.references)[:5],
            fix_commands=[f"sudo apt-get install --only-upgrade {shlex.quote(package)}"]
            if scheme == "dpkg" else [f"sudo dnf update {shlex.quote(package)}"],
        ))
    return findings
