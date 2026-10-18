"""Load OSV-format advisories and match them against installed packages.

Works fully offline from a directory of OSV JSON records (the format published
by https://osv.dev and most distributions); optionally augments results with
a live query to the OSV API. Version ranges are evaluated with the target's
native version comparison, so an advisory matches exactly the affected
versions and no others.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from ..models import HostInfo, Severity
from . import version as ver
from .cvss import base_score, score_to_severity

log = logging.getLogger(__name__)

# package-manager scheme -> OSV ecosystem families that use it
_ECOSYSTEMS = {
    "dpkg": {"Debian", "Ubuntu"},
    "rpm": {"Rocky Linux", "AlmaLinux", "Red Hat", "CentOS", "Fedora", "openSUSE", "SUSE"},
}


@dataclass
class Advisory:
    id: str
    summary: str
    severity: Severity
    cvss: str = ""
    references: list[str] = field(default_factory=list)
    # package name -> list of (ecosystem, ranges, explicit_versions)
    affected: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass
class VulnMatch:
    package: str
    installed_version: str
    advisory_id: str
    severity: Severity
    summary: str
    fixed_version: str
    references: list[str]


# Specific distro name (lower-cased substring of os NAME) -> OSV ecosystem family.
_DISTRO_FAMILY = {
    "ubuntu": "Ubuntu", "debian": "Debian", "rocky": "Rocky Linux", "alma": "AlmaLinux",
    "red hat": "Red Hat", "rhel": "Red Hat", "centos": "CentOS", "fedora": "Fedora",
    "opensuse": "openSUSE", "suse": "SUSE",
}


def detect_scheme(host: HostInfo) -> tuple[str, set[str]]:
    """Return (version scheme, OSV ecosystem families to match against).

    When the specific distribution is recognised, only that family is matched,
    so a Ubuntu host is not flagged by a Debian-only advisory and vice versa.
    """
    scheme = host.package_manager or "dpkg"
    name = (host.os_name or "").lower()
    for marker, family in _DISTRO_FAMILY.items():
        if marker in name:
            return scheme, {family}
    return scheme, _ECOSYSTEMS.get(scheme, set())


def _severity_of(record: dict[str, Any]) -> tuple[Severity, str]:
    # 1. explicit textual severity from database_specific
    text = (record.get("database_specific", {}) or {}).get("severity", "")
    cvss = ""
    for entry in record.get("severity", []) or []:
        if entry.get("type", "").startswith("CVSS") and entry.get("score"):
            cvss = entry["score"]
            if cvss.startswith("CVSS:"):
                score = base_score(cvss)
                if score is not None:
                    return Severity(score_to_severity(score)), cvss
    if isinstance(text, str) and text.lower() in [s.value for s in Severity]:
        return Severity(text.lower()), cvss
    if isinstance(text, str) and text.upper() in ("MODERATE",):
        return Severity.MEDIUM, cvss
    return Severity.MEDIUM, cvss  # unknown severity defaults to medium, never silent


def parse_advisory(record: dict[str, Any]) -> Advisory | None:
    if not record.get("id") or not record.get("affected"):
        return None
    severity, cvss = _severity_of(record)
    advisory = Advisory(
        id=str(record["id"]), summary=str(record.get("summary") or record.get("details", ""))[:300],
        severity=severity, cvss=cvss,
        references=[r.get("url", "") for r in record.get("references", []) if r.get("url")][:5],
    )
    for entry in record["affected"]:
        package = entry.get("package", {})
        name = package.get("name")
        ecosystem = package.get("ecosystem", "")
        if not name:
            continue
        advisory.affected.setdefault(name, []).append({
            "ecosystem": ecosystem,
            "ranges": entry.get("ranges", []),
            "versions": entry.get("versions", []),
        })
    return advisory or None


def _fixed_version(ranges: list[dict[str, Any]]) -> str:
    for rng in ranges:
        for event in rng.get("events", []):
            if "fixed" in event:
                return event["fixed"]
    return ""


def _affected(version: str, affected_entry: dict[str, Any], scheme: str) -> bool:
    if version in affected_entry.get("versions", []):
        return True
    for rng in affected_entry.get("ranges", []):
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER", None):
            continue
        vulnerable = False
        for event in rng.get("events", []):
            if "introduced" in event:  # becomes affected at/after this version
                intro = event["introduced"]
                if intro == "0" or ver.compare(version, intro, scheme) >= 0:
                    vulnerable = True
            elif "fixed" in event:  # no longer affected at/after the fix
                if ver.compare(version, event["fixed"], scheme) >= 0:
                    vulnerable = False
            elif "last_affected" in event:  # no longer affected beyond this version
                if ver.compare(version, event["last_affected"], scheme) > 0:
                    vulnerable = False
        if vulnerable:
            return True
    return False


class AdvisoryDatabase:
    def __init__(self, advisories: list[Advisory], scheme: str, families: set[str]) -> None:
        self.scheme = scheme
        self.families = families
        self._by_package: dict[str, list[Advisory]] = {}
        for advisory in advisories:
            for name in advisory.affected:
                self._by_package.setdefault(name, []).append(advisory)
        self.count = len(advisories)

    @classmethod
    def load(cls, directory: str | Path, host: HostInfo) -> AdvisoryDatabase:
        scheme, families = detect_scheme(host)
        advisories: list[Advisory] = []
        path = Path(directory)
        if path.is_dir():
            for file in sorted(path.rglob("*.json")):
                advisories += _load_file(file)
        return cls(advisories, scheme, families)

    def match(self, packages: list[tuple[str, str]]) -> list[VulnMatch]:
        matches: list[VulnMatch] = []
        for name, installed in packages:
            for advisory in self._by_package.get(name, []):
                for entry in advisory.affected.get(name, []):
                    family = entry["ecosystem"].split(":")[0]
                    if self.families and family and family not in self.families:
                        continue
                    if _affected(installed, entry, self.scheme):
                        matches.append(VulnMatch(
                            package=name, installed_version=installed, advisory_id=advisory.id,
                            severity=advisory.severity, summary=advisory.summary,
                            fixed_version=_fixed_version(entry["ranges"]),
                            references=advisory.references))
                        break
        return matches


def _load_file(file: Path) -> list[Advisory]:
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("could not read advisory %s: %s", file.name, exc)
        return []
    records = data if isinstance(data, list) else [data]
    return [adv for record in records if (adv := parse_advisory(record))]


def query_osv_api(packages: list[tuple[str, str]], families: set[str], scheme: str,
                  timeout: float = 20.0) -> list[VulnMatch]:
    """Query https://api.osv.dev for the installed packages (optional, networked)."""
    ecosystem = next(iter(sorted(families)), "Debian")
    queries = [{"version": v, "package": {"name": n, "ecosystem": ecosystem}}
               for n, v in packages]
    matches: list[VulnMatch] = []
    try:
        with httpx.Client(timeout=timeout) as client:
            for chunk_start in range(0, len(queries), 1000):
                batch = queries[chunk_start:chunk_start + 1000]
                resp = client.post("https://api.osv.dev/v1/querybatch",
                                   json={"queries": batch})
                resp.raise_for_status()
                for query, result in zip(batch, resp.json().get("results", []), strict=False):
                    for vuln in result.get("vulns", []) or []:
                        matches.append(VulnMatch(
                            package=query["package"]["name"], installed_version=query["version"],
                            advisory_id=vuln.get("id", "?"), severity=Severity.MEDIUM,
                            summary="", fixed_version="", references=[]))
    except httpx.HTTPError as exc:
        log.warning("OSV API query failed: %s", type(exc).__name__)
    return matches
