import json

from secposture.advisories import scan_packages
from secposture.advisories.osv import AdvisoryDatabase, detect_scheme, parse_advisory
from secposture.models import HostInfo, Severity, Status

from conftest import SAMPLE_ADVISORIES
from helpers import facts

UBUNTU = HostInfo(package_manager="dpkg", os_name="Ubuntu 20.04.6 LTS")


_HIGH = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _advisory(pkg, ecosystem, introduced, fixed, cvss=_HIGH):
    return parse_advisory({
        "id": f"TEST-{pkg}", "summary": "test", "severity": [{"type": "CVSS_V3", "score": cvss}],
        "affected": [{"package": {"ecosystem": ecosystem, "name": pkg},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": introduced}, {"fixed": fixed}]}]}]})


def test_sample_advisory_matches_vulnerable_sudo():
    f = facts(packages=[("sudo", "1.8.31-1ubuntu1"), ("bash", "5.1-6")])
    findings = scan_packages(f, UBUNTU, SAMPLE_ADVISORIES)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.control_id == "PKG-sudo" and finding.severity == Severity.HIGH
    assert finding.status == Status.FAIL and "CVE-2021-3156" in finding.detail
    assert finding.evidence["fixed_version"] == "1.8.31-1ubuntu1.2"


def test_patched_version_is_not_flagged():
    f = facts(packages=[("sudo", "1.9.5p1-1ubuntu1")])
    assert scan_packages(f, UBUNTU, SAMPLE_ADVISORIES) == []


def test_ecosystem_is_distro_specific():
    scheme, families = detect_scheme(UBUNTU)
    assert scheme == "dpkg" and families == {"Ubuntu"}
    scheme, families = detect_scheme(HostInfo(package_manager="rpm", os_name="Rocky Linux 9"))
    assert scheme == "rpm" and families == {"Rocky Linux"}


def test_range_matching_with_last_affected(tmp_path):
    record = {
        "id": "T-1", "summary": "s", "severity": [{"type": "CVSS_V3", "score": _CRIT}],
        "affected": [{"package": {"ecosystem": "Ubuntu", "name": "openssl"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [
                          {"introduced": "3.0.0"}, {"last_affected": "3.0.2"}]}]}]}
    (tmp_path / "a.json").write_text(json.dumps(record))
    db = AdvisoryDatabase.load(tmp_path, UBUNTU)
    assert db.match([("openssl", "3.0.1")]) and not db.match([("openssl", "3.0.3")])
    assert not db.match([("openssl", "2.9.0")])


def test_severity_from_cvss_vector():
    adv = _advisory("x", "Ubuntu", "0", "2.0")
    assert adv.severity == Severity.HIGH  # 7.8 base score
    adv_crit = _advisory("y", "Ubuntu", "0", "2.0", cvss=_CRIT)
    assert adv_crit.severity == Severity.CRITICAL


def test_malformed_advisory_file_is_skipped(tmp_path):
    (tmp_path / "broken.json").write_text("{ not json")
    (tmp_path / "empty.json").write_text("{}")
    db = AdvisoryDatabase.load(tmp_path, UBUNTU)
    assert db.count == 0
