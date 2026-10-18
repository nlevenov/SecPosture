import pytest

from secposture.advisories.cvss import base_score, score_to_severity
from secposture.advisories.version import deb_compare, rpm_compare


@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0", "1.0", 1),
    ("1.0-1", "1.0-2", -1), ("1:1.0", "2.0", 1), ("1.0~rc1", "1.0", -1),
    ("1.0~rc1", "1.0~rc2", -1), ("3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1),
    ("1.2.3", "1.2.3a", -1), ("1.0.0", "1.0", 1),
    ("2.38-3ubuntu1", "2.38-3ubuntu1.1", -1), ("1.8.31-1ubuntu1", "1.8.31-1ubuntu1.2", -1),
])
def test_deb_compare(a, b, expected):
    assert deb_compare(a, b) == expected
    assert deb_compare(b, a) == -expected


@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0), ("1.0", "1.1", -1), ("1.0-1", "1.0-2", -1),
    ("2.0.1", "2.0.1~rc1", 1), ("1.0", "1.0.1", -1), ("5.14.0-284", "5.14.0-70", 1),
])
def test_rpm_compare(a, b, expected):
    assert rpm_compare(a, b) == expected
    assert rpm_compare(b, a) == -expected


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
])
def test_cvss_base_score(vector, score):
    assert base_score(vector) == score


def test_cvss_severity_buckets():
    assert score_to_severity(9.8) == "critical" and score_to_severity(7.0) == "high"
    assert score_to_severity(4.0) == "medium" and score_to_severity(0.1) == "low"
    assert base_score("not a vector") is None
