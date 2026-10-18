import pytest

from secposture.baseline import diff
from secposture.config import ScoringSettings
from secposture.controls import evaluate
from secposture.models import AuditResult, Finding, HostInfo, Severity, Status
from secposture.results import load_result, save_result
from secposture.scoring import grade_for, pass_rate, score

from helpers import facts


def _result(findings, **host):
    r = AuditResult(host=HostInfo(**host), profile="server", findings=findings,
                    tool_version="test")
    return score(r)


def _finding(cid, status, sev=Severity.HIGH):
    return Finding(cid, cid, __import__("secposture.models", fromlist=["Category"]).Category.SSH,
                   sev, status)


def test_perfect_host_scores_100():
    r = _result([_finding("A", Status.PASS), _finding("B", Status.PASS)])
    assert r.score == 100 and r.grade == "A"


def test_critical_failure_dominates_score():
    good = [_finding(f"P{i}", Status.PASS, Severity.LOW) for i in range(10)]
    r = _result(good + [_finding("X", Status.FAIL, Severity.CRITICAL)])
    assert r.score < 50  # one critical outweighs ten low passes


def test_warn_earns_half_credit():
    all_warn = _result([_finding("A", Status.WARN), _finding("B", Status.WARN)])
    assert all_warn.score == 50


def test_not_applicable_excluded_from_score():
    r = _result([_finding("A", Status.PASS), _finding("B", Status.NOT_APPLICABLE)])
    assert r.score == 100 and pass_rate(r) == (1, 1)


def test_grade_cutoffs():
    s = ScoringSettings()
    assert grade_for(90, s) == "A" and grade_for(89, s) == "B" and grade_for(59, s) == "F"


def test_result_signing_and_tamper_detection(tmp_path):
    r = _result([_finding("A", Status.FAIL)], hostname="h1")
    path = save_result(r, tmp_path / "r.sp.json", "key1")
    assert load_result(path, "key1").score == r.score
    with pytest.raises(ValueError, match="signature"):
        load_result(path, "wrong-key")
    # flipping a byte in the payload is detected
    import json
    doc = json.loads(path.read_text())
    doc["result"]["score"] = 100
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        load_result(path, "key1")
    assert load_result(path, "key1", require_valid=False).score == 100


def test_unsigned_result_uses_checksum(tmp_path):
    r = _result([_finding("A", Status.PASS)])
    path = save_result(r, tmp_path / "r.sp.json")  # no key
    assert load_result(path).score == 100  # sha256 checksum verifies


def test_baseline_diff(ctx):
    before = _result(evaluate(facts(sshd_config={"permitrootlogin": "yes"}), ctx))
    after = _result(evaluate(facts(), ctx))  # fixed
    d = diff(before, after)
    assert any(f.control_id == "SSH-01" for f in d.resolved)
    assert d.score_after >= d.score_before and not d.regressed

    regressed = diff(after, before)
    assert any(f.control_id == "SSH-01" for f in regressed.new_failures)
    assert regressed.regressed
