import json

import pytest

from secposture import cli
from secposture.audit import run_audit
from secposture.collectors import LocalCollector
from secposture.config import Settings
from secposture.controls import evaluate
from secposture.models import AuditResult, HostInfo
from secposture.report import render_html, render_remediation, render_terminal
from secposture.scoring import score

from conftest import SAMPLE_ADVISORIES
from helpers import facts


@pytest.fixture
def result(ctx):
    r = AuditResult(host=HostInfo(hostname="h1", os_name="Ubuntu", privileged=True),
                    profile="server", findings=evaluate(facts(sshd_config={
                        "permitrootlogin": "yes"}, world_writable_files=["/x"]), ctx),
                    tool_version="test")
    return score(r)


def test_html_report_escapes_hostile_evidence(ctx):
    f = facts(world_writable_files=["/srv/<script>alert(1)</script>"])
    r = score(AuditResult(host=HostInfo(hostname="h"), profile="server",
                          findings=evaluate(f, ctx), tool_version="t"))
    html = render_html(r)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html  # the payload is HTML-escaped, shown as text


def test_terminal_and_remediation_render(result):
    text = render_terminal(result)
    assert "Posture score" in text and "SSH-01" in text
    script = render_remediation(result)
    assert script.startswith("#!/usr/bin/env bash") and "--i-have-reviewed-this" in script
    assert "set -euo pipefail" in script


def test_cli_audit_saves_signed_result_and_report(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"signing_key: k\nadvisories:\n  local_dir: {SAMPLE_ADVISORIES}\n")
    rc = cli.main(["-c", str(cfg), "audit", "--save", "--html", "--remediation"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Posture score" in out and "saved result" in out
    saved = next((tmp_path / "results").glob("*.sp.json"))
    doc = json.loads(saved.read_text())
    assert doc["signature"]["algorithm"] == "hmac-sha256"
    assert list((tmp_path / "reports").glob("*.report.html"))
    assert list((tmp_path / "reports").glob("*.harden.sh"))


def test_cli_fail_under_gate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["audit", "--fail-under", "100"]) == 3   # real host won't score 100
    assert cli.main(["audit", "--fail-under", "0"]) == 0


def test_cli_controls_listing(capsys):
    assert cli.main(["controls"]) == 0
    assert "controls" in capsys.readouterr().out
    assert cli.main(["controls", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)


def test_cli_rejects_bad_ssh_target(capsys):
    assert cli.main(["audit", "--ssh", "root@host; rm -rf /"]) == 2
    assert "invalid" in capsys.readouterr().out.lower()


def test_cli_invalid_config(tmp_path, capsys):
    bad = tmp_path / "b.yaml"
    bad.write_text("profile: router\n")
    assert cli.main(["-c", str(bad), "controls"]) == 2


def test_report_roundtrip_from_saved(tmp_path):
    s = Settings()
    s.advisories.local_dir = SAMPLE_ADVISORIES
    r = run_audit(LocalCollector(), s)
    from secposture.results import save_result
    saved = save_result(r, tmp_path / "x.sp.json")
    assert cli.main(["report", str(saved), "-o", str(tmp_path / "o.html")]) == 0
    assert (tmp_path / "o.html").read_text().startswith("<!doctype html>")


def test_remediation_script_neutralizes_hostile_filenames(ctx):
    # a world-writable file with a shell-injection name must be quoted, not executed
    f = facts(world_writable_files=["/tmp/x; rm -rf / $(reboot)"], unowned=[])
    r = score(AuditResult(host=HostInfo(hostname="h"), profile="server",
                          findings=evaluate(f, ctx), tool_version="t"))
    line = next(line_ for line_ in render_remediation(r).splitlines() if "chmod o-w" in line_)
    assert line.strip() == "sudo chmod o-w '/tmp/x; rm -rf / $(reboot)'"


def test_host_fields_are_sanitized_for_the_terminal():
    from secposture.collectors import LocalCollector
    from secposture.collectors.gather import host_info

    info = host_info(LocalCollector())
    assert "\x1b" not in info.os_name and "\x1b" not in info.kernel
    assert info.hostname
