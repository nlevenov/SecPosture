"""Each control is driven to pass and to fail with fixture data."""

import pytest

from secposture.collectors.base import FileStat
from secposture.controls import REGISTRY, evaluate
from secposture.models import Category, Status

from helpers import facts


def _run(control_id, f, ctx):
    fn = next(fn for ctrl, fn in REGISTRY if ctrl.id == control_id)
    return fn(f, ctx)


def test_baseline_fixture_is_mostly_clean(ctx):
    findings = evaluate(facts(), ctx)
    failed = [f.control_id for f in findings if f.status == Status.FAIL]
    assert not failed, f"baseline fixture should pass all controls, failed: {failed}"


@pytest.mark.parametrize("control_id,override", [
    ("SSH-01", {"sshd_config": {"permitrootlogin": "yes"}}),
    ("SSH-02", {"sshd_config": {"passwordauthentication": "yes"}}),
    ("SSH-03", {"sshd_config": {"permitemptypasswords": "yes"}}),
    ("SSH-04", {"sshd_config": {"maxauthtries": "10"}}),
    ("SSH-08", {"sshd_config": {"ciphers": "aes128-cbc,3des-cbc"}}),
    ("ACC-01", {"passwd": [{"name": "backdoor", "uid": 0, "gid": 0, "home": "/",
                            "shell": "/bin/bash", "password": "x"}]}),
    ("ACC-02", {"shadow": {"ghost": ["", "0"]}, "shadow_readable": True}),
    ("ACC-03", {"login_defs": {"ENCRYPT_METHOD": "MD5"}}),
    ("ACC-08", {"passwd": [{"name": "bad", "uid": 1000, "gid": 1000, "home": "/h",
                            "shell": "/bin/sh", "password": "$6$leaked$hash"}]}),
    ("FS-02", {"file_stats": {"/etc/shadow": FileStat("/etc/shadow", True, 0o644, 0, 0,
                                                      "root", "root")}}),
    ("FS-06", {"world_writable_files": ["/etc/cron.d/evil"]}),
    ("KRN-01", {"sysctl": {"kernel.randomize_va_space": "0"}}),
    ("NET-01", {"firewall": {"backend": "none", "active": False}}),
    ("NET-02", {"listening": [{"proto": "tcp", "address": "0.0.0.0", "port": 23,
                               "process": "telnetd"}]}),
    ("SVC-01", {"packages": [("telnetd", "0.17")]}),
])
def test_control_fails_on_bad_input(control_id, override, ctx):
    outcome = _run(control_id, facts(**override), ctx)
    assert outcome.status in (Status.FAIL, Status.WARN), \
        f"{control_id} should flag, got {outcome.status}"


def test_ssh_controls_not_applicable_without_sshd(ctx):
    f = facts(sshd_config={}, sshd_source="none")
    ssh_findings = [x for x in evaluate(f, ctx) if x.category == Category.SSH]
    assert all(x.status == Status.NOT_APPLICABLE for x in ssh_findings)


def test_empty_password_check_errors_without_shadow(ctx):
    assert _run("ACC-02", facts(shadow={}, shadow_readable=False), ctx).status == Status.ERROR


def test_permit_root_prohibit_password_is_warn_not_fail(ctx):
    assert _run("SSH-01", facts(sshd_config={"permitrootlogin": "prohibit-password"}),
                ctx).status == Status.WARN


def test_suid_allowlist_suppresses_known_binaries(ctx):
    f = facts(suid_sgid=[{"mode": "4755", "owner": "root", "group": "root",
                          "path": "/opt/custom/tool"}])
    assert _run("FS-09", f, ctx).status == Status.WARN
    ctx.allowed_suid = frozenset({"/opt/custom/tool"})
    assert _run("FS-09", f, ctx).status == Status.PASS


def test_exposed_ports_respects_allowlist(ctx):
    f = facts(listening=[{"proto": "tcp", "address": "0.0.0.0", "port": 8080,
                          "process": "nginx"}])
    assert _run("NET-03", f, ctx).status == Status.WARN
    ctx.allowed_listen_ports = frozenset({8080})
    assert _run("NET-03", f, ctx).status == Status.PASS


def test_disabled_controls_are_skipped(ctx):
    ids = {f.control_id for f in evaluate(facts(), ctx, disabled={"SSH-01", "kernel"})}
    assert "SSH-01" not in ids and not any(i.startswith("KRN") for i in ids)


def test_broken_check_does_not_crash_the_audit(ctx, monkeypatch):
    # a control raising an exception becomes an ERROR finding, never propagates
    f = facts()
    f.sysctl = None  # type: ignore - will make a kernel check raise
    findings = evaluate(f, ctx)
    assert any(x.status == Status.ERROR for x in findings)
    assert len(findings) > 40  # all other controls still evaluated
