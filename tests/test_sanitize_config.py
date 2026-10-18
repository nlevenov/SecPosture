import pytest

from secposture.config import load_settings
from secposture.sanitize import (
    clean,
    clean_block,
    parse_target,
    valid_hostname,
    valid_username,
)


def test_clean_strips_control_chars_keeps_markup_text():
    # ANSI escape (ESC) removed so terminal output cannot be hijacked; < > kept
    # as literal text for the autoescaping HTML layer to encode.
    assert clean("ok \x1b[31mred\x1b[0m <b>x</b>\x00") == "ok [31mred[0m <b>x</b>"
    assert clean("a\r\nb\tc   d") == "a b c d"
    assert clean("x" * 999, 10) == "x" * 10
    assert clean(None) == "" and clean(b"by\xfftes") == "by�tes"


def test_clean_block_keeps_newlines():
    assert clean_block("line1\nline2\x00\nline3").splitlines() == ["line1", "line2", "line3"]


@pytest.mark.parametrize("target,user,host", [
    ("root@127.0.0.1", "root", "127.0.0.1"),
    ("ubuntu@host.example.com", "ubuntu", "host.example.com"),
    ("svc_backup@10.0.0.5", "svc_backup", "10.0.0.5"),
])
def test_parse_target_accepts_valid(target, user, host):
    assert parse_target(target) == (user, host)


@pytest.mark.parametrize("target", [
    "root@h; rm -rf /", "a b@host", "user@-oProxyCommand=x", "noat", "user@host$(id)",
    "root@h`whoami`", "@host", "user@", "-u@host",
])
def test_parse_target_rejects_injection(target):
    with pytest.raises(ValueError):
        parse_target(target)


def test_hostname_and_username_validation():
    assert valid_hostname("localhost") and valid_hostname("2001:db8::1")
    assert not valid_hostname("-startdash") and not valid_hostname("a host")
    assert valid_username("root") and not valid_username("Root") and not valid_username("a;b")


def test_defaults_and_shipped_config_valid(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SECPOSTURE_CONFIG", raising=False)
    assert load_settings().profile == "server"


@pytest.mark.parametrize("content,message", [
    ("profile: router\n", "profile must be"),
    ("scoring:\n  grade_a: 50\n  grade_b: 60\n", "decreasing"),
    ("ssh:\n  prt: 22\n", "ssh.prt"),
    ("nonsense: 1\n", "unknown setting 'nonsense'"),
])
def test_invalid_config_rejected(tmp_path, content, message):
    path = tmp_path / "bad.yaml"
    path.write_text(content)
    with pytest.raises((ValueError, FileNotFoundError), match=message):
        load_settings(path)


def test_env_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("KEY", "s3cret")
    path = tmp_path / "c.yaml"
    path.write_text("signing_key: ${KEY}\nadvisories:\n  use_osv_api: ${API:-false}\n")
    settings = load_settings(path)
    assert settings.signing_key == "s3cret" and settings.advisories.use_osv_api is False
