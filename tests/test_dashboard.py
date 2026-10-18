import time
from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from secposture.audit import run_audit
from secposture.collectors import LocalCollector
from secposture.config import Settings
from secposture.dashboard import auth
from secposture.passwords import hash_password
from secposture.results import save_result

from conftest import ROOT, SAMPLE_ADVISORIES

APP = str(ROOT / "src" / "secposture" / "dashboard" / "app.py")
PASSWORD = "fleet-dashboard-pass"


@pytest.fixture
def app(tmp_path, monkeypatch):
    results = tmp_path / "results"
    s = Settings()
    s.advisories.local_dir = SAMPLE_ADVISORIES
    s.signing_key = "k"
    r = run_audit(LocalCollector(), s)
    r.host.hostname = "host-a"
    save_result(r, results / "host-a.sp.json", "k")
    monkeypatch.setenv("SECPOSTURE_RESULTS_DIR", str(results))
    monkeypatch.setenv("SECPOSTURE_SIGNING_KEY", "k")
    monkeypatch.setenv("SECPOSTURE_DASHBOARD_PASSWORD_HASH", hash_password(PASSWORD))
    monkeypatch.setattr(auth, "FAILURE_DELAY", 0)
    st.cache_resource.clear()
    st.cache_data.clear()
    yield AppTest.from_file(APP, default_timeout=30)
    st.cache_resource.clear()
    st.cache_data.clear()


def _login(at, password=PASSWORD):
    at.run()
    at.text_input[0].input(password)
    at.button[0].click().run()
    return at


def test_locked_without_password(app, monkeypatch):
    monkeypatch.setenv("SECPOSTURE_DASHBOARD_PASSWORD_HASH", "")
    app.run()
    assert any("locked" in e.value for e in app.error)
    assert not app.metric


def test_wrong_password_rejected(app):
    _login(app, "nope-nope-nope")
    assert any(e.value == "Invalid password." for e in app.error)
    assert not app.metric


def test_fleet_overview_after_login(app):
    _login(app)
    labels = {m.label for m in app.metric}
    assert {"Hosts", "Mean score", "Critical findings"} <= labels


def test_brute_force_lockout(app):
    app.run()
    for _ in range(auth.SESSION_MAX_FAILURES):
        app.text_input[0].input("guessing-it")
        app.button[0].click().run()
    app.run()
    assert any("Too many failed" in e.value for e in app.error)


def test_session_expiry(app):
    _login(app)
    app.session_state["auth_until"] = time.time() - 1
    app.run()
    assert not app.metric and app.text_input[0].label == "Password"


def test_unsigned_result_flagged(app, tmp_path, monkeypatch):
    # write a result signed with a different key -> should load but be UNSIGNED
    results = Path(tmp_path) / "results"
    s = Settings()
    s.advisories.local_dir = SAMPLE_ADVISORIES
    r = run_audit(LocalCollector(), s)
    r.host.hostname = "rogue"
    save_result(r, results / "rogue.sp.json", "a-different-key")
    _login(app)
    assert any("UNSIGNED" in w.value or "signature" in w.value for w in app.warning)
