"""SecPosture fleet dashboard.

Loads signed audit results from a directory and shows fleet-wide posture,
per-host trend and findings. Started through ``secposture dashboard``, which
applies the hardened Streamlit server options. All displayed values were
sanitized when the audit was produced; nothing is rendered as raw HTML.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import streamlit as st

from secposture.dashboard.auth import logout, require_login
from secposture.dashboard.loader import latest_per_host, load_results
from secposture.scoring import pass_rate

st.set_page_config(page_title="SecPosture", page_icon=":material/security:", layout="wide",
                   menu_items={})

SEV_COLORS = {"critical": "#d11149", "high": "#e8702a", "medium": "#e8c21d",
              "low": "#3aa0d1", "info": "#9aa4b2"}
GRADE_COLORS = {"A": "#2f9e44", "B": "#5aa02f", "C": "#e8a81d", "D": "#e8702a", "F": "#d11149"}


@st.cache_data(ttl=20)
def _load(directory: str, signing_key: str, _token: float):
    loaded, skipped = load_results(directory, signing_key)
    return loaded, skipped


require_login()
results_dir = os.environ.get("SECPOSTURE_RESULTS_DIR", "results")
signing_key = os.environ.get("SECPOSTURE_SIGNING_KEY", "")
loaded, skipped = _load(results_dir, signing_key, st.session_state.get("reload", 0.0))

with st.sidebar:
    st.title("SecPosture")
    st.caption(f"results: {results_dir}")
    if st.button("Refresh", use_container_width=True):
        st.session_state["reload"] = datetime.now().timestamp()
        st.cache_data.clear()
        st.rerun()
    if st.button("Sign out", use_container_width=True):
        logout()

if not loaded:
    st.info(f"No audit results found in '{results_dir}'. Produce one with "
            "`secposture audit --save`.")
    for note in skipped:
        st.warning(note)
    st.stop()

latest = latest_per_host(loaded)
rows = []
for host, item in sorted(latest.items()):
    r = item.result
    passed, applicable = pass_rate(r)
    sev = r.severity_counts()
    rows.append({
        "Host": host, "OS": f"{r.host.os_name} {r.host.os_version}".strip(),
        "Score": r.score, "Grade": r.grade, "Passed": f"{passed}/{applicable}",
        "Critical": sev["critical"], "High": sev["high"], "Medium": sev["medium"],
        "Open": len(r.open_findings),
        "Audited": datetime.fromtimestamp(r.host.collected_at, tz=timezone.utc)
        if r.host.collected_at else None,
        "Trusted": "yes" if item.trusted else "UNSIGNED",
    })
fleet = pd.DataFrame(rows)

st.header("Fleet posture")
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Hosts", len(fleet), border=True)
k2.metric("Mean score", round(fleet["Score"].mean()), border=True)
k3.metric("Grade A", int((fleet["Grade"] == "A").sum()), border=True)
k4.metric("Critical findings", int(fleet["Critical"].sum()), border=True)
k5.metric("Hosts below C", int((fleet["Score"] < 70).sum()), border=True)

left, right = st.columns([3, 2])
with left, st.container(border=True):
    st.subheader("Hosts")
    st.dataframe(
        fleet.style.map(lambda g: f"color:{GRADE_COLORS.get(g, '')};font-weight:700",
                        subset=["Grade"]),
        hide_index=True, use_container_width=True,
        column_config={"Audited": st.column_config.DatetimeColumn("Audited (UTC)",
                                                                  format="YYYY-MM-DD HH:mm"),
                       "Score": st.column_config.ProgressColumn("Score", min_value=0,
                                                                max_value=100, format="%d")})
with right, st.container(border=True):
    st.subheader("Open findings by severity")
    totals = {s: int(fleet[s.capitalize()].sum()) for s in ("critical", "high", "medium")}
    totals["low"] = sum(latest[h].result.severity_counts()["low"] for h in latest)
    totals["info"] = sum(latest[h].result.severity_counts()["info"] for h in latest)
    data = pd.DataFrame({"severity": list(totals), "count": list(totals.values())})
    fig = px.bar(data[data["count"] > 0], x="count", y="severity", orientation="h",
                 color="severity", color_discrete_map=SEV_COLORS)
    fig.update_layout(height=300, showlegend=False, margin={"l": 10, "r": 10, "t": 10, "b": 10})
    st.plotly_chart(fig, use_container_width=True)

if any(not item.trusted for item in latest.values()):
    st.warning("One or more results failed signature verification and are marked UNSIGNED. "
               "Confirm the signing key and the integrity of those files.")

st.divider()
st.subheader("Host detail")
host = st.selectbox("Host", sorted(latest))
item = latest[host]
result = item.result
history = sorted((i for i in loaded
                  if (i.result.host.hostname or i.result.host.target) == host),
                 key=lambda i: i.result.host.collected_at)
if len(history) > 1:
    trend = pd.DataFrame([{
        "when": datetime.fromtimestamp(i.result.host.collected_at, tz=timezone.utc),
        "score": i.result.score} for i in history])
    fig = px.line(trend, x="when", y="score", markers=True, range_y=[0, 100])
    fig.update_layout(height=220, margin={"l": 10, "r": 10, "t": 10, "b": 10})
    st.plotly_chart(fig, use_container_width=True)

open_rows = [{"Severity": f.severity.value, "Status": f.status.value, "Control": f.control_id,
              "Finding": f.title, "Detail": f.detail, "Remediation": f.remediation}
             for f in result.open_findings]
if open_rows:
    st.dataframe(pd.DataFrame(open_rows).style.map(
        lambda s: f"color:{SEV_COLORS.get(s, '')};font-weight:700", subset=["Severity"]),
        hide_index=True, use_container_width=True)
else:
    st.success("No open findings on this host.")

with st.expander("Passed & informational controls"):
    other = [{"Status": f.status.value, "Control": f.control_id, "Result": f.detail}
             for f in result.findings if not f.is_open]
    st.dataframe(pd.DataFrame(other), hide_index=True, use_container_width=True)
