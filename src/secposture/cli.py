"""Command line interface: ``secposture <command>``."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import subprocess  # nosec B404 - launches streamlit with a fixed argv, no shell
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import PROFILES, Settings, load_settings
from .sanitize import parse_target

log = logging.getLogger("secposture")
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _collector(args: argparse.Namespace, settings: Settings):
    from .collectors import LocalCollector, SSHCollector

    if args.ssh:
        password = getpass.getpass(f"SSH password for {args.ssh}: ") if args.ask_pass else None
        return SSHCollector(
            args.ssh, port=args.port or settings.ssh.port,
            key_file=args.key or settings.ssh.key_file, password=password,
            known_hosts=args.known_hosts or settings.ssh.known_hosts,
            allow_agent=settings.ssh.allow_agent,
            connect_timeout=settings.ssh.connect_timeout,
            command_timeout=settings.ssh.command_timeout)
    return LocalCollector()


def cmd_audit(args: argparse.Namespace, settings: Settings) -> int:
    from .audit import run_audit
    from .report import render_terminal, write_html, write_remediation
    from .results import save_result

    if args.profile:
        settings.profile = args.profile
    try:
        collector = _collector(args, settings)
    except (ValueError, OSError) as exc:
        print(f"error: could not connect: {exc}")
        return 1
    except Exception as exc:  # paramiko raises several auth/host-key types
        print(f"error: SSH connection failed: {type(exc).__name__}: {exc}")
        return 1

    with collector:
        result = run_audit(collector, settings)

    print(render_terminal(result, show="all" if args.all else "open"))
    if args.verbose:
        for note in result.collection_errors:
            print(f"  note: {note}")

    stem = _safe_stem(result.host.hostname or args.ssh or "localhost")
    if args.save is not None:
        path = args.save or f"results/{stem}-{_stamp()}.sp.json"
        save_result(result, path, settings.signing_key)
        print(f"\nsaved result -> {path}")
    if args.html is not None:
        path = args.html or f"reports/{stem}-{_stamp()}.report.html"
        write_html(result, path)
        print(f"wrote HTML report -> {path}")
    if args.remediation is not None:
        path = args.remediation or f"reports/{stem}-{_stamp()}.harden.sh"
        write_remediation(result, path)
        print(f"wrote remediation script (review before running) -> {path}")

    if args.fail_under is not None and result.score < args.fail_under:
        print(f"\nposture score {result.score} is below the required {args.fail_under}")
        return 3
    return 0


def cmd_report(args: argparse.Namespace, settings: Settings) -> int:
    from .report import write_html
    from .results import load_result

    try:
        result = load_result(args.result, settings.signing_key,
                             require_valid=not args.no_verify)
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}")
        return 1
    out = args.out or Path(args.result).with_suffix(".report.html")
    write_html(result, out)
    print(f"wrote HTML report -> {out}")
    return 0


def cmd_controls(args: argparse.Namespace, settings: Settings) -> int:
    from .controls import all_controls, load_catalog

    load_catalog()
    controls = sorted(all_controls(), key=lambda c: c.id)
    if args.json:
        import json

        print(json.dumps([{"id": c.id, "title": c.title, "category": c.category.value,
                           "severity": c.severity.value, "profiles": list(c.profiles),
                           "rationale": c.rationale} for c in controls], indent=2))
        return 0
    print(f"{'ID':<8} {'Severity':<9} {'Category':<11} Title")
    for c in controls:
        marker = "" if args.profile in c.profiles else " (n/a for profile)"
        print(f"{c.id:<8} {c.severity.value:<9} {c.category.value:<11} {c.title}{marker}")
    print(f"\n{len(controls)} controls")
    return 0


def cmd_baseline(args: argparse.Namespace, settings: Settings) -> int:
    from .audit import run_audit
    from .baseline import diff
    from .results import load_result, save_result

    if args.action == "save":
        with _collector(args, settings) as collector:
            result = run_audit(collector, settings)
        path = args.file or f"baselines/{_safe_stem(result.host.hostname)}.baseline.json"
        save_result(result, path, settings.signing_key)
        print(f"saved baseline (score {result.score}, grade {result.grade}) -> {path}")
        return 0

    # diff
    try:
        baseline = load_result(args.file, settings.signing_key,
                               require_valid=not args.no_verify)
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}")
        return 1
    with _collector(args, settings) as collector:
        current = run_audit(collector, settings)
    result = diff(baseline, current)
    s = result.summary()
    arrow = "+" if s["score_delta"] >= 0 else ""
    print(f"score {s['score_before']} -> {s['score_after']} ({arrow}{s['score_delta']})")
    print(f"new failures: {s['new_failures']}   resolved: {s['resolved']}   "
          f"still open: {s['still_open']}")
    for f in result.new_failures:
        print(f"  REGRESSION [{f.severity.value}] {f.control_id} {f.title}")
    for f in result.resolved:
        print(f"  resolved   [{f.severity.value}] {f.control_id} {f.title}")
    return 3 if result.regressed else 0


def cmd_hash_password(args: argparse.Namespace, settings: Settings) -> int:
    from .passwords import MIN_LENGTH, hash_password

    password = getpass.getpass("Dashboard password: ")
    if password != getpass.getpass("Repeat: "):
        print("error: passwords do not match")
        return 2
    try:
        encoded = hash_password(password)
    except ValueError as exc:
        print(f"error: {exc} (minimum {MIN_LENGTH})")
        return 2
    print("\nAdd this to your environment (.env):\n")
    print(f"SECPOSTURE_DASHBOARD_PASSWORD_HASH='{encoded}'")
    return 0


def cmd_dashboard(args: argparse.Namespace, settings: Settings) -> int:
    from .passwords import is_valid_hash

    password_hash = (os.environ.get("SECPOSTURE_DASHBOARD_PASSWORD_HASH")
                     or settings.dashboard.password_hash)
    if not is_valid_hash(password_hash):
        print("error: no dashboard password configured. Create one with "
              "`secposture hash-password` and set SECPOSTURE_DASHBOARD_PASSWORD_HASH.")
        return 2
    try:
        import streamlit  # noqa: F401
    except ImportError:
        print("error: the dashboard needs the extra dependencies. "
              "Install with: pip install 'secposture[dashboard]'")
        return 2
    if args.host not in LOOPBACK and not settings.dashboard.allowed_hosts_ok(args.host):
        print(f"warning: serving on {args.host}; put a TLS reverse proxy in front.")
    app = Path(__file__).parent / "dashboard" / "app.py"
    command = [sys.executable, "-m", "streamlit", "run", str(app),
               "--server.address", args.host, "--server.port", str(args.port),
               "--server.headless", "true", "--server.enableXsrfProtection", "true",
               "--server.enableCORS", "true", "--server.fileWatcherType", "none",
               "--server.enableStaticServing", "false", "--server.xsrfCookieSameSite", "strict",
               "--browser.gatherUsageStats", "false", "--client.showErrorDetails", "none",
               "--client.toolbarMode", "minimal", "--global.developmentMode", "false",
               "--server.allowedHosts", "localhost", "--server.allowedHosts", "127.0.0.1"]
    env = {**os.environ, "SECPOSTURE_DASHBOARD_PASSWORD_HASH": password_hash,
           "SECPOSTURE_RESULTS_DIR": args.results or settings.dashboard.results_dir,
           "SECPOSTURE_SIGNING_KEY": settings.signing_key}
    print(f"fleet dashboard on http://{args.host}:{args.port}")
    try:
        return subprocess.call(command, env=env)  # noqa: S603  # nosec B603 - fixed argv
    except KeyboardInterrupt:
        return 0


def _safe_stem(name: str) -> str:
    import re

    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:60] or "host"


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secposture",
                                     description="Host and service security posture auditor")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-c", "--config", dest="config_path", help="settings YAML file")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_target(p: argparse.ArgumentParser) -> None:
        p.add_argument("--ssh", metavar="USER@HOST", help="audit a remote host over SSH")
        p.add_argument("--port", type=int, help="SSH port")
        p.add_argument("--key", help="SSH private key file")
        p.add_argument("--known-hosts", help="SSH known_hosts file")
        p.add_argument("--ask-pass", action="store_true", help="prompt for an SSH password")

    p = sub.add_parser("audit", help="run an audit (local, or --ssh user@host)")
    add_target(p)
    p.add_argument("--profile", choices=PROFILES, help="benchmark profile")
    p.add_argument("--all", action="store_true", help="show passing controls too")
    p.add_argument("--save", nargs="?", const="", metavar="FILE", help="save signed JSON result")
    p.add_argument("--html", nargs="?", const="", metavar="FILE", help="write an HTML report")
    p.add_argument("--remediation", nargs="?", const="", metavar="FILE",
                   help="write a review-only hardening script")
    p.add_argument("--fail-under", type=int, metavar="SCORE",
                   help="exit non-zero if the posture score is below SCORE (for CI gates)")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("report", help="render an HTML report from a saved result")
    p.add_argument("result", help="saved .sp.json result")
    p.add_argument("-o", "--out", help="output HTML path")
    p.add_argument("--no-verify", action="store_true", help="load even if the signature fails")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("controls", help="list the control catalog")
    p.add_argument("--profile", choices=PROFILES, default="server")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_controls)

    p = sub.add_parser("baseline", help="save a baseline or diff the host against one")
    p.add_argument("action", choices=["save", "diff"])
    p.add_argument("file", nargs="?", help="baseline file (save target / diff source)")
    add_target(p)
    p.add_argument("--profile", choices=PROFILES)
    p.add_argument("--no-verify", action="store_true")
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("dashboard", help="start the fleet dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8501)
    p.add_argument("--results", help="directory of saved results")
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser("hash-password", help="create a dashboard password hash")
    p.set_defaults(func=cmd_hash_password)
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        settings = load_settings(args.config_path)
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: invalid configuration: {exc}")
        return 2
    if getattr(args, "ssh", None):
        try:
            parse_target(args.ssh)
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
    return args.func(args, settings)


if __name__ == "__main__":
    sys.exit(main())
