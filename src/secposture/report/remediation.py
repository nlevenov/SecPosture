"""Generate a review-only hardening script from an audit's fix commands.

The script is written to disk, never executed. It opens with 'set -e' and a
loud banner telling the operator to read it, understand each change and run it
only on a host they intend to harden. Commands come verbatim from each
control's remediation and were sanitized when the finding was built.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..models import AuditResult

_HEADER = """#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# SecPosture remediation script  (REVIEW BEFORE RUNNING)
# Host:      {host}
# Generated: {when}
# Profile:   {profile}
#
# This script was generated from audit findings. It changes system
# configuration. Read every command, confirm it suits this host, and run it
# only on a system you administer. Take a backup / snapshot first.
# ---------------------------------------------------------------------------
set -euo pipefail

if [[ "${{1:-}}" != "--i-have-reviewed-this" ]]; then
  echo "Refusing to run until reviewed. Re-run with --i-have-reviewed-this once you have"
  echo "read the commands below and confirmed they are appropriate for this host."
  exit 2
fi
"""


def render_remediation(result: AuditResult) -> str:
    lines = [_HEADER.format(host=result.host.hostname or result.host.target or "localhost",
                            when=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                            profile=result.profile)]
    for finding in result.open_findings:
        if not finding.fix_commands:
            continue
        lines.append(f"\n# [{finding.severity.value.upper()}] {finding.control_id} "
                     f"- {finding.title}")
        lines.append(f"# {finding.detail}")
        lines.extend(finding.fix_commands)
    lines.append('\necho "SecPosture remediation complete. Re-run the audit to confirm."')
    return "\n".join(lines) + "\n"


def write_remediation(result: AuditResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_remediation(result), encoding="utf-8")
    path.chmod(0o750)
    return path
