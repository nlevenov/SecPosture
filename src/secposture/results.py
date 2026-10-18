"""Signed, integrity-checked serialization of audit results.

Results and baselines carry a detached signature. With a configured HMAC key
the signature authenticates the file (so a tampered result is rejected);
without one it is a SHA-256 checksum that still catches corruption and
accidental edits.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from typing import Any

from .models import AuditResult

log = logging.getLogger(__name__)


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(data: bytes, key: str) -> tuple[str, str]:
    if key:
        return "hmac-sha256", hmac.new(key.encode(), data, hashlib.sha256).hexdigest()
    return "sha256", hashlib.sha256(data).hexdigest()


def save_result(result: AuditResult, path: str | Path, signing_key: str = "") -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = result.to_dict()
    algorithm, digest = _digest(_canonical(payload), signing_key)
    document = {"schema": "secposture/result/1", "result": payload,
                "signature": {"algorithm": algorithm, "digest": digest}}
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(document, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


def load_result(path: str | Path, signing_key: str = "", *,
                require_valid: bool = True) -> AuditResult:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    payload = document["result"]
    signature = document.get("signature", {})
    algorithm, expected = _digest(_canonical(payload), signing_key)
    valid = (signature.get("algorithm") == algorithm
             and hmac.compare_digest(str(signature.get("digest", "")), expected))
    if not valid:
        message = f"signature check failed for {path}"
        if require_valid:
            raise ValueError(message)
        log.warning("%s - loading anyway", message)
    return AuditResult.from_dict(payload)
