"""Collector for the host the tool runs on."""

from __future__ import annotations

import grp
import os
import pwd
import subprocess  # nosec B404 - runs only the fixed read-only command allowlist

from .base import Collector, CommandResult, FileStat


class LocalCollector(Collector):
    transport = "local"

    def __init__(self, default_timeout: float = 30.0, slow_timeout: float = 120.0) -> None:
        self.default_timeout = default_timeout
        self.slow_timeout = slow_timeout

    def read_file(self, path: str, max_bytes: int = 1_048_576) -> str | None:
        try:
            with open(path, "rb") as fh:  # noqa: PTH123 - explicit binary read
                return fh.read(max_bytes).decode("utf-8", "replace")
        except (OSError, ValueError):
            return None

    def stat_file(self, path: str) -> FileStat:
        try:
            info = os.lstat(path)
        except OSError:
            return FileStat(path=path, exists=False)
        is_link = os.path.islink(path)
        target = os.stat(path) if is_link and os.path.exists(path) else info
        return FileStat(
            path=path, exists=True, mode=target.st_mode & 0o7777,
            uid=target.st_uid, gid=target.st_gid,
            owner=_name(pwd.getpwuid, target.st_uid),
            group=_name(grp.getgrgid, target.st_gid),
            size=target.st_size, is_symlink=is_link,
        )

    def list_dir(self, path: str) -> list[str]:
        try:
            return sorted(os.listdir(path))
        except OSError:
            return []

    def run(self, key: str, timeout: float | None = None) -> CommandResult:
        argv = self._check_key(key)
        from .base import SLOW_COMMANDS

        limit = timeout or (self.slow_timeout if key in SLOW_COMMANDS else self.default_timeout)
        try:
            proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed allowlist argv, no shell
                argv, capture_output=True, text=True, timeout=limit,
                encoding="utf-8", errors="replace", check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
            )
        except subprocess.TimeoutExpired:
            return CommandResult(rc=124, stdout="", stderr="timed out", timed_out=True)
        except FileNotFoundError:
            return CommandResult(rc=127, stdout="", stderr="command not found")
        except OSError as exc:
            return CommandResult(rc=1, stdout="", stderr=str(exc))
        return CommandResult(rc=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def _name(lookup, value: int) -> str:
    try:
        entry = lookup(value)
    except (KeyError, OSError):
        return ""
    return entry.pw_name if hasattr(entry, "pw_name") else entry.gr_name
