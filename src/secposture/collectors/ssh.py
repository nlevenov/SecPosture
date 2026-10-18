"""Collector for a remote host you administer, over SSH.

Host keys are verified against a known_hosts file by default; an unknown or
changed key aborts the audit rather than trusting it blindly. File reads go
over SFTP (no remote shell), and commands are the fixed allowlist executed
without a login shell interpreting any caller input.
"""

from __future__ import annotations

import contextlib
import shlex
import stat as stat_mod

import paramiko

from ..sanitize import parse_target
from .base import SLOW_COMMANDS, Collector, CommandResult, FileStat


class SSHCollector(Collector):
    transport = "ssh"

    def __init__(self, target: str, *, port: int = 22, key_file: str = "",
                 password: str | None = None, known_hosts: str = "", allow_agent: bool = True,
                 connect_timeout: float = 15.0, command_timeout: float = 30.0,
                 slow_timeout: float = 180.0) -> None:
        self.user, self.host = parse_target(target)
        self.target_label = f"{self.user}@{self.host}"
        self.port = port
        self.command_timeout = command_timeout
        self.slow_timeout = slow_timeout
        self._client = paramiko.SSHClient()
        if known_hosts:
            self._client.load_host_keys(known_hosts)
        else:
            self._client.load_system_host_keys()
        # Refuse to connect to a host whose key we have not already recorded.
        self._client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self._client.connect(
            self.host, port=port, username=self.user, password=password,
            key_filename=key_file or None, allow_agent=allow_agent,
            look_for_keys=allow_agent, timeout=connect_timeout, auth_timeout=connect_timeout,
            banner_timeout=connect_timeout,
        )
        self._sftp = self._client.open_sftp()
        self._sftp.get_channel().settimeout(command_timeout)

    def read_file(self, path: str, max_bytes: int = 1_048_576) -> str | None:
        try:
            with self._sftp.open(path, "r") as fh:
                fh.prefetch()
                return fh.read(max_bytes).decode("utf-8", "replace")
        except (OSError, paramiko.SSHException):
            return None

    def stat_file(self, path: str) -> FileStat:
        try:
            info = self._sftp.lstat(path)
        except (OSError, paramiko.SSHException):
            return FileStat(path=path, exists=False)
        is_link = stat_mod.S_ISLNK(info.st_mode or 0)
        if is_link:
            with contextlib.suppress(OSError, paramiko.SSHException):
                info = self._sftp.stat(path)  # resolve symlink target
        return FileStat(
            path=path, exists=True, mode=(info.st_mode or 0) & 0o7777,
            uid=info.st_uid if info.st_uid is not None else -1,
            gid=info.st_gid if info.st_gid is not None else -1,
            size=info.st_size or 0, is_symlink=is_link,
        )

    def list_dir(self, path: str) -> list[str]:
        try:
            return sorted(self._sftp.listdir(path))
        except (OSError, paramiko.SSHException):
            return []

    def run(self, key: str, timeout: float | None = None) -> CommandResult:
        argv = self._check_key(key)
        limit = timeout or (self.slow_timeout if key in SLOW_COMMANDS else self.command_timeout)
        # argv is fixed; shlex.quote each element so the remote shell treats
        # them as literal arguments. LC_ALL/PATH are pinned for stable parsing.
        command = "LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin " + " ".join(
            shlex.quote(part) for part in argv)
        try:
            # command is built from the fixed allowlist with every token shell-quoted
            _stdin, stdout, stderr = self._client.exec_command(  # nosec B601
                command, timeout=limit)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = stdout.channel.recv_exit_status()
        except paramiko.SSHException as exc:
            return CommandResult(rc=1, stdout="", stderr=str(exc))
        except TimeoutError:
            return CommandResult(rc=124, stdout="", stderr="timed out", timed_out=True)
        return CommandResult(rc=rc, stdout=out, stderr=err)

    def close(self) -> None:
        try:
            self._sftp.close()
        finally:
            self._client.close()
