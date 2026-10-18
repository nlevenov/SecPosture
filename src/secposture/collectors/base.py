"""Read-only fact collection.

A ``Collector`` exposes exactly four primitives against a target: read a file,
stat a file, list a directory, and run one of a **fixed set** of read-only
commands. No method ever takes a caller-supplied command, and no target value
is ever interpolated into a command line - the command allowlist below is the
only thing that runs. This is what keeps an auditor safe to point at a host:
it observes, it never changes anything and it cannot be steered into running
arbitrary input.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

# Logical name -> argv. Every command is read-only and non-interactive.
# `-xdev` keeps the filesystem scans on the root device so they stay bounded.
COMMANDS: dict[str, list[str]] = {
    "uname": ["uname", "-rs"],
    "id": ["id", "-u"],
    "os_release": ["cat", "/etc/os-release"],
    "sysctl": ["sysctl", "-a", "--ignore"],
    "listen": ["ss", "-tulnpH"],
    "listen_noproc": ["ss", "-tulnH"],
    "dpkg": ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${db:Status-Abbrev}\\n"],
    "rpm": ["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\tii\\n"],
    "services": ["systemctl", "list-units", "--type=service", "--state=running",
                 "--no-pager", "--no-legend", "--plain"],
    "suid_sgid": ["find", "/", "-xdev", "-type", "f", "(", "-perm", "-4000", "-o",
                  "-perm", "-2000", ")", "-printf", "%m %u %g %p\\n"],
    "world_writable": ["find", "/", "-xdev", "-type", "f", "-perm", "-0002",
                       "-not", "-path", "/proc/*", "-printf", "%m %u %g %p\\n"],
    "ww_dirs": ["find", "/", "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm",
                "-1000", "-printf", "%m %u %g %p\\n"],
    "unowned": ["find", "/", "-xdev", "(", "-nouser", "-o", "-nogroup", ")",
                "-printf", "%u %g %p\\n"],
    "ufw": ["ufw", "status", "verbose"],
    "firewalld": ["firewall-cmd", "--state"],
    "iptables": ["iptables", "-S"],
    "nft": ["nft", "list", "ruleset"],
    "modules": ["lsmod"],
    "mounts": ["findmnt", "-rn", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"],
}
# Commands allowed to be slow (filesystem walks); given a longer timeout.
SLOW_COMMANDS = frozenset({"suid_sgid", "world_writable", "ww_dirs", "unowned"})

# Files read directly (via open / SFTP), never through a shell.
SENSITIVE_FILES = (
    "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/login.defs",
    "/etc/ssh/sshd_config", "/etc/fstab", "/etc/os-release", "/etc/crontab",
    "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/etc/gshadow",
)


@dataclass
class CommandResult:
    rc: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out


@dataclass
class FileStat:
    path: str
    exists: bool
    mode: int = 0                 # permission bits, e.g. 0o644
    uid: int = -1
    gid: int = -1
    owner: str = ""
    group: str = ""
    size: int = 0
    is_symlink: bool = False

    @property
    def mode_str(self) -> str:
        return format(self.mode, "04o")


class Collector(ABC):
    """Abstract read-only view of a target host."""

    transport = "base"

    @abstractmethod
    def read_file(self, path: str, max_bytes: int = 1_048_576) -> str | None:
        """Return file contents, or None if missing / unreadable."""

    @abstractmethod
    def stat_file(self, path: str) -> FileStat:
        ...

    @abstractmethod
    def list_dir(self, path: str) -> list[str]:
        """Return file names in ``path`` (not recursive), empty if unreadable."""

    @abstractmethod
    def run(self, key: str, timeout: float | None = None) -> CommandResult:
        """Run the allowlisted command named ``key``."""

    def close(self) -> None:  # noqa: B027 - optional override; local collector needs none
        return None

    def __enter__(self) -> Collector:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -------------------------------------------------------- shared helpers
    @staticmethod
    def _check_key(key: str) -> list[str]:
        if key not in COMMANDS:
            raise KeyError(f"command {key!r} is not in the read-only allowlist")
        return COMMANDS[key]


@dataclass
class HostFacts:
    """Everything the controls evaluate, gathered once per audit."""

    sshd_config: dict[str, str] = field(default_factory=dict)
    sshd_source: str = "none"     # "sshd -T" | "file" | "none"
    login_defs: dict[str, str] = field(default_factory=dict)
    passwd: list[dict[str, Any]] = field(default_factory=list)
    shadow: dict[str, list[str]] = field(default_factory=dict)
    groups: list[dict[str, Any]] = field(default_factory=list)
    sysctl: dict[str, str] = field(default_factory=dict)
    listening: list[dict[str, Any]] = field(default_factory=list)
    packages: list[tuple[str, str]] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    suid_sgid: list[dict[str, Any]] = field(default_factory=list)
    world_writable_files: list[str] = field(default_factory=list)
    world_writable_dirs: list[dict[str, Any]] = field(default_factory=list)
    unowned: list[str] = field(default_factory=list)
    firewall: dict[str, Any] = field(default_factory=dict)
    mounts: list[dict[str, str]] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    file_stats: dict[str, FileStat] = field(default_factory=dict)
    shadow_readable: bool = False
    now: float = field(default_factory=time.time)
