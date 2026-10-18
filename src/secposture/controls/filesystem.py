"""Filesystem permission and integrity controls."""

from __future__ import annotations

from ..collectors.base import FileStat, HostFacts
from ..models import Category, Severity
from . import CheckContext, CheckOutcome, control, fail, not_applicable, ok, q, warn

REF = ("CIS Distribution Independent Linux 6.1", "CIS 1.1")

# SUID/SGID binaries present on a stock distribution; anything outside this set
# is surfaced for review rather than failed outright.
COMMON_SUID = frozenset({
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chfn", "/usr/bin/chsh",
    "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/pkexec", "/usr/bin/fusermount", "/usr/bin/fusermount3", "/usr/bin/crontab",
    "/usr/bin/at", "/usr/bin/expiry", "/usr/bin/chage", "/usr/bin/wall", "/usr/bin/write",
    "/usr/bin/ssh-agent", "/usr/bin/dotlockfile", "/usr/bin/mlocate", "/usr/bin/bsd-write",
    "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/policykit-1/polkit-agent-helper-1", "/usr/sbin/unix_chkpwd",
    "/usr/sbin/pam_extrausers_chkpwd", "/usr/libexec/openssh/ssh-keysign",
    "/usr/bin/umount.udisks2", "/usr/sbin/mount.nfs",
})


def _check_perms(stat: FileStat, name: str, max_mode: int, owner: str = "root",
                 groups: tuple[str, ...] = ("root",)) -> CheckOutcome:
    if not stat.exists:
        return not_applicable(f"{name} not present")
    problems = []
    if stat.mode & ~max_mode & 0o777:
        problems.append(f"mode {stat.mode_str} (max {max_mode:04o})")
    if stat.owner and stat.owner != owner:
        problems.append(f"owner {stat.owner} (expected {owner})")
    if stat.group and stat.group not in groups:
        problems.append(f"group {stat.group} (expected {'/'.join(groups)})")
    if not problems:
        return ok(f"{name} {stat.mode_str} {stat.owner}:{stat.group}")
    fix = [f"sudo chown {owner}:{groups[0]} {q(name)}", f"sudo chmod {max_mode:04o} {q(name)}"]
    return fail(f"{name}: {', '.join(problems)}", fix=fix, mode=stat.mode_str,
                owner=stat.owner, group=stat.group)


@control("FS-01", "/etc/passwd permissions are correct", Category.FILESYSTEM, Severity.MEDIUM,
         "If /etc/passwd is writable by non-root, accounts can be added or UIDs changed.",
         "Run 'sudo chown root:root /etc/passwd && sudo chmod 644 /etc/passwd'.", references=REF)
def passwd_perms(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    return _check_perms(facts.file_stats["/etc/passwd"], "/etc/passwd", 0o644)


@control("FS-02", "/etc/shadow permissions are correct", Category.FILESYSTEM, Severity.HIGH,
         "A readable /etc/shadow exposes password hashes to offline cracking.",
         "Run 'sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow'.",
         references=REF)
def shadow_perms(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    return _check_perms(facts.file_stats["/etc/shadow"], "/etc/shadow", 0o640,
                        groups=("shadow", "root"))


@control("FS-03", "/etc/group permissions are correct", Category.FILESYSTEM, Severity.LOW,
         "A writable /etc/group lets attackers grant themselves privileged group membership.",
         "Run 'sudo chown root:root /etc/group && sudo chmod 644 /etc/group'.", references=REF)
def group_perms(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    return _check_perms(facts.file_stats["/etc/group"], "/etc/group", 0o644)


@control("FS-04", "/etc/gshadow permissions are correct", Category.FILESYSTEM, Severity.MEDIUM,
         "/etc/gshadow holds group password hashes and must not be readable by other users.",
         "Run 'sudo chown root:shadow /etc/gshadow && sudo chmod 640 /etc/gshadow'.",
         references=REF)
def gshadow_perms(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    return _check_perms(facts.file_stats["/etc/gshadow"], "/etc/gshadow", 0o640,
                        groups=("shadow", "root"))


@control("FS-05", "sshd_config permissions are correct", Category.FILESYSTEM, Severity.MEDIUM,
         "A writable sshd_config lets an attacker weaken SSH authentication.",
         "Run 'sudo chown root:root /etc/ssh/sshd_config && sudo chmod 600 "
         "/etc/ssh/sshd_config'.", references=REF)
def sshd_perms(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    return _check_perms(facts.file_stats["/etc/ssh/sshd_config"], "/etc/ssh/sshd_config", 0o600)


@control("FS-06", "No world-writable files", Category.FILESYSTEM, Severity.HIGH,
         "World-writable files can be modified by any user, enabling tampering with scripts, "
         "configuration or data that privileged processes rely on.",
         "Remove world write: 'sudo chmod o-w <file>' after confirming each is intentional.",
         references=REF)
def world_writable(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    files = facts.world_writable_files
    if not files:
        return ok("no world-writable files found")
    return fail(f"{len(files)} world-writable file(s)", files=files[:50],
                fix=[f"sudo chmod o-w {q(f)}" for f in files[:20]])


@control("FS-07", "World-writable directories have the sticky bit", Category.FILESYSTEM,
         Severity.MEDIUM, "A world-writable directory without the sticky bit lets any user "
         "delete or rename another user's files in it.",
         "Add the sticky bit: 'sudo chmod +t <dir>'.", references=REF)
def sticky_dirs(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    dirs = [d["path"] for d in facts.world_writable_dirs]
    if not dirs:
        return ok("world-writable directories all have the sticky bit")
    return fail(f"{len(dirs)} world-writable director(ies) without sticky bit", dirs=dirs[:50],
                fix=[f"sudo chmod +t {q(d)}" for d in dirs[:20]])


@control("FS-08", "No unowned files", Category.FILESYSTEM, Severity.MEDIUM,
         "Files with no valid owner or group often remain from deleted accounts and may be "
         "silently reassigned when a new user reuses the UID.",
         "Assign a valid owner: 'sudo chown root:root <file>' after review.", references=REF)
def unowned(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not facts.unowned:
        return ok("no unowned files found")
    return warn(f"{len(facts.unowned)} unowned file(s)", files=facts.unowned[:50])


@control("FS-09", "SUID/SGID binaries are the expected set", Category.FILESYSTEM,
         Severity.MEDIUM, "Each SUID/SGID binary runs with elevated privileges; an "
         "unexpected one is a common privilege-escalation vector and must be justified.",
         "Review each unexpected binary; remove the SUID/SGID bit if not required "
         "('sudo chmod u-s <file>'), or add it to allowed_suid once justified.", references=REF)
def suid_review(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not facts.suid_sgid:
        return ok("no SUID/SGID binaries found")
    unexpected = [b["path"] for b in facts.suid_sgid
                  if b["path"] not in COMMON_SUID and b["path"] not in ctx.allowed_suid]
    if not unexpected:
        return ok(f"{len(facts.suid_sgid)} SUID/SGID binaries, all expected")
    return warn(f"{len(unexpected)} unexpected SUID/SGID binary(ies) to review",
                unexpected=unexpected[:50], total=len(facts.suid_sgid))


@control("FS-10", "/tmp is mounted with nodev, nosuid, noexec", Category.FILESYSTEM,
         Severity.LOW, "Mounting /tmp with nodev,nosuid,noexec stops it being used to run "
         "dropped executables or SUID binaries.",
         "Mount /tmp as a separate filesystem with 'nodev,nosuid,noexec' options.",
         profiles=("server",), references=REF)
def tmp_mount(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    tmp = next((m for m in facts.mounts if m["target"] == "/tmp"), None)
    if tmp is None:
        return warn("/tmp is not a separate mount point")
    options = {o.strip() for o in tmp["options"].split(",")}
    missing = [opt for opt in ("nodev", "nosuid", "noexec") if opt not in options]
    if not missing:
        return ok(f"/tmp mounted with {tmp['options']}")
    return warn(f"/tmp missing mount options: {', '.join(missing)}", options=tmp["options"])


@control("FS-11", "Bootloader configuration is protected", Category.FILESYSTEM, Severity.LOW,
         "A readable grub.cfg can leak a hashed boot password; a writable one allows boot "
         "parameters to be changed.",
         "Run 'sudo chown root:root <grub.cfg> && sudo chmod 600 <grub.cfg>'.",
         profiles=("server",), references=REF)
def grub_perms(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    for path in ("/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"):
        stat = facts.file_stats.get(path)
        if stat and stat.exists:
            return _check_perms(stat, path, 0o600)
    return not_applicable("no grub.cfg found")
