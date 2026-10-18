"""Kernel / sysctl hardening controls."""

from __future__ import annotations

from ..collectors.base import HostFacts
from ..models import Category, Severity
from . import CheckContext, CheckOutcome, control, error, fail, ok

REF = ("CIS Distribution Independent Linux 3.2/3.3", "kernel.org sysctl")


def _sysctl_control(id: str, title: str, key: str, expected: str, severity: Severity,
                    rationale: str, profiles: tuple[str, ...] = ("server", "workstation"),
                    comparator: str = "eq") -> None:
    remediation = (f"Set '{key} = {expected}' in /etc/sysctl.d/99-secposture.conf and apply "
                   f"with 'sudo sysctl --system'.")

    @control(id, title, Category.KERNEL, severity, rationale, remediation, profiles=profiles,
             references=REF)
    def check(facts: HostFacts, ctx: CheckContext, _key=key, _exp=expected,
              _cmp=comparator) -> CheckOutcome:
        if _key not in facts.sysctl:
            return error(f"{_key} not present (kernel may not support it)")
        actual = facts.sysctl[_key].split()[0] if facts.sysctl[_key] else ""
        good = actual == _exp
        if _cmp == "gte":
            try:
                good = int(actual) >= int(_exp)
            except ValueError:
                good = False
        if good:
            return ok(f"{_key} = {actual}")
        fix = [f"echo '{_key} = {_exp}' | sudo tee -a /etc/sysctl.d/99-secposture.conf",
               "sudo sysctl --system"]
        return fail(f"{_key} = {actual} (expected {_cmp} {_exp})", fix=fix, key=_key,
                    actual=actual, expected=_exp)


_sysctl_control("KRN-01", "Address space layout randomization is enabled",
                "kernel.randomize_va_space", "2", Severity.HIGH,
                "ASLR randomizes memory layout, making memory-corruption exploits far less "
                "reliable. Value 2 enables full randomization.")
_sysctl_control("KRN-02", "IP forwarding is disabled", "net.ipv4.ip_forward", "0",
                Severity.MEDIUM, "A non-router host forwarding packets can be abused to pivot "
                "traffic between networks.", profiles=("workstation", "server"))
_sysctl_control("KRN-03", "ICMP redirects are not accepted", "net.ipv4.conf.all.accept_redirects",
                "0", Severity.MEDIUM, "Accepting ICMP redirects lets an attacker alter the "
                "host's routing table to intercept traffic.")
_sysctl_control("KRN-04", "Secure ICMP redirects only",
                "net.ipv4.conf.all.secure_redirects", "0", Severity.LOW,
                "Even 'secure' redirects trust gateways that may be spoofed; disable them.")
_sysctl_control("KRN-05", "ICMP redirects are not sent", "net.ipv4.conf.all.send_redirects",
                "0", Severity.LOW, "Only routers should send ICMP redirects.")
_sysctl_control("KRN-06", "Source-routed packets are rejected",
                "net.ipv4.conf.all.accept_source_route", "0", Severity.MEDIUM,
                "Source routing lets a sender dictate a packet's path and bypass network "
                "controls.")
_sysctl_control("KRN-07", "TCP SYN cookies are enabled", "net.ipv4.tcp_syncookies", "1",
                Severity.MEDIUM, "SYN cookies keep the host responsive during a SYN flood.")
_sysctl_control("KRN-08", "Reverse-path filtering is enabled", "net.ipv4.conf.all.rp_filter",
                "1", Severity.LOW, "Reverse-path filtering drops spoofed source addresses.")
_sysctl_control("KRN-09", "Broadcast ICMP is ignored",
                "net.ipv4.icmp_echo_ignore_broadcasts", "1", Severity.LOW,
                "Ignoring broadcast ICMP prevents the host from amplifying Smurf attacks.")
_sysctl_control("KRN-10", "Martian packets are logged", "net.ipv4.conf.all.log_martians", "1",
                Severity.INFO, "Logging impossible source addresses aids detection of spoofing.")
_sysctl_control("KRN-11", "Kernel pointer addresses are restricted", "kernel.kptr_restrict",
                "1", Severity.MEDIUM, "Hiding kernel pointers from unprivileged users removes "
                "an aid to kernel exploitation.", comparator="gte")
_sysctl_control("KRN-12", "dmesg is restricted", "kernel.dmesg_restrict", "1", Severity.LOW,
                "Restricting dmesg keeps kernel addresses and state from unprivileged users.")
_sysctl_control("KRN-13", "ptrace scope is restricted", "kernel.yama.ptrace_scope", "1",
                Severity.MEDIUM, "Restricting ptrace stops one process reading another's "
                "memory (e.g. scraping secrets from a running process).", comparator="gte")
_sysctl_control("KRN-14", "SUID core dumps are disabled", "fs.suid_dumpable", "0",
                Severity.MEDIUM, "Core dumps of SUID programs can contain sensitive data and "
                "must not be written.")


@control("KRN-15", "Hardlink and symlink protection is enabled", Category.KERNEL, Severity.LOW,
         "Protected symlinks/hardlinks prevent a class of TOCTOU attacks in world-writable "
         "directories such as /tmp.",
         "Set 'fs.protected_symlinks = 1' and 'fs.protected_hardlinks = 1' via sysctl.",
         references=REF)
def link_protection(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    sym = facts.sysctl.get("fs.protected_symlinks", "")
    hard = facts.sysctl.get("fs.protected_hardlinks", "")
    if sym == "1" and hard == "1":
        return ok("protected_symlinks and protected_hardlinks enabled")
    return fail(f"protected_symlinks={sym or '?'}, protected_hardlinks={hard or '?'}", fix=[
        "echo 'fs.protected_symlinks = 1' | sudo tee -a /etc/sysctl.d/99-secposture.conf",
        "echo 'fs.protected_hardlinks = 1' | sudo tee -a /etc/sysctl.d/99-secposture.conf",
        "sudo sysctl --system"])
