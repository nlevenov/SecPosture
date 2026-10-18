"""OpenSSH server hardening controls.

Values fall back to the OpenSSH compiled-in default when a directive is
absent, so the audit reflects the server's effective behaviour, not just what
is written in the file. Only global directives (before any ``Match`` block)
are evaluated.
"""

from __future__ import annotations

from ..collectors.base import HostFacts
from ..models import Category, Severity
from . import CheckContext, CheckOutcome, control, fail, not_applicable, ok, warn

REF = ("CIS Distribution Independent Linux 5.2", "OpenSSH sshd_config(5)")

WEAK_CRYPTO = ("arcfour", "3des", "-cbc", "hmac-md5", "hmac-sha1-96", "umac-64",
               "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "blowfish",
               "cast128", "ssh-rsa")


def _get(facts: HostFacts, key: str, default: str) -> str:
    return facts.sshd_config.get(key.lower(), default)


def _ssh_present(facts: HostFacts) -> bool:
    return facts.sshd_source != "none"


@control("SSH-01", "Root login over SSH is restricted", Category.SSH, Severity.HIGH,
         "Direct SSH login as root removes per-user accountability and makes the single "
         "most valuable account directly brute-forceable.",
         "Set 'PermitRootLogin no' (or 'prohibit-password' for key-only break-glass access) "
         "in /etc/ssh/sshd_config and reload sshd.", references=REF)
def permit_root_login(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not _ssh_present(facts):
        return not_applicable("no sshd_config found")
    value = _get(facts, "PermitRootLogin", "prohibit-password").lower()
    if value == "no":
        return ok("PermitRootLogin no")
    fix = ["sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
           "sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd"]
    if value == "prohibit-password":
        return warn("PermitRootLogin prohibit-password (key-only root login still allowed)",
                    fix=fix, value=value)
    return fail(f"PermitRootLogin {value}", fix=fix, value=value)


@control("SSH-02", "SSH uses key-based authentication", Category.SSH, Severity.MEDIUM,
         "Password authentication exposes SSH to credential guessing. Public-key "
         "authentication is not brute-forceable.",
         "Set 'PasswordAuthentication no' once key access is confirmed working.",
         references=REF)
def password_auth(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not _ssh_present(facts):
        return not_applicable("no sshd_config found")
    value = _get(facts, "PasswordAuthentication", "yes").lower()
    if value == "no":
        return ok("PasswordAuthentication no")
    fix = ["sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "
           "/etc/ssh/sshd_config", "sudo systemctl reload ssh 2>/dev/null || "
           "sudo systemctl reload sshd"]
    return fail("PasswordAuthentication yes", fix=fix, value=value)


@control("SSH-03", "Empty passwords are rejected over SSH", Category.SSH, Severity.CRITICAL,
         "Permitting empty passwords lets any account with a blank password be accessed "
         "with no credential at all.",
         "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.", references=REF)
def permit_empty(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not _ssh_present(facts):
        return not_applicable("no sshd_config found")
    value = _get(facts, "PermitEmptyPasswords", "no").lower()
    if value == "no":
        return ok("PermitEmptyPasswords no")
    return fail("PermitEmptyPasswords yes", value=value, fix=[
        "sudo sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "
        "/etc/ssh/sshd_config"])


@control("SSH-04", "Authentication attempts per connection are limited", Category.SSH,
         Severity.MEDIUM, "A low MaxAuthTries slows online password guessing.",
         "Set 'MaxAuthTries 4' or lower in /etc/ssh/sshd_config.", references=REF)
def max_auth_tries(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not _ssh_present(facts):
        return not_applicable("no sshd_config found")
    try:
        value = int(_get(facts, "MaxAuthTries", "6"))
    except ValueError:
        return warn("MaxAuthTries not an integer")
    if value <= 4:
        return ok(f"MaxAuthTries {value}")
    return fail(f"MaxAuthTries {value} (> 4)", value=value, fix=[
        "sudo sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config"])


@control("SSH-05", "Idle SSH sessions time out", Category.SSH, Severity.LOW,
         "Idle interactive sessions left open are a hijacking opportunity on shared or "
         "unattended workstations.",
         "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 3' in /etc/ssh/sshd_config.",
         references=REF)
def client_alive(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not _ssh_present(facts):
        return not_applicable("no sshd_config found")
    try:
        interval = int(_get(facts, "ClientAliveInterval", "0"))
        count = int(_get(facts, "ClientAliveCountMax", "3"))
    except ValueError:
        return warn("ClientAlive settings not integers")
    if 0 < interval <= 300 and count <= 3:
        return ok(f"ClientAliveInterval {interval}, ClientAliveCountMax {count}")
    return fail(f"ClientAliveInterval {interval}, ClientAliveCountMax {count}",
                interval=interval, count=count, fix=[
                    "sudo sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' "
                    "/etc/ssh/sshd_config",
                    "sudo sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 3/' "
                    "/etc/ssh/sshd_config"])


@control("SSH-06", "SSH login grace time is short", Category.SSH, Severity.LOW,
         "A long LoginGraceTime lets unauthenticated connections tie up server resources.",
         "Set 'LoginGraceTime 60' or lower in /etc/ssh/sshd_config.", references=REF)
def login_grace(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not _ssh_present(facts):
        return not_applicable("no sshd_config found")
    raw = _get(facts, "LoginGraceTime", "120").lower().replace("m", "")
    try:
        value = int(raw) * (60 if "m" in _get(facts, "LoginGraceTime", "120").lower() else 1)
    except ValueError:
        return warn("LoginGraceTime not parseable")
    if 0 < value <= 60:
        return ok(f"LoginGraceTime {value}s")
    return fail(f"LoginGraceTime {value}s (> 60)", value=value, fix=[
        "sudo sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config"])


@control("SSH-07", "X11 forwarding is disabled", Category.SSH, Severity.LOW,
         "X11 forwarding widens the attack surface between client and server and is rarely "
         "needed on servers.",
         "Set 'X11Forwarding no' in /etc/ssh/sshd_config.",
         profiles=("server",), references=REF)
def x11(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not _ssh_present(facts):
        return not_applicable("no sshd_config found")
    value = _get(facts, "X11Forwarding", "no").lower()
    if value == "no":
        return ok("X11Forwarding no")
    return fail("X11Forwarding yes", value=value, fix=[
        "sudo sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config"])


@control("SSH-08", "Only strong SSH cryptography is offered", Category.SSH, Severity.MEDIUM,
         "Legacy ciphers, MACs and key-exchange algorithms (CBC modes, HMAC-MD5/SHA1, "
         "DH group1/14-SHA1, 3DES, arcfour) have known weaknesses.",
         "Remove weak algorithms, or pin modern ones with 'Ciphers', 'MACs' and "
         "'KexAlgorithms' directives in /etc/ssh/sshd_config.", references=REF)
def weak_crypto(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not _ssh_present(facts):
        return not_applicable("no sshd_config found")
    offenders = {}
    for directive in ("ciphers", "macs", "kexalgorithms", "hostkeyalgorithms"):
        value = facts.sshd_config.get(directive)
        if value:
            weak = [w for w in WEAK_CRYPTO if w.lstrip("-") in value.lower()]
            if weak:
                offenders[directive] = sorted(set(weak))
    if not offenders:
        return ok("no weak algorithms explicitly configured")
    return fail(f"weak algorithms configured: {', '.join(offenders)}", weak=offenders)


@control("SSH-09", "Rhosts and host-based authentication are disabled", Category.SSH,
         Severity.MEDIUM, "Host-based and .rhosts authentication trust the client host "
         "instead of a credential and are easily spoofed.",
         "Set 'IgnoreRhosts yes' and 'HostbasedAuthentication no' in /etc/ssh/sshd_config.",
         references=REF)
def rhosts(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not _ssh_present(facts):
        return not_applicable("no sshd_config found")
    ignore = _get(facts, "IgnoreRhosts", "yes").lower()
    hostbased = _get(facts, "HostbasedAuthentication", "no").lower()
    if ignore == "yes" and hostbased == "no":
        return ok("IgnoreRhosts yes, HostbasedAuthentication no")
    return fail(f"IgnoreRhosts {ignore}, HostbasedAuthentication {hostbased}",
                ignore_rhosts=ignore, hostbased=hostbased)


@control("SSH-10", "SSH logging is verbose enough for forensics", Category.SSH, Severity.INFO,
         "LogLevel VERBOSE records the key fingerprint used to log in, which is essential "
         "for investigating unauthorized access.",
         "Set 'LogLevel VERBOSE' in /etc/ssh/sshd_config.", references=REF)
def log_level(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not _ssh_present(facts):
        return not_applicable("no sshd_config found")
    value = _get(facts, "LogLevel", "INFO").upper()
    if value in ("VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3"):
        return ok(f"LogLevel {value}")
    return warn(f"LogLevel {value} (VERBOSE recommended)", value=value, fix=[
        "sudo sed -i 's/^#*LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config"])
