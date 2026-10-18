"""User account and password-policy controls."""

from __future__ import annotations

from ..collectors.base import HostFacts
from ..models import Category, Severity
from . import CheckContext, CheckOutcome, control, error, fail, manual, ok, q, warn

REF = ("CIS Distribution Independent Linux 5.4", "shadow(5)", "login.defs(5)")
NOLOGIN_SHELLS = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false",
                  "/dev/null", "")
STRONG_HASHES = ("sha512", "yescrypt")


@control("ACC-01", "Only root has UID 0", Category.ACCOUNTS, Severity.CRITICAL,
         "Any account with UID 0 has full root privileges. A second UID-0 account is a "
         "classic persistence backdoor.",
         "Change the extra account's UID, or remove it, so root is the only UID-0 account.",
         references=REF)
def uid_zero(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    extras = [u["name"] for u in facts.passwd if u["uid"] == 0 and u["name"] != "root"]
    if not extras:
        return ok("root is the only UID-0 account")
    return fail(f"additional UID-0 accounts: {', '.join(extras)}", accounts=extras)


@control("ACC-02", "No account has an empty password", Category.ACCOUNTS, Severity.CRITICAL,
         "An account whose shadow password field is empty can be accessed with no password.",
         "Lock or set a password for the account: 'sudo passwd -l <user>'.", references=REF)
def empty_passwords(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not facts.shadow_readable:
        return error("/etc/shadow not readable (run as root for this check)")
    empty = [user for user, fields in facts.shadow.items() if fields and fields[0] == ""]
    if not empty:
        return ok("no accounts with an empty password")
    return fail(f"accounts with empty password: {', '.join(empty)}", accounts=empty,
                fix=[f"sudo passwd -l {q(u)}" for u in empty])


@control("ACC-03", "Strong password hashing is configured", Category.ACCOUNTS, Severity.MEDIUM,
         "Weak password hashing (MD5, DES) makes stolen hashes cheap to crack offline.",
         "Set 'ENCRYPT_METHOD SHA512' (or yescrypt) in /etc/login.defs.", references=REF)
def hash_method(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    method = facts.login_defs.get("ENCRYPT_METHOD", "").lower()
    if method in STRONG_HASHES:
        return ok(f"ENCRYPT_METHOD {method}")
    if not method:
        return warn("ENCRYPT_METHOD not set in /etc/login.defs (defaults are PAM-dependent)")
    return fail(f"weak ENCRYPT_METHOD {method}", value=method, fix=[
        "sudo sed -i 's/^#*ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs"])


@control("ACC-04", "Maximum password age is bounded", Category.ACCOUNTS, Severity.LOW,
         "Passwords that never expire give a leaked credential an unlimited useful life.",
         "Set 'PASS_MAX_DAYS 365' (or stricter) in /etc/login.defs.", references=REF)
def pass_max_days(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    try:
        value = int(facts.login_defs.get("PASS_MAX_DAYS", "99999"))
    except ValueError:
        return warn("PASS_MAX_DAYS not an integer")
    if 0 < value <= 365:
        return ok(f"PASS_MAX_DAYS {value}")
    return fail(f"PASS_MAX_DAYS {value} (> 365)", value=value, fix=[
        "sudo sed -i 's/^#*PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs"])


@control("ACC-05", "Password warning period is set", Category.ACCOUNTS, Severity.INFO,
         "Users warned before expiry are less likely to be locked out and choose rushed "
         "weak passwords.",
         "Set 'PASS_WARN_AGE 7' or more in /etc/login.defs.", references=REF)
def pass_warn(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    try:
        value = int(facts.login_defs.get("PASS_WARN_AGE", "0"))
    except ValueError:
        return warn("PASS_WARN_AGE not an integer")
    return ok(f"PASS_WARN_AGE {value}") if value >= 7 else warn(f"PASS_WARN_AGE {value} (< 7)")


@control("ACC-06", "Default umask is restrictive", Category.ACCOUNTS, Severity.LOW,
         "A permissive default umask makes new files world- or group-readable, leaking data "
         "between users.",
         "Set 'UMASK 027' in /etc/login.defs.", references=REF)
def umask(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    value = facts.login_defs.get("UMASK", "022")
    try:
        bits = int(value, 8)
    except ValueError:
        return warn(f"UMASK {value} not octal")
    if bits & 0o027 == 0o027:
        return ok(f"UMASK {value}")
    return fail(f"UMASK {value} (027 or stricter recommended)", value=value, fix=[
        "sudo sed -i 's/^#*UMASK.*/UMASK 027/' /etc/login.defs"])


@control("ACC-07", "System accounts have no interactive shell", Category.ACCOUNTS,
         Severity.MEDIUM, "Service / system accounts (UID < 1000) with a login shell widen "
         "the set of accounts an attacker can use for interactive access or lateral movement.",
         "Set the shell of non-login system accounts to nologin: "
         "'sudo usermod -s /usr/sbin/nologin <user>'.", references=REF)
def system_shells(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    offenders = [u["name"] for u in facts.passwd
                 if 0 < u["uid"] < 1000 and u["shell"] not in NOLOGIN_SHELLS
                 and u["name"] not in ("sync",)]
    if not offenders:
        return ok("system accounts have no interactive shell")
    return warn(f"system accounts with a login shell: {', '.join(offenders)}",
                accounts=offenders,
                fix=[f"sudo usermod -s /usr/sbin/nologin {q(u)}" for u in offenders])


@control("ACC-08", "Shadowed passwords are in use", Category.ACCOUNTS, Severity.HIGH,
         "A password hash stored in world-readable /etc/passwd (instead of 'x' pointing to "
         "/etc/shadow) can be read and cracked by any local user.",
         "Run 'sudo pwconv' to move password hashes into /etc/shadow.", references=REF)
def shadowed(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    leaked = [u["name"] for u in facts.passwd if u["password"] not in ("x", "*", "!")]
    if not leaked:
        return ok("all password hashes are shadowed")
    return fail(f"password hash in /etc/passwd for: {', '.join(leaked)}", accounts=leaked,
                fix=["sudo pwconv"])


@control("ACC-09", "No duplicate UIDs or usernames", Category.ACCOUNTS, Severity.MEDIUM,
         "Duplicate UIDs make two usernames share one identity, breaking accountability and "
         "file ownership; duplicate names cause unpredictable logins.",
         "Give each account a unique UID and name in /etc/passwd.", references=REF)
def duplicates(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    seen_uid: dict[int, list[str]] = {}
    seen_name: dict[str, int] = {}
    for u in facts.passwd:
        seen_uid.setdefault(u["uid"], []).append(u["name"])
        seen_name[u["name"]] = seen_name.get(u["name"], 0) + 1
    dup_uid = {uid: names for uid, names in seen_uid.items() if len(names) > 1}
    dup_name = [name for name, count in seen_name.items() if count > 1]
    if not dup_uid and not dup_name:
        return ok("no duplicate UIDs or usernames")
    return fail("duplicate accounts found", duplicate_uids=dup_uid, duplicate_names=dup_name)


@control("ACC-10", "Root PATH and login review", Category.ACCOUNTS, Severity.INFO,
         "The set of accounts able to obtain root (sudo / wheel group members) should be "
         "reviewed periodically and kept minimal.",
         "Review members of the sudo/wheel groups and remove any that no longer need it.",
         references=REF)
def sudoers_review(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    admins: list[str] = []
    for group in facts.groups:
        if group["name"] in ("sudo", "wheel", "admin"):
            admins.extend(group["members"])
    return manual(f"accounts able to obtain root (sudo/wheel/admin): "
                  f"{', '.join(sorted(set(admins))) or 'none found in group file'}",
                  admins=sorted(set(admins)))
