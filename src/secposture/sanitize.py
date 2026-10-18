"""Normalization of untrusted values.

Everything this tool reads from a target - config file contents, command
output, package names, process names - is data, and on a compromised host it
may be hostile. Values that reach a report (HTML, JSON, terminal) are bounded
and stripped of control and markup characters here, once, at the point they
enter the model.
"""

from __future__ import annotations

import re

# Control characters (including ESC, so terminal ANSI injection is impossible)
# are removed. Markup characters such as < > are kept intact and instead
# encoded at each output boundary: the HTML report autoescapes, the terminal
# and JSON treat them as ordinary text.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS = re.compile(r"[ \t]+")

# Hostnames / targets accepted for SSH. Deliberately strict: these are used to
# build connections and must never carry shell metacharacters or option-like
# values.
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})\.?)+$")
_USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")


def clean(value: object, max_len: int = 512) -> str:
    """Printable, single-line, markup-free text bounded to ``max_len``."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = _CONTROL.sub("", str(value))
    text = _WS.sub(" ", text.replace("\r", " ").replace("\n", " ")).strip()
    return text[:max_len]


def clean_block(value: object, max_len: int = 8192) -> str:
    """Like :func:`clean` but keeps newlines (for multi-line evidence)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    lines = (_CONTROL.sub("", line) for line in str(value).splitlines())
    return "\n".join(lines)[:max_len]


def valid_hostname(value: str) -> bool:
    value = value.strip()
    if value in ("localhost",) or _is_ip(value):
        return True
    return bool(_HOSTNAME.match(value))


def valid_username(value: str) -> bool:
    return bool(_USERNAME.match(value.strip()))


def _is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_target(target: str) -> tuple[str, str]:
    """Split ``user@host`` into (user, host), validating both.

    Raises ``ValueError`` on anything that is not a plain user@host pair, so a
    crafted value can never flow into a connection or a command line.
    """
    target = target.strip()
    if "@" not in target:
        raise ValueError("ssh target must be in the form user@host")
    user, _, host = target.partition("@")
    if not valid_username(user):
        raise ValueError(f"invalid username in ssh target: {user!r}")
    if not valid_hostname(host):
        raise ValueError(f"invalid hostname in ssh target: {host!r}")
    return user, host
