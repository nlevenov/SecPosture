"""Native Debian (dpkg) and RPM version comparison.

Distribution package versions are not PEP 440 and must be compared with the
distro's own algorithm, or vulnerability ranges match the wrong versions.
Both algorithms below follow their reference implementations (dpkg
``verrevcmp`` and rpm ``rpmvercmp``) so that "is this installed version inside
the advisory's affected range" is answered correctly.
"""

from __future__ import annotations

import re


def _order(char: str) -> int:
    """Debian character ranking: '~' < end-of-string < letters < other symbols.

    Mirrors dpkg's ``order()``: a digit or the end of the string ranks 0, a
    letter ranks by its code point, '~' ranks below everything, and any other
    symbol ranks above the letters.
    """
    if char == "" or char.isdigit():
        return 0
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _deb_verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        # compare non-digit run
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) and not a[i].isdigit() else _order("")
            bc = _order(b[j]) if j < len(b) and not b[j].isdigit() else _order("")
            if ac != bc:
                return -1 if ac < bc else 1
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        # compare digit run numerically
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if first_diff == 0:
                first_diff = (a[i] > b[j]) - (a[i] < b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def deb_compare(a: str, b: str) -> int:
    """Return -1/0/1 for dpkg version ordering of ``a`` vs ``b``."""
    ea, _, ra = _split_deb(a)
    eb, _, rb = _split_deb(b)
    if ea != eb:
        return -1 if ea < eb else 1
    upstream = _deb_verrevcmp(_split_deb(a)[1], _split_deb(b)[1])
    if upstream:
        return upstream
    return _deb_verrevcmp(ra, rb)


def _split_deb(version: str) -> tuple[int, str, str]:
    version = version.strip()
    epoch = 0
    if ":" in version:
        head, _, version = version.partition(":")
        epoch = int(head) if head.isdigit() else 0
    upstream, _, revision = version.rpartition("-")
    if not upstream:  # no revision present
        upstream, revision = version, ""
    return epoch, upstream, revision


_RPM_SEG = re.compile(r"(\d+|[a-zA-Z]+|~|\^)")


def _rpm_segments(value: str) -> list[str]:
    return _RPM_SEG.findall(value)


def rpm_compare(a: str, b: str) -> int:
    """Return -1/0/1 for rpm version ordering (rpmvercmp), ignoring epoch here."""
    if a == b:
        return 0
    sa, sb = _rpm_segments(a), _rpm_segments(b)
    for x, y in zip(sa, sb, strict=False):
        if x == "~" or y == "~":
            if x != y:
                return -1 if x == "~" else 1
            continue
        if x == "^" or y == "^":
            if x != y:
                return 1 if x == "^" else -1
            continue
        x_digit, y_digit = x[0].isdigit(), y[0].isdigit()
        if x_digit != y_digit:
            return 1 if x_digit else -1       # numeric segments win over alpha
        if x_digit:
            xi, yi = x.lstrip("0") or "0", y.lstrip("0") or "0"
            if len(xi) != len(yi):
                return 1 if len(xi) > len(yi) else -1
        if x != y:
            return 1 if x > y else -1
    if len(sa) == len(sb):
        return 0
    # the version with remaining segments is newer, unless the next is '~'
    remaining = sa[len(sb):] if len(sa) > len(sb) else sb[len(sa):]
    longer_is_a = len(sa) > len(sb)
    if remaining and remaining[0] == "~":
        return -1 if longer_is_a else 1
    return 1 if longer_is_a else -1


def compare(a: str, b: str, scheme: str) -> int:
    if scheme == "rpm":
        return rpm_compare(a, b)
    return deb_compare(a, b)
