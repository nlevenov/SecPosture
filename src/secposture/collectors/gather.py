"""Build a :class:`HostFacts` from a collector by parsing read-only sources."""

from __future__ import annotations

import re
from typing import Any

from ..models import HostInfo
from ..sanitize import clean
from .base import SENSITIVE_FILES, Collector, HostFacts

_KV = re.compile(r"^\s*([A-Za-z0-9_.]+)\s*=\s*(.*?)\s*$")


def gather(collector: Collector) -> tuple[HostFacts, list[str]]:
    facts = HostFacts()
    errors: list[str] = []

    def guard(label: str, fn, *args):
        try:
            return fn(*args)
        except Exception as exc:  # one bad source must not abort the audit
            errors.append(f"{label}: {type(exc).__name__}: {exc}")
            return None

    facts.sshd_config, facts.sshd_source = guard("sshd_config", _sshd, collector) or ({}, "none")
    facts.login_defs = guard("login.defs", _login_defs, collector) or {}
    facts.passwd = guard("passwd", _passwd, collector) or []
    facts.groups = guard("group", _group, collector) or []
    shadow = guard("shadow", _shadow, collector)
    facts.shadow, facts.shadow_readable = (shadow or {}), shadow is not None
    facts.sysctl = guard("sysctl", _sysctl, collector) or {}
    facts.listening = guard("listening", _listening, collector) or []
    facts.packages = guard("packages", _packages, collector) or []
    facts.services = guard("services", _services, collector) or []
    facts.suid_sgid = guard("suid_sgid", _suid, collector) or []
    facts.world_writable_files = guard("world_writable", _ww_files, collector) or []
    facts.world_writable_dirs = guard("ww_dirs", _ww_dirs, collector) or []
    facts.unowned = guard("unowned", _unowned, collector) or []
    facts.firewall = guard("firewall", _firewall, collector) or {}
    facts.mounts = guard("mounts", _mounts, collector) or []
    facts.modules = guard("modules", _modules, collector) or []
    facts.file_stats = {p: collector.stat_file(p) for p in SENSITIVE_FILES}
    return facts, errors


def host_info(collector: Collector) -> HostInfo:
    info = HostInfo(transport=collector.transport)
    info.target = clean(getattr(collector, "target_label", ""), 100)
    uname = collector.run("uname")
    if uname.ok:
        parts = uname.stdout.split()
        info.kernel = clean(parts[1] if len(parts) > 1 else uname.stdout, 100)
    osr = _parse_kv_quoted(collector.read_file("/etc/os-release") or "")
    info.os_name = clean(osr.get("NAME", ""), 80)
    info.os_version = clean(osr.get("VERSION", osr.get("VERSION_ID", "")), 80)
    hostname = clean(collector.read_file("/etc/hostname") or "", 80)
    info.hostname = hostname or (info.target.split("@")[-1] if info.target else "localhost")
    uid = collector.run("id")
    info.privileged = uid.ok and uid.stdout.strip() == "0"
    if collector.run("dpkg").ok:
        info.package_manager = "dpkg"
    elif collector.run("rpm").ok:
        info.package_manager = "rpm"
    return info


# --------------------------------------------------------------- parsers

def _sshd(c: Collector) -> tuple[dict[str, str], str]:
    config: dict[str, str] = {}
    text = c.read_file("/etc/ssh/sshd_config")
    if text is None:
        return config, "none"
    _merge_sshd(config, text)
    for name in c.list_dir("/etc/ssh/sshd_config.d"):
        if name.endswith(".conf"):
            included = c.read_file(f"/etc/ssh/sshd_config.d/{name}")
            if included:
                _merge_sshd(config, included)
    return config, "file"


def _merge_sshd(config: dict[str, str], text: str) -> None:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("match "):
            break  # only global directives are evaluated (before any Match block)
        parts = line.split(None, 1)
        if len(parts) == 2:
            key = parts[0].lower()
            config.setdefault(key, parts[1].strip())  # first occurrence wins, as sshd does


def _login_defs(c: Collector) -> dict[str, str]:
    result: dict[str, str] = {}
    text = c.read_file("/etc/login.defs") or ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            result[parts[0].upper()] = parts[1].strip()
    return result


def _passwd(c: Collector) -> list[dict[str, Any]]:
    out = []
    for line in (c.read_file("/etc/passwd") or "").splitlines():
        fields = line.split(":")
        if len(fields) >= 7:
            out.append({"name": fields[0], "uid": _int(fields[2]), "gid": _int(fields[3]),
                        "home": fields[5], "shell": fields[6], "password": fields[1]})
    return out


def _group(c: Collector) -> list[dict[str, Any]]:
    out = []
    for line in (c.read_file("/etc/group") or "").splitlines():
        fields = line.split(":")
        if len(fields) >= 4:
            members = [m for m in fields[3].split(",") if m]
            out.append({"name": fields[0], "gid": _int(fields[2]), "members": members})
    return out


def _shadow(c: Collector) -> dict[str, list[str]] | None:
    text = c.read_file("/etc/shadow")
    if text is None:
        return None
    result: dict[str, list[str]] = {}
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) >= 2:
            result[fields[0]] = fields[1:]
    return result


def _sysctl(c: Collector) -> dict[str, str]:
    result: dict[str, str] = {}
    res = c.run("sysctl")
    if not res.ok:
        return result
    for line in res.stdout.splitlines():
        match = _KV.match(line)
        if match:
            result[match.group(1)] = match.group(2)
    return result


def _listening(c: Collector) -> list[dict[str, Any]]:
    res = c.run("listen")
    if not res.ok:
        res = c.run("listen_noproc")
    sockets = []
    for line in res.stdout.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        proto, local = cols[0], cols[4]
        addr, _, port = local.rpartition(":")
        process = ""
        match = re.search(r'users:\(\("([^"]+)"', line)
        if match:
            process = match.group(1)
        sockets.append({"proto": proto, "address": addr, "port": _int(port),
                        "process": process})
    return sockets


def _packages(c: Collector) -> list[tuple[str, str]]:
    for key in ("dpkg", "rpm"):
        res = c.run(key)
        if res.ok and res.stdout.strip():
            packages = []
            for line in res.stdout.splitlines():
                cols = line.split("\t")
                if len(cols) < 2 or not cols[0]:
                    continue
                installed = key == "rpm" or (len(cols) >= 3 and "n" not in cols[2])
                if installed:  # dpkg marks removed-but-configured packages with 'n'
                    packages.append((cols[0], cols[1]))
            return packages
    return []


def _services(c: Collector) -> list[str]:
    res = c.run("services")
    out = []
    for line in res.stdout.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.endswith(".service"):
            out.append(name[: -len(".service")])
    return out


def _find_rows(c: Collector, key: str) -> list[str]:
    res = c.run(key)
    if res.timed_out:
        raise TimeoutError(f"{key} filesystem scan timed out")
    return [line for line in res.stdout.splitlines() if line.strip()]


def _suid(c: Collector) -> list[dict[str, Any]]:
    out = []
    for line in _find_rows(c, "suid_sgid"):
        cols = line.split(None, 3)
        if len(cols) == 4:
            out.append({"mode": cols[0], "owner": cols[1], "group": cols[2], "path": cols[3]})
    return out


def _ww_files(c: Collector) -> list[str]:
    return [line.split(None, 3)[-1] for line in _find_rows(c, "world_writable")]


def _ww_dirs(c: Collector) -> list[dict[str, Any]]:
    out = []
    for line in _find_rows(c, "ww_dirs"):
        cols = line.split(None, 3)
        if len(cols) == 4:
            out.append({"mode": cols[0], "path": cols[3]})
    return out


def _unowned(c: Collector) -> list[str]:
    return [line.split(None, 2)[-1] for line in _find_rows(c, "unowned")]


def _firewall(c: Collector) -> dict[str, Any]:
    ufw = c.run("ufw")
    if ufw.ok and "status:" in ufw.stdout.lower():
        active = "status: active" in ufw.stdout.lower()
        return {"backend": "ufw", "active": active}
    fw = c.run("firewalld")
    if fw.ok and "running" in fw.stdout.lower():
        return {"backend": "firewalld", "active": True}
    nft = c.run("nft")
    if nft.ok and nft.stdout.strip():
        rules = sum(1 for line in nft.stdout.splitlines() if "chain" in line)
        return {"backend": "nftables", "active": rules > 0, "chains": rules}
    ipt = c.run("iptables")
    if ipt.ok:
        policies = [line for line in ipt.stdout.splitlines() if line.startswith("-P")]
        drops = any("DROP" in p for p in policies)
        rules = sum(1 for line in ipt.stdout.splitlines() if line.startswith("-A"))
        return {"backend": "iptables", "active": drops or rules > 0, "rules": rules}
    return {"backend": "none", "active": False}


def _mounts(c: Collector) -> list[dict[str, str]]:
    res = c.run("mounts")
    out = []
    for line in res.stdout.splitlines():
        cols = line.split(None, 3)
        if len(cols) == 4:
            out.append({"target": cols[0], "source": cols[1], "fstype": cols[2],
                        "options": cols[3]})
    return out


def _modules(c: Collector) -> list[str]:
    res = c.run("modules")
    return [line.split()[0] for line in res.stdout.splitlines()[1:] if line.split()]


def _parse_kv_quoted(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        match = _KV.match(line)
        if match:
            result[match.group(1)] = match.group(2).strip().strip('"')
    return result


def _int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1
