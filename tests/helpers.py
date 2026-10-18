"""Fixture builders for controls and advisory tests."""

from __future__ import annotations

from secposture.collectors.base import FileStat, HostFacts


def facts(**overrides) -> HostFacts:
    """A HostFacts preloaded with a reasonably hardened baseline.

    Individual tests override single fields to drive one control to fail.
    """
    base = HostFacts(
        sshd_config={
            "permitrootlogin": "no", "passwordauthentication": "no",
            "permitemptypasswords": "no", "maxauthtries": "4",
            "clientaliveinterval": "300", "clientalivecountmax": "3",
            "logingracetime": "60", "x11forwarding": "no", "ignorerhosts": "yes",
            "hostbasedauthentication": "no", "loglevel": "VERBOSE",
        },
        sshd_source="file",
        login_defs={"ENCRYPT_METHOD": "SHA512", "PASS_MAX_DAYS": "365",
                    "PASS_WARN_AGE": "7", "UMASK": "027"},
        passwd=[{"name": "root", "uid": 0, "gid": 0, "home": "/root",
                 "shell": "/bin/bash", "password": "x"},
                {"name": "daemon", "uid": 1, "gid": 1, "home": "/usr/sbin",
                 "shell": "/usr/sbin/nologin", "password": "x"},
                {"name": "alice", "uid": 1000, "gid": 1000, "home": "/home/alice",
                 "shell": "/bin/bash", "password": "x"}],
        groups=[{"name": "sudo", "gid": 27, "members": ["alice"]}],
        shadow={"root": ["$6$abc$def", "19000"], "alice": ["$6$x$y", "19000"]},
        shadow_readable=True,
        sysctl={
            "kernel.randomize_va_space": "2", "net.ipv4.ip_forward": "0",
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.all.secure_redirects": "0",
            "net.ipv4.conf.all.send_redirects": "0",
            "net.ipv4.conf.all.accept_source_route": "0",
            "net.ipv4.tcp_syncookies": "1", "net.ipv4.conf.all.rp_filter": "1",
            "net.ipv4.icmp_echo_ignore_broadcasts": "1",
            "net.ipv4.conf.all.log_martians": "1", "kernel.kptr_restrict": "2",
            "kernel.dmesg_restrict": "1", "kernel.yama.ptrace_scope": "1",
            "fs.suid_dumpable": "0", "fs.protected_symlinks": "1",
            "fs.protected_hardlinks": "1"},
        listening=[{"proto": "tcp", "address": "0.0.0.0", "port": 22, "process": "sshd"}],
        packages=[("openssh-server", "1:9.6p1-3"), ("bash", "5.2.21-2")],
        services=["ssh", "systemd-journald"],
        suid_sgid=[{"mode": "4755", "owner": "root", "group": "root",
                    "path": "/usr/bin/sudo"}],
        world_writable_files=[],
        world_writable_dirs=[],
        unowned=[],
        firewall={"backend": "ufw", "active": True},
        mounts=[{"target": "/tmp", "source": "tmpfs", "fstype": "tmpfs",
                 "options": "rw,nosuid,nodev,noexec"}],
        file_stats={
            "/etc/passwd": FileStat("/etc/passwd", True, 0o644, 0, 0, "root", "root"),
            "/etc/shadow": FileStat("/etc/shadow", True, 0o640, 0, 42, "root", "shadow"),
            "/etc/group": FileStat("/etc/group", True, 0o644, 0, 0, "root", "root"),
            "/etc/gshadow": FileStat("/etc/gshadow", True, 0o640, 0, 42, "root", "shadow"),
            "/etc/ssh/sshd_config": FileStat("/etc/ssh/sshd_config", True, 0o600, 0, 0,
                                             "root", "root"),
        },
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base
