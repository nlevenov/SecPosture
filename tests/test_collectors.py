"""Local collector and a real SSH integration test against a throwaway sshd."""

import pytest

from secposture.collectors import LocalCollector, SSHCollector, gather, host_info
from secposture.collectors.base import COMMANDS


def test_command_allowlist_is_read_only():
    # every allowlisted command is a known read-only tool; no mutating verbs
    mutating = {"rm", "mv", "cp", "dd", "mkfs", "chmod", "chown", "kill", "tee", "sh", "bash"}
    for argv in COMMANDS.values():
        assert argv[0] not in mutating


def test_local_collector_rejects_unknown_command():
    c = LocalCollector()
    with pytest.raises(KeyError):
        c.run("rm -rf /")
    with pytest.raises(KeyError):
        c.run("arbitrary")


def test_local_collector_reads_facts():
    c = LocalCollector()
    assert c.run("id").ok
    stat = c.stat_file("/etc/passwd")
    assert stat.exists and stat.owner == "root"
    assert c.read_file("/etc/hostname") is not None
    assert c.read_file("/nonexistent/path") is None


def test_local_gather_and_host_info():
    c = LocalCollector()
    info = host_info(c)
    assert info.transport == "local" and info.os_name
    f, errors = gather(c)
    assert f.passwd and f.sysctl
    assert isinstance(errors, list)


def test_ssh_collector_matches_local(ssh_server):
    local_facts, _ = gather(LocalCollector())
    with SSHCollector(ssh_server["target"], port=ssh_server["port"],
                      key_file=ssh_server["key"], known_hosts=ssh_server["known_hosts"],
                      allow_agent=False) as c:
        assert c.transport == "ssh"
        info = host_info(c)
        assert info.transport == "ssh" and info.privileged  # root over ssh
        ssh_facts, errors = gather(c)
    # reading /etc/shadow over SFTP works as root
    assert ssh_facts.shadow_readable == local_facts.shadow_readable
    assert ssh_facts.sshd_config == local_facts.sshd_config
    assert len(ssh_facts.passwd) == len(local_facts.passwd)


def test_ssh_rejects_unknown_host_key(ssh_server, tmp_path):
    import paramiko

    empty = tmp_path / "empty_known_hosts"
    empty.write_text("")
    with pytest.raises((paramiko.SSHException, paramiko.BadHostKeyException,
                        paramiko.ssh_exception.SSHException)):
        SSHCollector(ssh_server["target"], port=ssh_server["port"],
                     key_file=ssh_server["key"], known_hosts=str(empty), allow_agent=False)


def test_ssh_run_only_allows_allowlisted_commands(ssh_server):
    with SSHCollector(ssh_server["target"], port=ssh_server["port"],
                      key_file=ssh_server["key"], known_hosts=ssh_server["known_hosts"],
                      allow_agent=False) as c:
        with pytest.raises(KeyError):
            c.run("evil; rm -rf /")
        assert c.run("uname").ok
