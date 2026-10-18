from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from secposture.controls import CheckContext, load_catalog
from secposture.models import HostInfo

load_catalog()
ROOT = Path(__file__).resolve().parents[1]
SAMPLE_ADVISORIES = str(ROOT / "src" / "secposture" / "data" / "advisories")


@pytest.fixture
def ctx() -> CheckContext:
    return CheckContext(profile="server", host=HostInfo(privileged=True))


def _tool(name: str) -> str | None:
    return shutil.which(name) or (f"/usr/sbin/{name}"
                                  if Path(f"/usr/sbin/{name}").exists() else None)


@pytest.fixture(scope="session")
def ssh_server(tmp_path_factory: pytest.TempPathFactory):
    """A throwaway sshd on localhost:random, key auth, for the SSH collector test."""
    sshd = _tool("sshd")
    keygen = shutil.which("ssh-keygen")
    keyscan = shutil.which("ssh-keyscan")
    if not (sshd and keygen and keyscan and os.geteuid() == 0):
        pytest.skip("sshd/ssh-keygen/ssh-keyscan or root required for SSH integration test")

    d = tmp_path_factory.mktemp("sshd")
    port = 2300 + (os.getpid() % 500)
    run = ["-q", "-t", "ed25519", "-N", ""]
    subprocess.run([keygen, *run, "-f", str(d / "host")], check=True, capture_output=True)
    subprocess.run([keygen, *run, "-f", str(d / "client")], check=True, capture_output=True)
    (d / "auth").mkdir()
    shutil.copy(d / "client.pub", d / "auth" / "authorized_keys")
    (d / "auth" / "authorized_keys").chmod(0o600)
    config = d / "sshd_config"
    config.write_text(
        f"Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/host\n"
        f"PidFile {d}/sshd.pid\nAuthorizedKeysFile {d}/auth/authorized_keys\n"
        "PasswordAuthentication no\nPermitRootLogin prohibit-password\nUsePAM no\n"
        "StrictModes no\nSubsystem sftp internal-sftp\nLogLevel ERROR\n")
    Path("/run/sshd").mkdir(parents=True, exist_ok=True)
    subprocess.run([sshd, "-f", str(config), "-E", str(d / "sshd.log")], check=True,
                   capture_output=True)
    time.sleep(1)
    known = d / "known_hosts"
    scan = subprocess.run([keyscan, "-p", str(port), "-t", "ed25519", "127.0.0.1"],
                          capture_output=True, text=True)
    known.write_text(scan.stdout)
    yield {"port": port, "key": str(d / "client"), "known_hosts": str(known),
           "target": "root@127.0.0.1"}
    pid_file = d / "sshd.pid"
    if pid_file.exists():
        with contextlib.suppress(ProcessLookupError, ValueError):
            os.kill(int(pid_file.read_text()), 15)
