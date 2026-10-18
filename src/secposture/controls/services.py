"""Installed-package and running-service hygiene controls."""

from __future__ import annotations

from ..collectors.base import HostFacts
from ..models import Category, Severity
from . import CheckContext, CheckOutcome, control, fail, manual, ok, q

REF = ("CIS Distribution Independent Linux 2.1/2.2",)

# Packages whose mere presence is a hardening finding (insecure daemons /
# clients that should be replaced by modern equivalents).
INSECURE_PACKAGES = {
    "telnetd": "telnet server (cleartext)", "telnet-server": "telnet server (cleartext)",
    "inetutils-telnetd": "telnet server (cleartext)",
    "rsh-server": "rsh/rlogin server (cleartext, trust-based)",
    "rsh-redone-server": "rsh server (cleartext)",
    "nis": "NIS (insecure directory service)", "ypserv": "NIS server",
    "tftpd": "TFTP server (no authentication)", "tftpd-hpa": "TFTP server",
    "xinetd": "legacy super-server", "vsftpd": "FTP server (prefer SFTP)",
    "proftpd": "FTP server (prefer SFTP)", "pure-ftpd": "FTP server (prefer SFTP)",
    "rpcbind": "RPC portmapper (broad attack surface if unused)",
    "finger": "finger (information disclosure)",
}
# Running services worth a human glance even when legitimate.
NOTABLE_SERVICES = ("cups", "avahi-daemon", "rpcbind", "nfs-server", "smbd", "vsftpd",
                    "apache2", "nginx", "mysql", "mariadb", "postgresql", "docker", "redis")


@control("SVC-01", "No insecure service packages are installed", Category.SERVICES,
         Severity.HIGH, "Legacy cleartext daemons (telnet, rsh, TFTP, NIS, FTP) have no "
         "place on a hardened host even if not currently running - they can be started.",
         "Remove the package: 'sudo apt purge <pkg>' / 'sudo dnf remove <pkg>'.",
         references=REF)
def insecure_packages(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    installed = {name for name, _ in facts.packages}
    hits = {name: reason for name, reason in INSECURE_PACKAGES.items() if name in installed}
    if not hits:
        return ok("no insecure service packages installed")
    return fail(f"insecure package(s) installed: {', '.join(sorted(hits))}", packages=hits,
                fix=[f"sudo apt-get purge -y {q(name)}" for name in sorted(hits)])


@control("SVC-02", "Running services are reviewed", Category.SERVICES, Severity.INFO,
         "Every running service is attack surface. Notable network daemons should be known "
         "and justified for this host's role.",
         "Disable services not required for this host's function: "
         "'sudo systemctl disable --now <service>'.", references=REF)
def running_services(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    if not facts.services:
        return ok("no running services reported (or systemd not in use)")
    notable = sorted({s for s in facts.services
                      if any(s == n or s.startswith(n) for n in NOTABLE_SERVICES)})
    return manual(f"{len(facts.services)} running service(s)"
                  + (f"; notable: {', '.join(notable)}" if notable else ""),
                  notable=notable, total=len(facts.services))
