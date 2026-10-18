"""Network exposure controls: firewall and listening services."""

from __future__ import annotations

from ..collectors.base import HostFacts
from ..models import Category, Severity
from . import CheckContext, CheckOutcome, control, fail, ok, warn

REF = ("CIS Distribution Independent Linux 4.2/3.5",)

# Cleartext / legacy services that should not be listening.
INSECURE_PORTS = {
    23: "telnet", 21: "ftp", 512: "rexec", 513: "rlogin", 514: "rsh",
    69: "tftp", 79: "finger", 111: "rpcbind", 2049: "nfs", 23231: "telnet-alt",
}
LOOPBACK = ("127.", "::1", "127.0.0.1")


def _is_public(address: str) -> bool:
    address = address.strip("[]")
    if address in ("0.0.0.0", "*", "::"):  # noqa: S104 - detecting a wildcard bind, not binding
        return True
    return not any(address.startswith(p) for p in LOOPBACK)


@control("NET-01", "A host firewall is active", Category.NETWORK, Severity.HIGH,
         "Without an active firewall, every listening service is reachable from any network "
         "the host is attached to.",
         "Enable a firewall (ufw/firewalld/nftables) with a default-deny inbound policy and "
         "allow only required ports.", references=REF)
def firewall_active(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    fw = facts.firewall
    if fw.get("active"):
        return ok(f"{fw.get('backend')} active")
    if fw.get("backend") in ("none", None):
        return fail("no active host firewall detected",
                    fix=["sudo ufw default deny incoming", "sudo ufw allow OpenSSH",
                         "sudo ufw enable"])
    return fail(f"{fw.get('backend')} present but not enforcing", backend=fw.get("backend"))


@control("NET-02", "No cleartext or legacy services are listening", Category.NETWORK,
         Severity.CRITICAL, "Services such as telnet, FTP, rsh and TFTP transmit credentials "
         "and data in the clear or have no meaningful authentication.",
         "Stop and remove the service; use SSH/SFTP/HTTPS equivalents instead.", references=REF)
def insecure_services(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    hits = []
    for sock in facts.listening:
        name = INSECURE_PORTS.get(sock["port"])
        if name and _is_public(sock["address"]):
            hits.append({"port": sock["port"], "service": name, "process": sock["process"]})
    if not hits:
        return ok("no cleartext/legacy services listening on a public interface")
    names = ", ".join(sorted({f"{h['service']}:{h['port']}" for h in hits}))
    return fail(f"insecure services listening: {names}", services=hits)


@control("NET-03", "Externally reachable listening ports are reviewed", Category.NETWORK,
         Severity.LOW, "Every service bound to a non-loopback address is remotely reachable "
         "and part of the attack surface; it should be known and intended.",
         "Confirm each externally bound port is required; bind the rest to localhost or close "
         "them, and list expected ports in allowed_listen_ports.", references=REF)
def exposed_ports(facts: HostFacts, ctx: CheckContext) -> CheckOutcome:
    public = sorted({sock["port"] for sock in facts.listening
                     if _is_public(sock["address"])})
    unexpected = [p for p in public if p not in ctx.allowed_listen_ports]
    if not public:
        return ok("no services bound to a public interface")
    if not unexpected:
        return ok(f"{len(public)} public port(s), all expected")
    detail = ", ".join(str(p) for p in unexpected)
    return warn(f"externally reachable port(s) to review: {detail}",
                ports=unexpected,
                processes=sorted({s["process"] for s in facts.listening
                                  if s["port"] in unexpected and s["process"]}))
