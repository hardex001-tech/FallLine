"""Fake network used by tests and by `fallline demo`. Never touches a real system.

The sample data resembles a typical intentionally-vulnerable lab (Metasploitable
2 plus an OWASP-style web VM) so the dashboard can be shown without a lab.
"""
from __future__ import annotations

import ipaddress

from .pipeline import Toolkit
from .scanners.base import Finding, PortProbe


def sample_lab() -> list[Finding]:
    def s(host, port, service, product="", version="", **kw):
        return Finding(host, port, "tcp", "open", service=service, product=product,
                       version=version, **kw)
    m = "192.168.56.101"
    w = "192.168.56.102"
    return [
        s(m, 21, "ftp", "vsftpd", "2.3.4"), s(m, 22, "ssh", "OpenSSH", "4.7p1 Debian"),
        s(m, 23, "telnet", "Linux telnetd"), s(m, 25, "smtp", "Postfix smtpd"),
        s(m, 80, "http", "Apache httpd", "2.2.8"), s(m, 139, "netbios-ssn", "Samba smbd", "3.X - 4.X"),
        s(m, 445, "netbios-ssn", "Samba smbd", "3.0.20"),
        s(m, 512, "exec", "netkit-rsh rexecd"), s(m, 513, "login"), s(m, 514, "shell", "Netkit rshd"),
        s(m, 1099, "java-rmi", "GNU Classpath grmiregistry"), s(m, 1524, "bindshell"),
        s(m, 2049, "nfs"), s(m, 3306, "mysql", "MySQL", "5.0.51a"),
        s(m, 5432, "postgresql", "PostgreSQL DB", "8.3.0"), s(m, 5900, "vnc", "VNC"),
        s(m, 6667, "irc", "UnrealIRCd", "3.2.8.1"), s(m, 8009, "ajp13", "Apache Jserv"),
        s(m, 8180, "http", "Apache Tomcat/Coyote JSP engine", "1.1"),
        s(w, 80, "http", "Apache httpd", "2.2.14"), s(w, 22, "ssh", "OpenSSH", "5.3"),
        s(w, 3306, "mysql", "MySQL", "5.1.41"),
        Finding(w, 80, "tcp", "open", service="http", check="web-admin-panel",
                title="phpMyAdmin", severity="high", source="httpx",
                evidence="admin-like page at http://192.168.56.102:80/phpmyadmin"),
    ]


_DEMO_HOSTNAMES = {
    "192.168.56.101": "metasploitable-lab",
    "192.168.56.102": "owasp-web-vm",
}


class FakeToolkit(Toolkit):
    name = "fake"

    def __init__(self, findings: list[Finding] | None = None):
        self.findings = list(findings if findings is not None else sample_lab())
        self.down_hosts: set[str] = set()
        self.silent_ports: set[tuple[str, int]] = set()   # firewall DROP: no answer
        self.calls: list[tuple] = []
        self.aws: list[Finding] = []

    # -- helpers for tests / demo -------------------------------------------
    def close_port(self, host: str, port: int) -> None:
        self.findings = [f for f in self.findings if not (f.host == host and f.port == port)]

    def replace(self, old: Finding, new: Finding) -> None:
        self.findings = [new if f is old else f for f in self.findings]

    # -- Toolkit API -------------------------------------------------------------
    def discover(self, net, top_ports):
        self.calls.append(("discover", str(net)))
        return "fake", [f for f in self.findings
                        if f.source != "httpx" and f.source != "nuclei"
                        and ipaddress.ip_address(f.host) in net and f.host not in self.down_hosts]

    def discover_hosts(self, net):
        self.calls.append(("discover_hosts", str(net)))
        by_host: dict[str, dict] = {}
        for f in self.findings:
            if f.source in ("httpx", "nuclei", "aws") or f.host in self.down_hosts:
                continue
            try:
                if ipaddress.ip_address(f.host) not in net:
                    continue
            except ValueError:
                continue
            entry = by_host.setdefault(
                f.host,
                {
                    "host": f.host,
                    "hostname": _DEMO_HOSTNAMES.get(f.host, ""),
                    "status": "up",
                    "open_ports": [],
                    "services": [],
                },
            )
            if f.port and f.port not in entry["open_ports"]:
                entry["open_ports"].append(f.port)
            if f.service and f.service not in entry["services"]:
                entry["services"].append(f.service)
        hosts = list(by_host.values())
        for h in hosts:
            h["open_ports"].sort()
        hosts.sort(key=lambda h: ipaddress.ip_address(h["host"]))
        return "fake", hosts

    def web_checks(self, findings):
        hosts = {f.host for f in findings}
        return [f for f in self.findings if f.source in ("httpx", "nuclei") and f.host in hosts], []

    def reprobe(self, finding):
        self.calls.append(("reprobe", finding.host, finding.port, finding.check))
        if finding.host in self.down_hosts or (finding.host, finding.port) in self.silent_ports:
            return PortProbe("unknown", "no response from host")
        here = [f for f in self.findings if f.host == finding.host and f.port == finding.port]
        if not here:
            return PortProbe("closed", "conn-refused")
        return PortProbe("open", "syn-ack", here)

    def aws_audit(self):
        return list(self.aws), []

