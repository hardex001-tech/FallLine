"""Pure-Python TCP connect scanner, used when Nmap is not installed.

Only checks a short list of commonly exposed ports on single hosts. It does
not identify service versions.
"""

from __future__ import annotations

import errno
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from .base import Finding, PortProbe

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    1433: "ms-sql",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    8080: "http-proxy",
}

DISCOVERY_PORTS = {
    21: "ftp",
    22: "ssh",
    80: "http",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "ms-wbt-server",
    8080: "http-proxy",
}


def scan(host: str, ports: dict[int, str] | None = None, timeout: float = 0.5) -> list[Finding]:
    ports = ports or COMMON_PORTS
    findings: list[Finding] = []
    for port, name in ports.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) == 0:
                findings.append(Finding(host, port, "tcp", "open", service=name, source="socket"))
    return findings


def probe_port(host: str, port: int, timeout: float = 1.0) -> PortProbe:
    """Single-port TCP re-check. Only a refused connection counts as closed."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        code = sock.connect_ex((host, port))
    if code == 0:
        return PortProbe(
            "open",
            "connected",
            [Finding(host, port, "tcp", "open", service=COMMON_PORTS.get(port, ""), source="socket")],
        )
    if code in (errno.ECONNREFUSED, 10061):  # 10061 = WSAECONNREFUSED
        return PortProbe("closed", "connection refused")
    return PortProbe("unknown", f"no answer (code {code}): inconclusive")


def discover_hosts(
    net: ipaddress.IPv4Network | ipaddress.IPv6Network,
    ports: dict[int, str] | None = None,
    timeout: float = 0.15,
) -> list[dict]:
    """Safe, non-intrusive TCP management/web port discovery across a subnet."""
    if net.num_addresses > 1024:
        raise ValueError("Subnet too large for socket host discovery (maximum /22 or 1024 addresses)")
    probe_ports = ports or DISCOVERY_PORTS
    hosts_to_check = [str(net.network_address)] if net.num_addresses == 1 else [str(ip) for ip in net.hosts()]

    def _check_host(ip_str: str) -> dict | None:
        open_ports: list[int] = []
        services: list[str] = []
        for port, svc in probe_ports.items():
            family = socket.AF_INET6 if ":" in ip_str else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip_str, port)) == 0:
                    open_ports.append(port)
                    services.append(svc)
        if not open_ports:
            return None
        return {
            "host": ip_str,
            "hostname": "",
            "status": "up",
            "open_ports": open_ports,
            "services": services,
        }

    discovered: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(32, max(1, len(hosts_to_check)))) as pool:
        for res in pool.map(_check_host, hosts_to_check):
            if res is not None:
                discovered.append(res)
    discovered.sort(key=lambda h: ipaddress.ip_address(h["host"]))
    return discovered
