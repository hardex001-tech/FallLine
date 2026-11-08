"""Nmap adapter.

Runs a service-detection scan (-sV) only. No NSE scripts, no exploitation.
The command is built as a list and run without a shell, so a target string
can never inject extra commands. The target is validated by the scope
guard before this module is called.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

from .base import Finding, PortProbe


class NmapError(Exception):
    """Raised when Nmap is missing or fails."""


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def build_command(target: str, top_ports: int = 1000) -> list[str]:
    return [
        "nmap",
        "-sV",  # service/version detection
        "--top-ports",
        str(top_ports),
        "-T3",  # normal timing, not aggressive
        "--open",  # only report open ports
        "-oX",
        "-",  # XML to stdout
        target,
    ]


def parse_nmap_xml(xml_text: str) -> list[Finding]:
    """Turn Nmap XML output into Finding objects."""
    findings: list[Finding] = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr", "")
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            findings.append(
                Finding(
                    host=ip,
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    state="open",
                    service=svc.get("name", "") if svc is not None else "",
                    product=svc.get("product", "") if svc is not None else "",
                    version=svc.get("version", "") if svc is not None else "",
                )
            )
    return findings


def scan(target: str, top_ports: int = 1000, timeout: int = 900) -> list[Finding]:
    if not nmap_available():
        raise NmapError("nmap was not found on PATH")
    try:
        result = subprocess.run(
            build_command(target, top_ports),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise NmapError(f"nmap timed out after {timeout}s")
    if result.returncode != 0:
        raise NmapError(f"nmap failed: {result.stderr.strip()}")
    return parse_nmap_xml(result.stdout)


def build_probe_command(host: str, port: int, protocol: str = "tcp") -> list[str]:
    """Command that re-checks exactly one port (used to verify a fix)."""
    return [
        "nmap",
        "-sU" if protocol == "udp" else "-sV",
        "-Pn",  # do not skip the host if ping is blocked
        "-p",
        str(int(port)),
        "--reason",
        "-T3",
        "-oX",
        "-",
        host,
    ]


def parse_port_probe(xml_text: str, port: int) -> PortProbe:
    """Interpret Nmap XML for a single-port probe.

    Only an explicit 'closed' answer (or a firewall that actively rejects)
    counts as closed/filtered-with-proof. A silent timeout is 'unknown'.
    """
    root = ET.fromstring(xml_text)
    findings = parse_nmap_xml(xml_text)
    for f in findings:
        if f.port == port:
            return PortProbe("open", "open", findings)
    for p in root.findall("host/ports/port"):
        if int(p.get("portid", "0")) != port:
            continue
        state = p.find("state")
        if state is None:
            break
        st = state.get("state", "")
        reason = state.get("reason", "")
        if st == "closed":
            return PortProbe("closed", reason)
        if st == "filtered":
            if reason in ("admin-prohibited", "host-prohibited", "net-prohibited", "reset"):
                return PortProbe("filtered", reason)
            return PortProbe("unknown", f"filtered ({reason or 'no response'}): inconclusive")
    # No <port> element at all: nmap collapsed it into <extraports> or host is down
    for extra in root.findall("host/ports/extraports"):
        if extra.get("state") == "closed":
            return PortProbe("closed", "closed (extraports)")
    return PortProbe("unknown", "no usable answer from host")


def probe_port(host: str, port: int, protocol: str = "tcp", timeout: int = 120) -> PortProbe:
    if not nmap_available():
        return PortProbe("unknown", "nmap not found")
    try:
        result = subprocess.run(
            build_probe_command(host, port, protocol),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return PortProbe("unknown", "nmap timed out")
    if result.returncode != 0:
        return PortProbe("unknown", f"nmap failed: {result.stderr.strip()[:200]}")
    try:
        return parse_port_probe(result.stdout, port)
    except ET.ParseError:
        return PortProbe("unknown", "could not parse nmap output")


def build_discover_command(target: str) -> list[str]:
    """Fast, safe TCP host discovery command (--top-ports 25, no scripts)."""
    return [
        "nmap",
        "-sT",
        "--top-ports",
        "25",
        "-T4",
        "--open",
        "-oX",
        "-",
        target,
    ]


def parse_nmap_hosts(xml_text: str) -> list[dict]:
    """Extract live hosts, hostnames, open ports, and service names from Nmap XML."""
    root = ET.fromstring(xml_text)
    hosts: list[dict] = []
    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") not in (None, "up"):
            continue
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr", "")
        if not ip:
            continue
        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name", "") if hn_el is not None else ""
        open_ports: list[int] = []
        services: list[str] = []
        for port in host.findall("ports/port"):
            pstate = port.find("state")
            if pstate is None or pstate.get("state") != "open":
                continue
            pnum = int(port.get("portid", "0"))
            open_ports.append(pnum)
            svc = port.find("service")
            sname = svc.get("name", "") if svc is not None else ""
            if sname and sname not in services:
                services.append(sname)
        if open_ports or (st is not None and st.get("state") == "up"):
            hosts.append(
                {
                    "host": ip,
                    "hostname": hostname,
                    "status": "up",
                    "open_ports": open_ports,
                    "services": services,
                }
            )
    return hosts


def discover_hosts(target: str, timeout: int = 180) -> list[dict]:
    if not nmap_available():
        raise NmapError("nmap was not found on PATH")
    try:
        result = subprocess.run(
            build_discover_command(target),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapError(f"nmap host discovery timed out after {timeout}s") from exc
    if result.returncode != 0:
        raise NmapError(f"nmap host discovery failed: {result.stderr.strip()}")
    return parse_nmap_hosts(result.stdout)
