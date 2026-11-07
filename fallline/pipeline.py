"""Scan pipeline: scope check -> discovery -> web profiling -> Nuclei -> store.

All real tools sit behind a `Toolkit`. Tests plug in a fake Toolkit so they
never touch a real network.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network

from . import aws_audit
from .knowledge import KnowledgeBase
from .scanners import (
    httpx_scanner,
    naabu_scanner,
    nmap_scanner,
    nuclei_scanner,
    socket_fallback,
)
from .scanners.base import Finding, PortProbe
from .scope import Scope
from .store import Store


class Toolkit:
    """Interface. Subclass and override for tests or new scanners."""

    name = "base"

    def discover(self, net: IPv4Network | IPv6Network, top_ports: int) -> tuple[str, list[Finding]]:
        raise NotImplementedError

    def discover_hosts(self, net: IPv4Network | IPv6Network) -> tuple[str, list[dict]]:
        raise NotImplementedError

    def web_checks(self, findings: list[Finding]) -> tuple[list[Finding], list[str]]:
        """Return (extra findings from httpx/Nuclei, warnings)."""
        return [], []

    def reprobe(self, finding: Finding) -> PortProbe:
        raise NotImplementedError

    def aws_audit(self) -> tuple[list[Finding], list[str]]:
        raise NotImplementedError


@dataclass
class RealToolkit(Toolkit):
    name = "real"
    aws_profile: str | None = None
    aws_region: str | None = None
    warnings: list[str] = field(default_factory=list)

    def discover(self, net, top_ports):
        if nmap_scanner.nmap_available():
            return "nmap", nmap_scanner.scan(str(net), top_ports=top_ports)
        if naabu_scanner.naabu_available():
            return "naabu", naabu_scanner.scan(str(net), top_ports=top_ports)
        if net.num_addresses != 1:
            raise RuntimeError("Nmap/Naabu not found; the fallback scanner only supports single hosts.")
        return "socket-fallback", socket_fallback.scan(str(net.network_address))

    def discover_hosts(self, net):
        if nmap_scanner.nmap_available():
            return "nmap", nmap_scanner.discover_hosts(str(net))
        return "socket-fallback", socket_fallback.discover_hosts(net)

    def web_checks(self, findings):
        extra, warnings = httpx_scanner.profile(findings)
        if not nuclei_scanner.nuclei_available():
            warnings.append("nuclei not installed: safe web checks skipped")
            return extra, warnings
        for f in [x for x in findings if httpx_scanner.is_web(x)]:
            try:
                extra += nuclei_scanner.scan_url(httpx_scanner.url_for(f), f.host, f.port)
            except (OSError, ValueError, RuntimeError) as exc:
                warnings.append(f"nuclei failed on {f.host}:{f.port}: {exc.__class__.__name__}")
        return extra, warnings

    def reprobe(self, finding):
        if nmap_scanner.nmap_available():
            probe = nmap_scanner.probe_port(finding.host, finding.port, finding.protocol)
        elif finding.protocol == "tcp":
            probe = socket_fallback.probe_port(finding.host, finding.port)
        else:
            return PortProbe("unknown", "UDP re-check needs nmap")
        if probe.state != "open" or finding.source not in ("httpx", "nuclei"):
            return probe
        # Web-level finding: re-run only that check against the still-open port
        if finding.source == "nuclei":
            if not nuclei_scanner.nuclei_available():
                return PortProbe("unknown", "nuclei not installed: cannot re-check")
            try:
                probe.findings += nuclei_scanner.scan_url(
                    httpx_scanner.url_for(finding), finding.host, finding.port,
                    template_id=finding.check)
            except (OSError, ValueError, RuntimeError) as exc:
                return PortProbe("unknown", f"nuclei re-check failed: {exc.__class__.__name__}")
        else:
            if httpx_scanner.find_binary() is None:
                return PortProbe("unknown", "httpx not installed: cannot re-check")
            base = next((f for f in probe.findings if f.port == finding.port), None)
            if base is None:
                return PortProbe("unknown", "no open port details for httpx re-check")
            if not base.service:
                base.service = finding.service or "http"
            new, warnings = httpx_scanner.profile([base])
            if warnings or not base.evidence:
                return PortProbe("unknown", warnings[0] if warnings else "httpx returned no HTTP response")
            probe.findings += new
        return probe

    def aws_audit(self):
        clients = aws_audit.boto_clients(self.aws_profile, self.aws_region)
        return aws_audit.run_audit(clients, region=self.aws_region or "region")


def run_scan(scope: Scope, store: Store, kb: KnowledgeBase, toolkit: Toolkit, target: str,
             user: str | None = None, top_ports: int = 1000, web: bool = True) -> dict:
    """Scope-checked scan; raises ScopeError when the target is not authorized."""
    net = scope.check(target, user=user)
    engine, findings = toolkit.discover(net, top_ports)
    warnings: list[str] = []
    if web:
        extra, warnings = toolkit.web_checks(findings)
        findings = findings + extra
    counts = store.ingest(findings, kb, target=str(net), engine=engine)
    return {"target": str(net), "engine": engine, "found": len(findings),
            "warnings": warnings, **counts}


def run_host_discovery(scope: Scope, toolkit: Toolkit, target: str, user: str | None = None) -> dict:
    """Scope-checked live subnet host discovery; raises ScopeError when target is not authorized."""
    net = scope.check(target, user=user)
    engine, hosts = toolkit.discover_hosts(net)
    return {"target": str(net), "engine": engine, "count": len(hosts), "hosts": hosts}

