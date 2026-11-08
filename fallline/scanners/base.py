"""Shared data types for scanners."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    """One exposed service (or one detected weakness) on a host."""

    host: str
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    # Extra fields filled in by later pipeline stages (all optional):
    check: str = ""  # e.g. a Nuclei template id or "web-admin-panel"
    title: str = ""  # human title from the tool (Nuclei name, web page title)
    severity: str = ""  # tool-reported severity (info/low/medium/high/critical)
    cves: list[str] = field(default_factory=list)
    source: str = "nmap"  # nmap | socket | httpx | nuclei | aws
    evidence: str = ""  # short, non-sensitive proof of detection

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PortProbe:
    """Result of re-checking ONE port, used by the verification loop.

    state is one of: open, closed, filtered, unknown.
    "unknown" means the check was inconclusive (host down, timeout, tool
    error). Unknown must never be treated as "fixed".
    """

    state: str
    reason: str = ""
    findings: list[Finding] = field(default_factory=list)
