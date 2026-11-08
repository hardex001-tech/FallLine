"""DAST (Dynamic Application Security Testing) Report Ingestion Engine.

Ingests industry-standard web vulnerability reports from OWASP ZAP (JSON)
and Burp Suite (XML), mapping web-tier vulnerabilities directly into the
FallLine attack graph as exploitable nodes.

Maps findings to MITRE ATT&CK:
- T1190: Exploit Public-Facing Application (SQL Injection, SSRF, RCE)
- T1059.007: Command and Scripting Interpreter: JavaScript (XSS)
- T1078: Valid Accounts: Broken Access Control
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .scanners.base import Finding


@dataclass
class DASTVulnerability:
    scanner: str  # "OWASP_ZAP" | "BURP_SUITE"
    title: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    host: str
    port: int
    url: str
    description: str
    solution: str
    mitre_tactic: str
    waf_rule: str

    def to_finding(self) -> Finding:
        return Finding(
            host=self.host,
            port=self.port,
            protocol="tcp",
            state="open",
            service="http" if self.port == 80 else ("https" if self.port == 443 else "http-alt"),
            product=self.scanner,
            version=self.title,
            title=f"{self.scanner}: {self.title}",
            evidence=f"URI: {self.url} | Severity: {self.severity}",
        )


@dataclass
class DASTIngestionResult:
    scanner: str
    target_hosts: list[str]
    total_findings: int
    vulnerabilities: list[DASTVulnerability] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "target_hosts": self.target_hosts,
            "total_findings": self.total_findings,
            "vulnerabilities": [
                {
                    "title": v.title,
                    "severity": v.severity,
                    "host": v.host,
                    "port": v.port,
                    "url": v.url,
                    "solution": v.solution,
                    "mitre_tactic": v.mitre_tactic,
                    "waf_rule": v.waf_rule,
                }
                for v in self.vulnerabilities
            ],
        }


def _map_mitre_and_waf(title: str) -> tuple[str, str]:
    """Map web vulnerability title to MITRE ATT&CK tactic and defensive WAF rule."""
    t_lower = title.lower()
    if "sql" in t_lower or "injection" in t_lower:
        return (
            "T1190",
            "# Cloudflare / ModSecurity CRS Rule: Block SQL Injection Patterns\n"
            'SecRule ARGS "(?i)(select.+from|union.+select|insert.+into|drop.+table)" '
            "\"id:1001,phase:2,deny,status:403,msg:'FallLine Choke Point: Blocked SQLi'\"",
        )
    elif "ssrf" in t_lower or "server-side request" in t_lower:
        return (
            "T1190",
            "# Block SSRF attempts targeting cloud metadata endpoints (169.254.169.254)\n"
            "iptables -A OUTPUT -m iprange --dst-range 169.254.169.254 -j DROP",
        )
    elif "cross site" in t_lower or "xss" in t_lower:
        return (
            "T1059.007",
            "# Enforce Content-Security-Policy (CSP) in Nginx\n"
            "add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;",
        )
    elif "access control" in t_lower or "traversal" in t_lower or "directory" in t_lower:
        return (
            "T1078",
            "# Nginx Path Traversal & Admin Access Restriction\n"
            "location ~* \\.(bak|old|env|git) { deny all; return 404; }",
        )
    else:
        return (
            "T1190",
            "# Generic Web Application Defense Header\n"
            "add_header X-Frame-Options 'DENY' always;\nadd_header X-Content-Type-Options 'nosniff' always;",
        )


def parse_burp_xml(xml_content: str) -> DASTIngestionResult:
    """Parse Burp Suite XML issue export."""
    root = ET.fromstring(xml_content)
    vulns: list[DASTVulnerability] = []
    hosts_seen: set[str] = set()

    for issue in root.findall(".//issue"):
        name = issue.findtext("name", "Unknown Web Vulnerability").strip()
        host_elem = issue.find("host")
        host_ip = host_elem.get("ip", "") if host_elem is not None else ""
        raw_url = issue.findtext("url", "") or (host_elem.text if host_elem is not None else "")

        parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
        host = host_ip or parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        hosts_seen.add(host)

        sev = (issue.findtext("severity", "Medium") or "Medium").upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev = "MEDIUM"

        desc = issue.findtext("issueBackground", "") or issue.findtext("issueDetail", "")
        solution = issue.findtext("remediationBackground", "") or "Apply strict input validation and least privilege."

        mitre, waf = _map_mitre_and_waf(name)

        vulns.append(
            DASTVulnerability(
                scanner="BURP_SUITE",
                title=name,
                severity=sev,
                host=host,
                port=port,
                url=raw_url,
                description=desc,
                solution=solution,
                mitre_tactic=mitre,
                waf_rule=waf,
            )
        )

    return DASTIngestionResult(
        scanner="BURP_SUITE",
        target_hosts=sorted(hosts_seen),
        total_findings=len(vulns),
        vulnerabilities=vulns,
    )


def parse_zap_json(json_content: str | dict[str, Any]) -> DASTIngestionResult:
    """Parse OWASP ZAP JSON alert report."""
    data = json.loads(json_content) if isinstance(json_content, str) else json_content
    vulns: list[DASTVulnerability] = []
    hosts_seen: set[str] = set()

    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        site_host = site.get("@host", "")
        site_port = int(site.get("@port", 80))
        if site_host:
            hosts_seen.add(site_host)

        alerts = site.get("alerts", [])
        if isinstance(alerts, dict):
            alerts = [alerts]

        for alert in alerts:
            name = alert.get("name", alert.get("alert", "Web Vulnerability"))
            risk_desc = alert.get("riskdesc", "Medium")
            sev = "MEDIUM"
            if "High" in risk_desc:
                sev = "HIGH"
            elif "Critical" in risk_desc:
                sev = "CRITICAL"
            elif "Low" in risk_desc:
                sev = "LOW"

            uri = alert.get("uri", f"http://{site_host}:{site_port}")
            parsed = urlparse(uri)
            host = site_host or parsed.hostname or "127.0.0.1"
            port = site_port or parsed.port or (443 if parsed.scheme == "https" else 80)
            hosts_seen.add(host)

            desc = alert.get("desc", "")
            solution = alert.get("solution", "Harden web application parameters.")
            mitre, waf = _map_mitre_and_waf(name)

            vulns.append(
                DASTVulnerability(
                    scanner="OWASP_ZAP",
                    title=name,
                    severity=sev,
                    host=host,
                    port=port,
                    url=uri,
                    description=desc,
                    solution=solution,
                    mitre_tactic=mitre,
                    waf_rule=waf,
                )
            )

    return DASTIngestionResult(
        scanner="OWASP_ZAP",
        target_hosts=sorted(hosts_seen),
        total_findings=len(vulns),
        vulnerabilities=vulns,
    )


def ingest_dast_report(path_or_content: str | Path) -> DASTIngestionResult:
    """Auto-detect format (ZAP JSON or Burp XML) and parse findings."""
    raw = ""
    if isinstance(path_or_content, (str, Path)) and Path(path_or_content).exists():
        raw = Path(path_or_content).read_text(encoding="utf-8")
    else:
        raw = str(path_or_content).strip()

    if raw.startswith("<") or "<issues" in raw:
        return parse_burp_xml(raw)
    else:
        return parse_zap_json(raw)
