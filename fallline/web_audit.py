"""Web Application and Cloud Exposure Auditor.

Audits authorized web servers and APIs for high-severity information disclosures
(exposed .env secrets, git repositories) and missing critical HTTP security headers.

Scope-guarded to prevent unauthorized scanning.
Maps findings to MITRE ATT&CK:
- T1190: Exploit Public-Facing Application
- T1552.001: Credentials in Files
"""

from __future__ import annotations

import http.client
from dataclasses import dataclass, field
from typing import Any

from fallline.scope import Scope, ScopeError


@dataclass
class WebExposureFinding:
    check_type: str  # "SENSITIVE_FILE" | "SECURITY_HEADER" | "CORS"
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    title: str
    target: str
    description: str
    evidence: str
    remediation: str
    mitre_tactic: str


@dataclass
class WebAuditResult:
    target: str
    port: int
    findings: list[WebExposureFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "port": self.port,
            "findings": [
                {
                    "check_type": f.check_type,
                    "severity": f.severity,
                    "title": f.title,
                    "target": f.target,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "mitre_tactic": f.mitre_tactic,
                }
                for f in self.findings
            ],
        }


# High-value exposure probes
SENSITIVE_PATHS = [
    (
        "/.env",
        "CRITICAL",
        "Exposed .env Configuration File",
        "Contains environment variables, API secrets, and database credentials.",
        "T1552.001",
    ),
    (
        "/.git/HEAD",
        "CRITICAL",
        "Exposed .git Source Code Repository",
        "Allows complete source code extraction via git object dumping.",
        "T1190",
    ),
    (
        "/config.json",
        "HIGH",
        "Exposed JSON Application Configuration",
        "Publicly exposes internal service endpoints and structural metadata.",
        "T1552.001",
    ),
    (
        "/wp-config.php.bak",
        "CRITICAL",
        "Exposed Database Configuration Backup",
        "Exposes cleartext MySQL database passwords.",
        "T1552.001",
    ),
]

# Required enterprise defense headers
SECURITY_HEADERS = [
    (
        "Strict-Transport-Security",
        "MEDIUM",
        "Missing HSTS Header",
        "Allows man-in-the-middle SSL stripping attacks.",
        "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;",
    ),
    (
        "Content-Security-Policy",
        "MEDIUM",
        "Missing Content-Security-Policy (CSP)",
        "Lacks protection against cross-site scripting (XSS) and data injection.",
        "add_header Content-Security-Policy \"default-src 'self';\" always;",
    ),
    (
        "X-Frame-Options",
        "LOW",
        "Missing X-Frame-Options Header",
        "Vulnerable to UI redressing and clickjacking attacks.",
        "add_header X-Frame-Options 'DENY' always;",
    ),
    (
        "X-Content-Type-Options",
        "LOW",
        "Missing X-Content-Type-Options Header",
        "Allows MIME-type sniffing bypasses.",
        "add_header X-Content-Type-Options 'nosniff' always;",
    ),
]


def audit_web_exposure(
    host: str,
    port: int = 80,
    use_ssl: bool = False,
    timeout: float = 2.5,
    scope: Scope | None = None,
    mock_responses: dict[str, tuple[int, dict[str, str], str]] | None = None,
) -> WebAuditResult:
    """Audit an authorized target for sensitive files and HTTP security headers."""
    import ipaddress

    if scope is not None:
        scope.check(host)
    else:
        try:
            ip = ipaddress.ip_address(host)
            if not (ip.is_private or ip.is_loopback):
                raise ScopeError(f"Target '{host}' is a public IP. Scans require verified scope authorization.")
        except ValueError:
            if host not in ("localhost", "127.0.0.1", "::1"):
                raise ScopeError(f"Target '{host}' requires verified scope authorization.")

    result = WebAuditResult(target=host, port=port)

    # 1. Check Root Endpoint for Security Headers
    conn = None
    try:
        if mock_responses and "/" in mock_responses:
            status, headers, body = mock_responses["/"]
        else:
            conn_cls = http.client.HTTPSConnection if use_ssl else http.client.HTTPConnection
            conn = conn_cls(host, port, timeout=timeout)
            conn.request("GET", "/")
            res = conn.getresponse()
            status = res.status
            headers = {k.title(): v for k, v in res.getheaders()}
            body = ""

        # Audit Security Headers
        for header_name, severity, title, desc, remediate in SECURITY_HEADERS:
            matching = [v for k, v in headers.items() if k.lower() == header_name.lower()]
            if not matching:
                result.findings.append(
                    WebExposureFinding(
                        check_type="SECURITY_HEADER",
                        severity=severity,
                        title=title,
                        target=f"{host}:{port}/",
                        description=desc,
                        evidence=f"Header '{header_name}' was not returned in HTTP {status} response.",
                        remediation=remediate,
                        mitre_tactic="T1190",
                    )
                )

        # Audit CORS Wildcard
        cors_origin = headers.get("Access-Control-Allow-Origin")
        cors_creds = headers.get("Access-Control-Allow-Credentials")
        if cors_origin == "*" and cors_creds == "true":
            result.findings.append(
                WebExposureFinding(
                    check_type="CORS",
                    severity="HIGH",
                    title="Dangerous CORS Wildcard with Credentials",
                    target=f"{host}:{port}/",
                    description="Access-Control-Allow-Origin is set to '*' while Allow-Credentials is true, allowing malicious cross-origin data theft.",
                    evidence="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                    remediation="Specify trusted origins explicitly instead of using '*'.",
                    mitre_tactic="T1190",
                )
            )

    except Exception:
        # Host may not have active web server on this port
        pass
    finally:
        if conn:
            conn.close()

    # 2. Check Sensitive Exposure Paths
    for path, severity, title, desc, mitre in SENSITIVE_PATHS:
        conn = None
        try:
            if mock_responses and path in mock_responses:
                status, headers, body = mock_responses[path]
            else:
                conn_cls = http.client.HTTPSConnection if use_ssl else http.client.HTTPConnection
                conn = conn_cls(host, port, timeout=timeout)
                conn.request("GET", path)
                res = conn.getresponse()
                status = res.status
                body = res.read(512).decode("utf-8", errors="replace")

            if status == 200:
                # Validate it's not a generic 404 SPA fallback page
                is_valid = False
                if path == "/.env" and ("=" in body or "KEY" in body or "SECRET" in body or "DB_" in body):
                    is_valid = True
                elif path == "/.git/HEAD" and ("ref:" in body or "refs/heads" in body):
                    is_valid = True
                elif path == "/config.json" and ("{" in body and "}" in body):
                    is_valid = True
                elif path == "/wp-config.php.bak" and ("DB_NAME" in body or "<?php" in body):
                    is_valid = True

                if is_valid:
                    result.findings.append(
                        WebExposureFinding(
                            check_type="SENSITIVE_FILE",
                            severity=severity,
                            title=title,
                            target=f"{host}:{port}{path}",
                            description=desc,
                            evidence=f"HTTP 200 OK returned on {path}. Preview: {body[:80]}...",
                            remediation=f"Block public web server access to '{path}' in server config immediately.",
                            mitre_tactic=mitre,
                        )
                    )
        except Exception:
            pass
        finally:
            if conn:
                conn.close()

    return result
