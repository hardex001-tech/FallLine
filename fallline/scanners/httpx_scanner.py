"""httpx adapter (ProjectDiscovery's httpx, not the Python library).

Profiles web services: status, title, technology and security headers.
Adds findings for admin panels and missing browser security headers.
Skipped gracefully when the tool is not installed.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess

from .base import Finding

WEB_PORTS = {80, 443, 8000, 8008, 8080, 8180, 8443, 8888}
ADMIN_RE = re.compile(r"admin|phpmyadmin|tomcat manager|manager|console|webmin|jenkins|grafana|kibana",
                      re.IGNORECASE)
REQUIRED_HEADERS = ("x-frame-options", "content-security-policy", "x-content-type-options")
_binary_cache: dict[str, str | None] = {}


def find_binary() -> str | None:
    """Locate ProjectDiscovery httpx. Kali ships it as 'httpx-toolkit'; the
    Python httpx package also installs a command called 'httpx', so we check
    the version banner to avoid running the wrong program."""
    for name in ("httpx-toolkit", "httpx"):
        path = shutil.which(name)
        if not path:
            continue
        if path in _binary_cache:
            if _binary_cache[path]:
                return path
            continue
        try:
            out = subprocess.run([path, "-version"], capture_output=True, text=True,
                                 timeout=15, check=False)
            banner = (out.stdout + out.stderr).lower()
        except (OSError, subprocess.TimeoutExpired):
            banner = ""
        ok = "projectdiscovery" in banner or "current version" in banner
        _binary_cache[path] = path if ok else None
        if ok:
            return path
    return None


def is_web(f: Finding) -> bool:
    return f.state == "open" and (f.port in WEB_PORTS or "http" in (f.service or "").lower())


def url_for(f: Finding) -> str:
    tls = f.port in (443, 8443) or "ssl" in (f.service or "").lower() or f.service == "https"
    return f"{'https' if tls else 'http'}://{f.host}:{f.port}"


def build_command(binary: str, url: str) -> list[str]:
    return [binary, "-silent", "-json", "-status-code", "-title", "-tech-detect",
            "-include-response-header", "-timeout", "5", "-no-color", "-u", url]


def parse_output(text: str, original: Finding) -> list[Finding]:
    """Enrich `original` in place and return any new findings."""
    new: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        title = str(row.get("title", "") or "")
        tech = ", ".join(row.get("tech", []) or row.get("technologies", []) or [])
        original.evidence = (f"HTTP {row.get('status_code', row.get('status-code', '?'))}; "
                             f"title={title[:80]!r}; tech={tech[:120]}")
        original.title = original.title or title[:120]
        url = str(row.get("url", ""))
        if ADMIN_RE.search(title) or re.search(r"/(admin|manager|phpmyadmin|console)\b", url, re.IGNORECASE):
            new.append(Finding(original.host, original.port, "tcp", "open", service="http",
                               check="web-admin-panel", title=title[:120] or url,
                               severity="high", source="httpx",
                               evidence=f"admin-like page at {url}"))
        headers = {str(k).lower().replace("_", "-"): v
                   for k, v in (row.get("header") or row.get("headers") or {}).items()}
        if headers:
            missing = [h for h in REQUIRED_HEADERS if h not in headers]
            if len(missing) >= 2:
                new.append(Finding(original.host, original.port, "tcp", "open", service="http",
                                   check="web-missing-headers", title="Missing security headers",
                                   severity="low", source="httpx",
                                   evidence="missing: " + ", ".join(missing)))
    return new


def profile(findings: list[Finding], timeout: int = 60) -> tuple[list[Finding], list[str]]:
    """Run httpx on each web finding. Returns (new findings, warnings)."""
    binary = find_binary()
    if binary is None:
        return [], ["httpx (ProjectDiscovery) not installed: web profiling skipped"]
    new: list[Finding] = []
    warnings: list[str] = []
    for f in [x for x in findings if is_web(x)]:
        try:
            res = subprocess.run(build_command(binary, url_for(f)), capture_output=True,
                                 text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            warnings.append(f"httpx timed out on {url_for(f)}")
            continue
        if res.returncode != 0:
            warnings.append(f"httpx failed on {url_for(f)}")
            continue
        new.extend(parse_output(res.stdout, f))
    return new, warnings
