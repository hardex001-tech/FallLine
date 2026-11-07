"""Nuclei adapter, SAFE templates only.

Only exposure/misconfiguration templates are selected, and every intrusive
category (exploits, brute force, fuzzing, DoS, default-login, injection...) is
excluded both on the command line and again when results are parsed.
Out-of-band (interactsh) callbacks are disabled. Skipped gracefully if Nuclei
is not installed.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from urllib.parse import urlparse

from .base import Finding

SAFE_TAGS = ("exposure", "misconfig")
FORBIDDEN_TAGS = ("intrusive", "dos", "fuzz", "bruteforce", "brute-force", "default-login",
                  "rce", "exploit", "sqli", "xss", "lfi", "ssrf", "injection", "oob",
                  "kev", "dast", "takeover")
_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def build_command(url: str, template_id: str | None = None) -> list[str]:
    cmd = ["nuclei", "-u", url, "-jsonl", "-silent", "-duc", "-ni",
           "-rl", "10", "-c", "10", "-timeout", "5", "-retries", "1",
           "-exclude-tags", ",".join(FORBIDDEN_TAGS)]
    if template_id:
        if not _ID_RE.match(template_id):
            raise ValueError("invalid template id")
        cmd += ["-id", template_id]
    else:
        cmd += ["-tags", ",".join(SAFE_TAGS)]
    return cmd


def parse_output(text: str, host: str, port: int) -> list[Finding]:
    out: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        info = row.get("info", {}) or {}
        tags = info.get("tags", []) or []
        if isinstance(tags, str):
            tags = tags.split(",")
        if {t.strip().lower() for t in tags} & set(FORBIDDEN_TAGS):
            continue  # defence in depth: never record intrusive-category results
        cve = (info.get("classification", {}) or {}).get("cve-id") or []
        if isinstance(cve, str):
            cve = [cve]
        matched = str(row.get("matched-at", ""))
        if matched:
            parsed = urlparse(matched if "://" in matched else f"http://{matched}")
            matched = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        out.append(Finding(host, port, "tcp", "open", service="http",
                           check=str(row.get("template-id", "")), title=str(info.get("name", ""))[:150],
                           severity=str(info.get("severity", "")).lower(),
                           cves=[c.upper() for c in cve], source="nuclei",
                           evidence=f"matched at {matched}"[:200]))
    return out


def scan_url(url: str, host: str, port: int, template_id: str | None = None,
             timeout: int = 300) -> list[Finding]:
    if not nuclei_available():
        raise FileNotFoundError("nuclei not installed")
    try:
        res = subprocess.run(build_command(url, template_id), capture_output=True, text=True,
                             timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"nuclei timed out after {timeout}s") from exc
    if res.returncode != 0:
        raise RuntimeError(f"nuclei failed: {res.stderr.strip()[:200]}")
    return parse_output(res.stdout, host, port)
