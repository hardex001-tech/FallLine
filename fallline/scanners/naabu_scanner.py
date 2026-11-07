"""Naabu adapter (ProjectDiscovery fast port scanner).

Used for fast host/port discovery on larger networks before service-version
checks. Runs in non-intrusive TCP connect/SYN discovery mode with JSON output
and a conservative packet rate. Skipped gracefully when naabu is not installed.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from .base import Finding
from .socket_fallback import COMMON_PORTS


class NaabuError(Exception):
    """Raised when Naabu is missing or fails."""


def naabu_available() -> bool:
    return shutil.which("naabu") is not None


def build_command(target: str, top_ports: int = 1000, rate: int = 500) -> list[str]:
    return [
        "naabu",
        "-host", target,
        "-top-ports", str(top_ports),
        "-rate", str(rate),
        "-json",
        "-silent",
        "-no-color",
    ]


def parse_output(text: str) -> list[Finding]:
    """Parse Naabu JSONL output into Finding objects."""
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        host = str(row.get("ip") or row.get("host") or "").strip()
        port = int(row.get("port") or 0)
        protocol = str(row.get("protocol") or "tcp").lower()
        if not host or port <= 0:
            continue
        key = (host, port, protocol)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                host=host,
                port=port,
                protocol=protocol,
                state="open",
                service=COMMON_PORTS.get(port, ""),
                source="naabu",
            )
        )
    return findings


def scan(target: str, top_ports: int = 1000, rate: int = 500, timeout: int = 600) -> list[Finding]:
    if not naabu_available():
        raise NaabuError("naabu was not found on PATH")
    try:
        result = subprocess.run(
            build_command(target, top_ports=top_ports, rate=rate),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NaabuError(f"naabu timed out after {timeout}s") from exc
    if result.returncode != 0:
        raise NaabuError(f"naabu failed: {result.stderr.strip()}")
    return parse_output(result.stdout)
