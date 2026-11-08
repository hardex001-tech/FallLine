"""Alias module re-exporting httpx_scanner for plan compatibility."""

from .httpx_scanner import (
    ADMIN_RE,
    REQUIRED_HEADERS,
    WEB_PORTS,
    build_command,
    find_binary,
    is_web,
    parse_output,
    profile,
    url_for,
)

__all__ = [
    "ADMIN_RE",
    "REQUIRED_HEADERS",
    "WEB_PORTS",
    "build_command",
    "find_binary",
    "is_web",
    "parse_output",
    "profile",
    "url_for",
]
