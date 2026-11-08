"""Alias module re-exporting nuclei_scanner for plan compatibility."""

from .nuclei_scanner import (
    FORBIDDEN_TAGS,
    SAFE_TAGS,
    build_command,
    nuclei_available,
    parse_output,
    scan_url,
)

__all__ = [
    "FORBIDDEN_TAGS",
    "SAFE_TAGS",
    "build_command",
    "nuclei_available",
    "parse_output",
    "scan_url",
]
