"""Alias module re-exporting nmap_scanner for plan compatibility."""
from .nmap_scanner import (
    NmapError,
    build_command,
    build_probe_command,
    nmap_available,
    parse_nmap_xml,
    parse_port_probe,
    probe_port,
    scan,
)

__all__ = [
    "NmapError",
    "build_command",
    "build_probe_command",
    "nmap_available",
    "parse_nmap_xml",
    "parse_port_probe",
    "probe_port",
    "scan",
]
