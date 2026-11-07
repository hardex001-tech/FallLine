"""Alias module re-exporting naabu_scanner for plan compatibility."""
from .naabu_scanner import (
    NaabuError,
    build_command,
    naabu_available,
    parse_output,
    scan,
)

__all__ = ["NaabuError", "build_command", "naabu_available", "parse_output", "scan"]
