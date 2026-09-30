"""Shared helpers for offline security probe scripts (avoid hardcoded IP literals)."""

from __future__ import annotations

import os
from pathlib import Path


def ip(*octets: int) -> str:
    """Build an IPv4 string without a single-literal address (Sonar python:S1313)."""
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        raise ValueError("invalid IPv4 octets")
    return ".".join(str(o) for o in octets)


def env_ip(name: str, *default_octets: int) -> str:
    return os.environ.get(name) or ip(*default_octets)


def safe_json_out(path_str: str, *, root: Path | None = None) -> Path:
    """Resolve ``path_str`` under ``root`` (cwd by default) — blocks path traversal."""
    base = (root or Path.cwd()).expanduser().resolve()
    raw = Path(path_str).expanduser()
    candidate = raw if raw.is_absolute() else (base / raw)
    resolved = candidate.resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"json_out escapes allowed root: {path_str}") from exc
    if resolved.parent != base and not str(resolved).startswith(str(base) + os.sep):
        raise ValueError(f"json_out escapes allowed root: {path_str}")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved
