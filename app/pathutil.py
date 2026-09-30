"""Path containment helpers — keep writes under an allowed root (path traversal)."""

from __future__ import annotations

import os
from pathlib import Path


def ensure_under(path: Path, root: Path) -> Path:
    """Resolve ``path`` and raise if it escapes ``root``.

    Used at write sinks so configured/export paths cannot traverse outside the
    intended data directory (Sonar pythonsecurity:S2083).
    """
    root_r = root.expanduser().resolve()
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = root_r / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root_r)
    except ValueError as exc:
        raise ValueError(f"path escapes allowed root: {path}") from exc
    return resolved


def _basename_only(name: str) -> str:
    """Accept a single path segment (no separators / traversal).

    Uses ``os.path.basename`` so static analyzers recognize the sanitizer
    (Sonar pythonsecurity:S2083).
    """
    text = (name or "").strip()
    if not text or text in (".", "..") or "/" in text or "\\" in text:
        raise ValueError(f"invalid basename: {name!r}")
    safe = os.path.basename(text)
    if safe != text or safe in (".", "..") or not safe:
        raise ValueError(f"invalid basename: {name!r}")
    return safe


def write_text_under(
    root: Path, name: str, text: str, *, encoding: str = "utf-8"
) -> Path:
    """Write ``root / basename`` only — filename is never taken from raw paths."""
    root_r = root.expanduser().resolve()
    path = root_r / _basename_only(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding=encoding) as fh:
        fh.write(text)
    return path


def write_bytes_under(root: Path, data: bytes, *segments: str) -> Path:
    """Write bytes at ``root / a / b / …`` with each segment basename-validated."""
    root_r = root.expanduser().resolve()
    parts = [_basename_only(s) for s in segments]
    if not parts:
        raise ValueError("empty relative path")
    # Build under root using only basename-sanitized segments (S2083).
    path = root_r
    for part in parts:
        path = path / part
    try:
        path.resolve().relative_to(root_r)
    except ValueError as exc:
        raise ValueError(f"path escapes allowed root: {segments!r}") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def sanitize_log_value(value: object, *, max_len: int = 200) -> str:
    """Strip CR/LF from values interpolated into log messages (S5145)."""
    text = str(value if value is not None else "")
    text = text.replace("\r", " ").replace("\n", " ").replace("\0", "")
    if len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text
