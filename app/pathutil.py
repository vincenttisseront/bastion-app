"""Path containment helpers — keep writes under an allowed root (path traversal)."""

from __future__ import annotations

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
    """Accept a single path segment (no separators / traversal)."""
    text = (name or "").strip()
    if not text or text in (".", "..") or "/" in text or "\\" in text:
        raise ValueError(f"invalid basename: {name!r}")
    if Path(text).name != text:
        raise ValueError(f"invalid basename: {name!r}")
    return text


def write_text_under(
    root: Path, name: str, text: str, *, encoding: str = "utf-8"
) -> Path:
    """Write ``root / basename`` only — filename is never taken from raw paths."""
    root_r = root.expanduser().resolve()
    path = root_r / _basename_only(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding=encoding)
    return path


def write_bytes_under(root: Path, relative: str, data: bytes) -> Path:
    """Write bytes at ``root / relative`` after rejecting ``..`` segments."""
    root_r = root.expanduser().resolve()
    rel = (relative or "").strip().replace("\\", "/")
    parts = [p for p in rel.split("/") if p and p != "."]
    if not parts or any(p == ".." for p in parts):
        raise ValueError(f"invalid relative path: {relative!r}")
    path = root_r.joinpath(*parts).resolve()
    path.relative_to(root_r)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def sanitize_log_value(value: object, *, max_len: int = 200) -> str:
    """Strip CR/LF from values interpolated into log messages (S5145)."""
    text = str(value if value is not None else "")
    text = text.replace("\r", " ").replace("\n", " ").replace("\0", "")
    if len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text
