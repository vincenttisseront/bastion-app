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
