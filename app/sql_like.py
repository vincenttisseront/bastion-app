"""LIKE patterns built from user input, with ``%`` / ``_`` taken literally."""

from __future__ import annotations

LIKE_ESCAPE = "\\"


def escape_like(text: str) -> str:
    """``text`` with LIKE wildcards escaped, for use with ``escape=LIKE_ESCAPE``."""
    return (
        text.replace(LIKE_ESCAPE, LIKE_ESCAPE * 2)
        .replace("%", LIKE_ESCAPE + "%")
        .replace("_", LIKE_ESCAPE + "_")
    )


def contains_pattern(needle: str) -> str:
    """``%needle%`` for ``.ilike(pattern, escape=LIKE_ESCAPE)``."""
    return f"%{escape_like(needle)}%"
