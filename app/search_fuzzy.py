"""Shared fuzzy text scoring (stdlib only — difflib + unicodedata)."""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence
from difflib import SequenceMatcher


def fold_text(value: str) -> str:
    """Lowercase + strip accents for fuzzy comparison."""
    norm = unicodedata.normalize("NFKD", value or "")
    return "".join(c for c in norm if not unicodedata.combining(c)).casefold()


def score_query_against_fields(query: str, fields: Sequence[str]) -> float:
    """Best SequenceMatcher ratio in [0, 1] across fields (substring boost)."""
    q = fold_text(query)
    if not q:
        return 0.0
    best = 0.0
    for field in fields:
        f = fold_text(str(field or ""))
        if not f:
            continue
        if q == f:
            return 1.0
        if q in f:
            best = max(best, 0.92)
        best = max(best, SequenceMatcher(None, q, f).ratio())
    return best


def rank_by_score(
    items: Sequence[tuple[float, object]],
    *,
    limit: int = 8,
    min_score: float = 0.52,
) -> list[object]:
    """Keep items with score >= min_score, highest first, capped at limit."""
    ranked = [(s, item) for s, item in items if s >= min_score]
    ranked.sort(key=lambda pair: (-pair[0],))
    return [item for _, item in ranked[: max(1, limit)]]
