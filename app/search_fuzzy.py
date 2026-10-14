"""Shared fuzzy text scoring (stdlib only — difflib + unicodedata)."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from difflib import SequenceMatcher
from urllib.parse import urlparse

_SPLIT = re.compile(r"[\s._/\-:@]+")


def fold_text(value: str) -> str:
    """Lowercase + strip accents for fuzzy comparison."""
    norm = unicodedata.normalize("NFKD", value or "")
    return "".join(c for c in norm if not unicodedata.combining(c)).casefold()


def _hostname_from(value: str) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        if "://" in raw or raw.startswith("//"):
            host = urlparse(raw if "://" in raw else f"https:{raw}").hostname
            return host.lower() if host else None
    except ValueError:
        return None
    # Bare host or host:port (no path).
    if "/" in raw or " " in raw:
        return None
    host = raw.split("@")[-1].split(":")[0].strip().lower()
    if host and "." in host and not host.startswith("."):
        return host
    return None


def field_match_candidates(field: str) -> list[str]:
    """Expand a field into matchable strings (full value, host, tokens, DNS labels)."""
    raw = str(field or "").strip()
    if not raw:
        return []
    seen: set[str] = set()
    out: list[str] = []

    def add(value: str | None) -> None:
        text = (value or "").strip()
        if len(text) < 2:
            return
        key = fold_text(text)
        if key in seen:
            return
        seen.add(key)
        out.append(text)

    add(raw)
    host = _hostname_from(raw)
    add(host)
    if host:
        for label in host.split("."):
            add(label)
    for tok in _SPLIT.split(raw):
        add(tok)
    return out


def score_query_against_fields(query: str, fields: Sequence[str]) -> float:
    """Best SequenceMatcher ratio in [0, 1] across fields (substring / token boost)."""
    q = fold_text(query)
    if not q:
        return 0.0
    best = 0.0
    for field in fields:
        for candidate in field_match_candidates(str(field or "")):
            f = fold_text(candidate)
            if not f:
                continue
            if q == f:
                return 1.0
            if f.startswith(q) or q.startswith(f):
                # Prefix either way (query « sonar » ↔ label « sonarqube »).
                overlap = min(len(q), len(f)) / max(len(q), len(f))
                best = max(best, 0.88 + 0.1 * overlap)
            if q in f:
                best = max(best, 0.92)
            elif f in q and len(f) >= 3:
                best = max(best, 0.85)
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
