"""Human-readable User-Agent summaries for session diagnostics."""

from __future__ import annotations

import re

_BROWSER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Edge", re.compile(r"Edg(?:e|A|iOS)?/(\d+)", re.I)),
    ("Firefox", re.compile(r"Firefox/(\d+)", re.I)),
    ("Chrome", re.compile(r"Chrome/(\d+)", re.I)),
    ("Safari", re.compile(r"Version/(\d+).*Safari/", re.I)),
    ("Opera", re.compile(r"OPR/(\d+)", re.I)),
]

_OS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Windows", re.compile(r"Windows NT", re.I)),
    ("macOS", re.compile(r"Mac OS X", re.I)),
    ("iOS", re.compile(r"iPhone|iPad", re.I)),
    ("Android", re.compile(r"Android", re.I)),
    ("Linux", re.compile(r"Linux", re.I)),
]


def summarize_user_agent(ua: str | None) -> str:
    """Return e.g. 'Firefox 152 / Windows' or '—' if empty/unknown."""
    raw = (ua or "").strip()
    if not raw:
        return "—"
    browser = None
    for name, pat in _BROWSER_PATTERNS:
        m = pat.search(raw)
        if m:
            browser = f"{name} {m.group(1)}"
            break
    os_name = None
    for name, pat in _OS_PATTERNS:
        if pat.search(raw):
            os_name = name
            break
    if browser and os_name:
        return f"{browser} / {os_name}"
    if browser:
        return browser
    if os_name:
        return os_name
    return raw[:48] + ("…" if len(raw) > 48 else "")
