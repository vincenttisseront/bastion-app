"""Human-readable User-Agent summaries for session diagnostics."""

from __future__ import annotations

from app import re_safe

_BROWSER_PATTERNS: list[tuple[str, object]] = [
    ("Edge", re_safe.compile(r"Edg(?:e|A|iOS)?/(\d+)", re_safe.IGNORECASE)),
    ("Firefox", re_safe.compile(r"Firefox/(\d+)", re_safe.IGNORECASE)),
    ("Chrome", re_safe.compile(r"Chrome/(\d+)", re_safe.IGNORECASE)),
    ("Safari", re_safe.compile(r"Version/(\d+)", re_safe.IGNORECASE)),
    ("Opera", re_safe.compile(r"OPR/(\d+)", re_safe.IGNORECASE)),
]

_OS_PATTERNS: list[tuple[str, object]] = [
    ("Windows", re_safe.compile(r"Windows NT", re_safe.IGNORECASE)),
    ("macOS", re_safe.compile(r"Mac OS X", re_safe.IGNORECASE)),
    ("iOS", re_safe.compile(r"iPhone|iPad", re_safe.IGNORECASE)),
    ("Android", re_safe.compile(r"Android", re_safe.IGNORECASE)),
    ("Linux", re_safe.compile(r"Linux", re_safe.IGNORECASE)),
]


def summarize_user_agent(ua: str | None) -> str:
    """Return e.g. 'Firefox 152 / Windows' or '—' if empty/unknown."""
    raw = (ua or "").strip()
    if not raw:
        return "—"
    browser = None
    for name, pat in _BROWSER_PATTERNS:
        m = pat.search(raw)
        if not m:
            continue
        if name == "Safari" and "Safari/" not in raw:
            continue
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
