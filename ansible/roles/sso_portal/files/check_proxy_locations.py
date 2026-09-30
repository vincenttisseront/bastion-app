#!/usr/bin/env python3
"""Fail if any nginx location /proxy/ is an active proxy (not legacy 301/302 redirect)."""

from __future__ import annotations

import pathlib
import sys


def _location_header_and_body(text: str, start: int) -> tuple[str, str, int] | None:
    """Return (header, body, line_no) for a `location … {` starting at start."""
    brace = text.find("{", start)
    if brace < 0:
        return None
    header = text[start:brace].strip()
    depth = 1
    i = brace + 1
    while i < len(text) and depth:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None
    body = text[brace + 1 : i - 1]
    line_no = text[:start].count("\n") + 1
    return header, body, line_no


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_proxy_locations.py <nginx_conf_dir>", file=sys.stderr)
        return 2

    conf_dir = pathlib.Path(sys.argv[1])
    bad: list[str] = []
    for path in sorted(conf_dir.glob("*.conf")):
        text = path.read_text(encoding="utf-8", errors="replace")
        needle = "location"
        pos = 0
        while True:
            idx = text.find(needle, pos)
            if idx < 0:
                break
            # Word-boundary-ish: start of line or whitespace before location
            if idx > 0 and text[idx - 1] not in " \t\n":
                pos = idx + len(needle)
                continue
            header_body = _location_header_and_body(text, idx)
            pos = idx + len(needle)
            if not header_body:
                continue
            header, body, line_no = header_body
            if "/proxy/" not in header:
                continue
            has_redirect = (
                "return 301" in body or "return 302" in body or "return 303" in body
            )
            has_proxy_pass = "proxy_pass" in body
            if has_proxy_pass or not has_redirect:
                bad.append(
                    f"{path}:{line_no}:{header} "
                    f"(proxy_pass={has_proxy_pass} redirect={has_redirect})"
                )
    if bad:
        print("\n".join(bad))
        return 1
    print("OK: aucune location /proxy/ active (uniquement redirects 301/302 legacy)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
