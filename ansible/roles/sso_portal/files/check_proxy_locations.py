#!/usr/bin/env python3
"""Fail if any nginx location /proxy/ is an active proxy (not legacy 301/302 redirect)."""

from __future__ import annotations

import pathlib
import re
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_proxy_locations.py <nginx_conf_dir>", file=sys.stderr)
        return 2

    conf_dir = pathlib.Path(sys.argv[1])
    loc_re = re.compile(
        r"location\s+[^{;\n]*?/proxy/[^{]*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}",
        re.MULTILINE,
    )
    bad: list[str] = []
    for path in sorted(conf_dir.glob("*.conf")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in loc_re.finditer(text):
            header = match.group(0).split("{", 1)[0].strip()
            body = match.group(1)
            line_no = text[: match.start()].count("\n") + 1
            has_redirect = re.search(r"\breturn\s+30[123]\b", body) is not None
            has_proxy_pass = re.search(r"\bproxy_pass\b", body) is not None
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
