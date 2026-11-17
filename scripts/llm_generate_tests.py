"""Draft tests for a module with the local LLM (developer tool, never in production).

Usage:
    LLM_ENABLED=true python -m scripts.llm_generate_tests app/re_safe.py
    LLM_ENABLED=true python -m scripts.llm_generate_tests app/web/csrf.py --framework pytest --focus "token rejeté"

The draft lands in tests/_llm_drafts/ (git-ignored, not collected by pytest).
Read it, fix it, then move it under tests/ yourself.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path, help="module to cover (e.g. app/re_safe.py)")
    parser.add_argument("--framework", choices=["pytest", "playwright"], default="pytest")
    parser.add_argument("--focus", default="", help="behaviour to prioritise")
    args = parser.parse_args(argv)

    from app.llm.features.test_generation import DraftRefused, generate_test_draft
    from app.sso_settings import get_settings

    if not args.source.is_file():
        print(f"introuvable : {args.source}", file=sys.stderr)
        return 2
    try:
        out, value = asyncio.run(
            generate_test_draft(
                get_settings(), args.source, framework=args.framework, focus=args.focus
            )
        )
    except DraftRefused as exc:
        print(f"refusé : {exc}", file=sys.stderr)
        return 1
    print(f"brouillon : {out}")
    print(value.get("summary", ""))
    for note in value.get("notes") or []:
        print(f"  - {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
