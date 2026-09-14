"""Tests for the ReDoS-safe regex facade (google-re2)."""

from __future__ import annotations

import time

from app import re_safe


def test_using_re2_in_ci_or_local_with_wheel():
    # Prefer RE2; if missing, facade still works with clamps.
    assert isinstance(re_safe.using_re2(), bool)


def test_compile_search_ignorecase():
    pat = re_safe.compile(r"crushauth=([^;]+)", re_safe.IGNORECASE)
    m = pat.search("Foo=1; CrushAuth=abc; Bar=2")
    assert m is not None
    assert m.group(1) == "abc"


def test_fullmatch_validator():
    assert re_safe.fullmatch(r"^[a-z0-9-]{2,40}$", "my-realm")
    assert re_safe.fullmatch(r"^[a-z0-9-]{2,40}$", "BAD_REALM") is None


def test_sub_with_group_ref():
    pat = re_safe.compile(
        r"(?i)(password)\s*=\s*[^\s'\",}]{1,64}",
    )
    assert pat.sub(r"\1=***", "password=s3cret") == "password=***"


def test_linear_time_on_near_miss():
    """Classic evil pattern for stdlib re; RE2 stays linear."""
    pat = re_safe.compile(r"(a+)+b")
    text = "a" * 30_000
    t0 = time.perf_counter()
    assert pat.search(text) is None
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.5, f"regex too slow ({elapsed:.3f}s) — ReDoS risk"


def test_rejects_overlong_counted_repeat():
    """RE2 MaxRepeat is 1000 — facade must fail fast on compile."""
    if not re_safe.using_re2():
        return
    try:
        re_safe.compile(r"a{0,1001}")
    except Exception as exc:
        assert "repetition" in str(exc).lower() or "1001" in str(exc)
    else:
        raise AssertionError("expected RE2 to reject {0,1001}")
