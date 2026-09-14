"""Tests for the ReDoS-safe regex facade (google-re2)."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from app import re_safe


def test_using_re2_in_ci_or_local_with_wheel():
    assert isinstance(re_safe.using_re2(), bool)


def test_flag_aliases():
    assert re_safe.I is re_safe.IGNORECASE
    assert re_safe.M is re_safe.MULTILINE
    assert re_safe.S is re_safe.DOTALL
    assert re_safe.X is re_safe.VERBOSE
    assert re_safe.A is re_safe.ASCII
    assert re_safe.U is re_safe.UNICODE


def test_compile_search_ignorecase():
    pat = re_safe.compile(r"crushauth=([^;]+)", re_safe.IGNORECASE)
    m = pat.search("Foo=1; CrushAuth=abc; Bar=2")
    assert m is not None
    assert m.group(1) == "abc"


def test_compile_with_short_flag_alias():
    pat = re_safe.compile(r"hello", re_safe.I)
    assert pat.search("HELLO") is not None


def test_compile_dotall_and_multiline():
    pat = re_safe.compile(r"a.b", re_safe.DOTALL)
    assert pat.search("a\nb") is not None
    pat_m = re_safe.compile(r"^b", re_safe.MULTILINE)
    assert pat_m.search("a\nb") is not None


def test_compile_rejects_verbose_on_re2():
    if not re_safe.using_re2():
        return
    with pytest.raises(ValueError, match="VERBOSE"):
        re_safe.compile(r"a + b", re_safe.VERBOSE)


def test_fullmatch_validator():
    assert re_safe.fullmatch(r"^[a-z0-9-]{2,40}$", "my-realm")
    assert re_safe.fullmatch(r"^[a-z0-9-]{2,40}$", "BAD_REALM") is None


def test_match_and_search_string_pattern():
    assert re_safe.match(r"abc", "abcdef") is not None
    assert re_safe.match(r"abc", "xabcdef") is None
    assert re_safe.search(r"abc", "xabcdef") is not None


def test_findall_finditer_split_sub_string_patterns():
    found = re_safe.findall(r"[ab]", "aba")
    assert found == ["a", "b", "a"]

    matches = list(re_safe.finditer(r"[0-9]+", "a12b34"))
    assert [m.group(0) for m in matches] == ["12", "34"]

    assert re_safe.split(r"[,;]", "a,b;c") == ["a", "b", "c"]
    assert re_safe.sub(r"\d+", "#", "a12b34") == "a#b#"


def test_compiled_pattern_paths():
    pat = re_safe.compile(r"(\w+)=(\w+)")
    assert re_safe.search(pat, "x=y").group(1) == "x"
    assert re_safe.match(pat, "x=y").group(2) == "y"
    assert re_safe.fullmatch(pat, "x=y") is not None
    assert re_safe.findall(pat, "x=y") == [("x", "y")]
    assert list(re_safe.finditer(pat, "a=b"))[0].group(0) == "a=b"
    assert re_safe.sub(pat, r"\1", "a=b") == "a"
    assert re_safe.split(pat, "a=b")  # compiled split


def test_sub_with_group_ref():
    pat = re_safe.compile(r"(?i)(password)\s*=\s*[^\s'\",}]{1,64}")
    assert pat.sub(r"\1=***", "password=s3cret") == "password=***"


def test_escape_and_error_exported():
    assert re_safe.escape("a+b") == "a\\+b"
    assert re_safe.error is not None


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
    with pytest.raises(Exception):
        re_safe.compile(r"a{0,1001}")


def test_stdlib_fallback_paths():
    """Exercise clamp + stdlib branches when RE2 is forced off."""
    with (
        patch.object(re_safe, "_USING_RE2", False),
        patch.object(re_safe, "_re2", None),
    ):
        assert re_safe._options_from_flags(re_safe.IGNORECASE) == re_safe.IGNORECASE
        assert re_safe._clamp(None, 10) is None
        assert re_safe._clamp("abcd", None) == "abcd"
        assert re_safe._clamp("abcdefghij", 4) == "abcd"
        assert re_safe._clamp(123, 4) == 123

        pat = re_safe.compile(r"(password)=\w+", re_safe.IGNORECASE)
        assert pat.search("PASSWORD=x") is not None
        assert re_safe.search(r"ab", "zab") is not None
        assert re_safe.match(r"ab", "abc") is not None
        assert re_safe.fullmatch(r"ab", "ab") is not None
        assert re_safe.findall(r"[ab]", "ab") == ["a", "b"]
        assert [m.group(0) for m in re_safe.finditer(r"[ab]", "ab")] == ["a", "b"]
        assert re_safe.sub(r"a", "b", "a") == "b"
        assert re_safe.split(r",", "a,b") == ["a", "b"]

        assert re_safe.search(pat, "password=zz") is not None
        assert re_safe.match(pat, "password=zz") is not None
        assert re_safe.fullmatch(pat, "password=zz") is not None
        assert re_safe.findall(pat, "password=zz")
        assert list(re_safe.finditer(pat, "password=zz"))
        assert re_safe.sub(pat, r"\1=***", "password=zz").startswith("password")
        assert re_safe.split(r"(\s+)", "a b") == ["a", " ", "b"]

        clipped = re_safe.search(r"password=\w+", "password=abcxxx", max_input_len=8)
        assert clipped is None
