"""Integrity tests for the central audit event catalogue."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.audit.event_catalog import (
    ACTION_TO_CODE,
    DOMAINS,
    EVENTS,
    Severity,
    parse_event_code,
    resolve_event,
    severity_from_number,
    uncatalogued_event,
)


def test_catalog_unique_codes_and_labels():
    codes = [e.code for e in EVENTS.values()]
    labels = [e.label for e in EVENTS.values()]
    assert len(codes) == len(set(codes))
    assert len(labels) == len(set(labels))


def test_catalog_domains_and_bands():
    for ev in EVENTS.values():
        assert ev.domain in DOMAINS
        assert 1 <= ev.number <= 4999
        assert ev.severity in Severity


def test_severity_from_number_bands():
    assert severity_from_number(1) is Severity.INFO
    assert severity_from_number(1001) is Severity.NOTICE
    assert severity_from_number(2001) is Severity.WARNING
    assert severity_from_number(3001) is Severity.ERROR
    assert severity_from_number(4001) is Severity.CRITICAL
    assert severity_from_number(0) is Severity.WARNING
    with pytest.raises(ValueError):
        severity_from_number(5000)


def test_parse_rejects_unknown_domain():
    with pytest.raises(ValueError):
        parse_event_code("BST-ZZZ-0001")


def test_resolve_known_action():
    ev = resolve_event(action="breakglass.login_failed")
    assert ev.code == "BST-BGL-2001"
    assert ev.severity is Severity.WARNING
    assert ev.label == "BREAKGLASS_LOGIN_FAILED"


def test_resolve_unknown_action_uncatalogued():
    ev = resolve_event(action="totally.unknown.event")
    assert ev.code.endswith("-0000")
    assert ev.severity is Severity.WARNING
    assert ev.label == "UNCATALOGUED_EVENT"


def test_resolve_explicit_code():
    ev = resolve_event(code="BST-BGL-4001")
    assert ev.severity is Severity.CRITICAL
    assert ev.label == "BREAKGLASS_LOGIN_FROM_NON_LAN"


def test_uncatalogued_guess_domain():
    assert uncatalogued_event("breakglass.foo").code == "BST-BGL-0000"
    assert uncatalogued_event("file.upload").code == "BST-FILE-0000"
    assert uncatalogued_event("weird").code == "BST-SYS-0000"


def test_all_literal_log_actions_are_catalogued():
    """Static coverage: action=\"...\" / action='...' near log_action calls."""
    root = Path(__file__).resolve().parents[1] / "app"
    pattern = re.compile(
        r"""log_action\s*\([\s\S]*?action\s*=\s*(['\"])([^'\"]+)\1""",
        re.MULTILINE,
    )
    # Also catch positional-ish rare forms: action as second/third kw only via action=
    missing: list[str] = []
    seen: set[str] = set()
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for m in pattern.finditer(text):
            action = m.group(2)
            if "{" in action:  # f-string fragment — catalogue concrete variants separately
                continue
            seen.add(action)
            if action not in ACTION_TO_CODE:
                missing.append(f"{path.relative_to(root.parent)}: {action}")
    assert not missing, "Uncatalogued log_action literals:\n" + "\n".join(missing)
    # Sanity: inventory should be large
    assert len(seen) >= 150
