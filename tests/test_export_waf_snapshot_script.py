"""Regression: jq aggregation in export-waf-snapshot.sh must use an array of families."""

from __future__ import annotations

from pathlib import Path


def test_export_waf_snapshot_uses_array_not_stream_for_families():
    script = (
        Path(__file__).parents[1] / "docker" / "nginx" / "export-waf-snapshot.sh"
    ).read_text(encoding="utf-8")
    # Stream binding ($a, $b, $c) as $fs then $fs[] indexes object values → jq error
    # "Cannot index string with string sec_rule_engine".
    assert "([$portal, $subdomain, $public]) as $fs" in script
    assert "($portal, $subdomain, $public) as $fs" not in script


def test_export_waf_snapshot_prefers_subdomain_overlay_file():
    script = (
        Path(__file__).parents[1] / "docker" / "nginx" / "export-waf-snapshot.sh"
    ).read_text(encoding="utf-8")
    assert "engine-subdomain-mode-generated.conf" in script
    assert 'overlay="${MODSEC}/generated/engine-subdomain-mode-generated.conf"' in script


def test_sync_exports_rewrites_subdomain_engine_via_cat():
    script = (
        Path(__file__).parents[1] / "docker" / "nginx" / "sync-exports-to-confd.sh"
    ).read_text(encoding="utf-8")
    assert (
        'cat "$EXPORTS/modsecurity/engine-subdomain-mode-generated.conf"' in script
    )
    assert (
        'cp -a "$EXPORTS/modsecurity/engine-subdomain-mode-generated.conf"'
        not in script
    )


def test_sync_exports_always_writes_include_safe_waf_stubs():
    """Missing exports must not leave dangling Includes or stale On overlays."""
    script = (
        Path(__file__).parents[1] / "docker" / "nginx" / "sync-exports-to-confd.sh"
    ).read_text(encoding="utf-8")
    assert "empty exclusions overlay (Include-safe)" in script
    assert "no promoted IP denies" in script
    assert "default portal rate zones (Include-safe)" in script
    assert "no public_armed path yet" in script
    assert "engine-public-mode-generated" in script
    # Engine overlays always forced Off when not armed (never leave missing file).
    assert script.count("SecRuleEngine Off") >= 2
