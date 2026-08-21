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
