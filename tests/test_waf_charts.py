"""Tests for server-side WAF SVG charts."""

from app.bastion.waf_charts import render_series_chart, _empty_panel


def test_empty_panel_unavailable_variant():
    svg = _empty_panel(title="Indisponible", message="Test", variant="unavailable")
    assert "waf-chart-unavailable" in svg
    assert "Indisponible" in svg


def test_series_chart_measured_zero():
    svg = render_series_chart(
        [{"label": "12h", "detections": 0}],
        title="Test",
        empty_variant="measured_zero",
    )
    assert "waf-chart-measured_zero" in svg or "Mesure effectuée" in svg
