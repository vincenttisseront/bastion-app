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


def test_donut_chart_renders():
    from app.bastion.waf_charts import render_donut_chart

    svg = render_donut_chart(
        [{"label": "SQLi", "count": 5}, {"label": "XSS", "count": 3}],
        title="Familles",
    )
    assert "waf-chart-donut" in svg
    assert "8" in svg  # total


def test_horizontal_bars_keep_readable_crs_labels():
    from app.bastion.waf_charts import render_owasp_bars

    svg = render_owasp_bars(
        [
            {
                "rule_id": "942110",
                "label": "Injection SQL (commentaire)",
                "count": 185,
            },
            {
                "rule_id": "949110",
                "label": "Score d'anomalie (blocage)",
                "count": 400,
            },
        ],
        title="Top 5 règles OWASP déclenchées",
    )
    assert "942110" in svg
    assert "949110" in svg
    assert "Injection SQL" in svg
    # Former hard clip to 16 chars made IDs unreadable ("490490…").
    assert "490490" not in svg
    assert 'x="248"' in svg  # bars start after wider label column
    assert "waf-chart-hbar-label" in svg


def test_dual_area_chart_has_vertical_scale():
    from app.bastion.waf_charts import _format_axis_count, render_dual_area_chart

    assert _format_axis_count(0) == "0"
    assert _format_axis_count(850) == "850"
    assert _format_axis_count(1200) == "1.2k"
    assert _format_axis_count(15000) == "15k"

    svg = render_dual_area_chart(
        [
            {"label": "10h", "inspected": 100, "detections": 20},
            {"label": "14h", "inspected": 900, "detections": 450},
            {"label": "18h", "inspected": 300, "detections": 80},
        ],
        title="Trafic vs tentatives d'intrusion (24 h)",
    )
    assert "sentinel-chart-axis-y" in svg
    assert ">900<" in svg or ">0.9k<" in svg
    assert ">0<" in svg
