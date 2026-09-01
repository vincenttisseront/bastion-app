"""Server-side SVG charts for WAF efficiency (no CDN, no client library)."""

from __future__ import annotations

import html
import math
from typing import Any


def _esc(text: Any) -> str:
    return html.escape(str(text), quote=True)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        trial = " ".join(current + [word])
        if len(trial) <= width:
            current.append(word)
        else:
            if current:
                lines.append(" ".join(current))
            current = [word]
    if current:
        lines.append(" ".join(current))
    return lines


def _empty_panel(
    *,
    title: str,
    message: str,
    resolution: str | None = None,
    variant: str = "unavailable",
    width: int = 400,
    height: int = 140,
) -> str:
    """Light-themed empty state — styled via CSS classes on SVG elements."""
    lines = [
        f'<text class="waf-chart-empty-title" x="{width // 2}" y="40" text-anchor="middle">{_esc(title)}</text>',
        f'<text class="waf-chart-empty-msg" x="{width // 2}" y="62" text-anchor="middle">{_esc(message[:72])}</text>',
    ]
    y = 82
    if resolution:
        for chunk in _wrap(resolution, 52)[:2]:
            lines.append(
                f'<text class="waf-chart-empty-hint" x="{width // 2}" y="{y}" text-anchor="middle">{_esc(chunk)}</text>'
            )
            y += 14
    inner = "\n".join(lines)
    return (
        f'<svg class="waf-chart waf-chart-empty waf-chart-{variant}" '
        f'viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="{_esc(title)}">'
        f'<rect class="waf-chart-bg" width="{width}" height="{height}" rx="8"/>'
        f"{inner}</svg>"
    )


def render_series_chart(
    series: list[dict[str, Any]],
    *,
    value_key: str = "detections",
    title: str,
    width: int = 420,
    height: int = 160,
    empty_variant: str = "measured_zero",
    empty_message: str = "Aucune donnée sur la période",
) -> str:
    values = [max(0, int(p.get(value_key) or 0)) for p in series]
    if not series:
        return _empty_panel(title=title, message=empty_message, variant=empty_variant, width=width, height=height)
    if sum(values) == 0 and empty_variant == "measured_zero":
        return _empty_panel(
            title=title,
            message="Mesure effectuée — aucune activité",
            variant="measured_zero",
            width=width,
            height=height,
        )

    pad_l, pad_b, pad_t, pad_r = 36, 32, 28, 12
    chart_w = width - pad_l - pad_r
    chart_h = height - pad_t - pad_b
    max_v = max(values) or 1
    gap = 2
    n = max(len(values), 1)
    # Cap bar width so sparse series (e.g. 7 daily points) stay readable when SVG scales.
    bar_w = min(28, max(3, (chart_w // n) - gap))
    # Center the bar group when capped width leaves unused horizontal space.
    used_w = n * bar_w + (n - 1) * gap
    offset_x = pad_l + max(0, (chart_w - used_w) // 2)

    parts = [
        f'<svg class="waf-chart waf-chart-series" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" aria-label="{_esc(title)}">',
        f'<rect class="waf-chart-bg" width="{width}" height="{height}" rx="8"/>',
        f'<text class="waf-chart-title" x="{pad_l}" y="18">{_esc(title)}</text>',
    ]
    # Grid lines
    for i in range(4):
        gy = pad_t + int(chart_h * i / 3)
        parts.append(
            f'<line class="waf-chart-grid" x1="{pad_l}" y1="{gy}" x2="{width - pad_r}" y2="{gy}"/>'
        )
    for i, (point, val) in enumerate(zip(series, values)):
        x = offset_x + i * (bar_w + gap)
        h = int((val / max_v) * chart_h) if val else 0
        y = pad_t + chart_h - h
        parts.append(
            f'<rect class="waf-chart-bar" x="{x}" y="{y}" width="{bar_w}" height="{max(h, 0)}" rx="2">'
            f'<title>{_esc(point.get("label", ""))}: {val}</title></rect>'
        )
        if len(series) <= 12 or i % max(1, len(series) // 6) == 0:
            parts.append(
                f'<text class="waf-chart-axis" x="{x + bar_w // 2}" y="{height - 10}" '
                f'text-anchor="middle">{_esc(str(point.get("label", ""))[:5])}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def render_horizontal_bars(
    items: list[dict[str, Any]],
    *,
    label_key: str,
    value_key: str = "count",
    title: str,
    width: int = 560,
    row_height: int = 28,
    label_chars: int = 42,
    label_col_w: int = 220,
) -> str:
    """Horizontal bars with a dedicated label column (no bar overlap / 16-char clip)."""
    inner_h = max(60, 36 + len(items) * row_height) if items else 100
    height = inner_h + 8
    if not items:
        return _empty_panel(
            title=title,
            message="Aucune entrée sur la période",
            variant="measured_zero",
            width=width,
            height=height,
        )
    max_v = max(int(it.get(value_key) or 0) for it in items) or 1
    parts = [
        f'<svg class="waf-chart waf-chart-hbars" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" aria-label="{_esc(title)}">',
        f'<rect class="waf-chart-bg" width="{width}" height="{height}" rx="8"/>',
        f'<text class="waf-chart-title" x="16" y="20">{_esc(title)}</text>',
    ]
    label_x = 16
    bar_x = label_col_w
    # Leave room for count text after the bar.
    bar_max_w = max(40, width - bar_x - 56)
    for i, it in enumerate(items):
        y = 32 + i * row_height
        rule_id = str(it.get("rule_id") or "").strip()
        human = str(it.get(label_key) or it.get("label") or "—").strip()
        if rule_id and human and not human.startswith(rule_id):
            full = f"{rule_id} · {human}"
        else:
            full = human or rule_id or "—"
        short = full if len(full) <= label_chars else full[: label_chars - 1] + "…"
        val = int(it.get(value_key) or 0)
        bw = max(2, int((val / max_v) * bar_max_w))
        parts.append(
            f'<text class="waf-chart-hbar-label" x="{label_x}" y="{y + 16}">'
            f'<title>{_esc(full)}: {val}</title>{_esc(short)}</text>'
        )
        parts.append(
            f'<rect class="waf-chart-hbar" x="{bar_x}" y="{y + 3}" width="{bw}" height="16" rx="3">'
            f'<title>{_esc(full)}: {val}</title></rect>'
        )
        parts.append(
            f'<text class="waf-chart-hbar-val" x="{bar_x + bw + 8}" y="{y + 15}">{val}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def render_donut_chart(
    items: list[dict[str, Any]],
    *,
    label_key: str = "label",
    value_key: str = "count",
    title: str = "Répartition par famille",
    width: int = 420,
    height: int = 180,
) -> str:
    total = sum(int(it.get(value_key) or 0) for it in items)
    if not items or total == 0:
        return _empty_panel(
            title=title,
            message="Aucune détection classée",
            variant="measured_zero",
            width=width,
            height=height,
        )

    colors = ["#10b981", "#3b82f6", "#f59e0b", "#ef4444", "#8b5cf6", "#64748b"]
    cx, cy, r, ri = 88, height // 2 + 8, 52, 32
    start = -math.pi / 2
    parts = [
        f'<svg class="waf-chart waf-chart-donut" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" aria-label="{_esc(title)}">',
        f'<rect class="waf-chart-bg" width="{width}" height="{height}" rx="8"/>',
        f'<text class="waf-chart-title" x="16" y="20">{_esc(title)}</text>',
    ]
    for i, it in enumerate(items):
        val = int(it.get(value_key) or 0)
        if val <= 0:
            continue
        angle = (val / total) * 2 * math.pi
        end = start + angle
        x1 = cx + r * math.cos(start)
        y1 = cy + r * math.sin(start)
        x2 = cx + r * math.cos(end)
        y2 = cy + r * math.sin(end)
        xi1 = cx + ri * math.cos(end)
        yi1 = cy + ri * math.sin(end)
        xi2 = cx + ri * math.cos(start)
        yi2 = cy + ri * math.sin(start)
        large = 1 if angle > math.pi else 0
        color = colors[i % len(colors)]
        parts.append(
            f'<path fill="{color}" d="M{x1:.1f},{y1:.1f} A{r},{r} 0 {large},1 {x2:.1f},{y2:.1f} '
            f'L{xi1:.1f},{yi1:.1f} A{ri},{ri} 0 {large},0 {xi2:.1f},{yi2:.1f} Z">'
            f'<title>{_esc(it.get(label_key, ""))}: {val}</title></path>'
        )
        start = end

    parts.append(f'<text class="waf-chart-donut-center" x="{cx}" y="{cy - 2}" text-anchor="middle">{total}</text>')
    parts.append(
        f'<text class="waf-chart-donut-sub" x="{cx}" y="{cy + 12}" text-anchor="middle">détections</text>'
    )
    ly = 36
    for i, it in enumerate(items):
        color = colors[i % len(colors)]
        val = int(it.get(value_key) or 0)
        lx = 180
        parts.append(f'<rect x="{lx}" y="{ly - 10}" width="10" height="10" rx="2" fill="{color}"/>')
        parts.append(
            f'<text class="waf-chart-legend" x="{lx + 16}" y="{ly - 1}">'
            f'{_esc(it.get(label_key, ""))} ({val})</text>'
        )
        ly += 18
    parts.append("</svg>")
    return "".join(parts)


def render_family_breakdown(
    families: list[dict[str, Any]],
    *,
    title: str = "Répartition par famille",
    width: int = 420,
) -> str:
    items = [{"label": f.get("label", f.get("family", "")), "count": f.get("count")} for f in families]
    return render_donut_chart(items, label_key="label", value_key="count", title=title, width=width)


def render_dual_area_chart(
    series: list[dict[str, Any]],
    *,
    title: str,
    primary_key: str = "inspected",
    secondary_key: str = "detections",
    primary_label: str = "Trafic inspecté",
    secondary_label: str = "Tentatives d'intrusion",
    width: int = 560,
    height: int = 200,
    empty_variant: str = "measured_zero",
    empty_message: str = "Aucune donnée sur la période",
) -> str:
    """Area chart — traffic vs intrusion attempts (Sentinel theme)."""
    if not series:
        return _empty_panel(title=title, message=empty_message, variant=empty_variant, width=width, height=height)
    p_vals = [max(0, int(p.get(primary_key) or 0)) for p in series]
    s_vals = [max(0, int(p.get(secondary_key) or 0)) for p in series]
    if sum(p_vals) + sum(s_vals) == 0 and empty_variant == "measured_zero":
        return _empty_panel(
            title=title,
            message="Mesure effectuée — aucune activité",
            variant="measured_zero",
            width=width,
            height=height,
        )

    pad_l, pad_b, pad_t, pad_r = 40, 36, 32, 16
    chart_w = width - pad_l - pad_r
    chart_h = height - pad_t - pad_b
    max_v = max(max(p_vals) if p_vals else 0, max(s_vals) if s_vals else 0, 1)
    n = max(len(series), 1)
    step = chart_w / max(n - 1, 1)

    def _points(vals: list[int]) -> str:
        pts: list[str] = []
        for i, val in enumerate(vals):
            x = pad_l + i * step
            y = pad_t + chart_h - int((val / max_v) * chart_h)
            pts.append(f"{x:.1f},{y:.1f}")
        return " ".join(pts)

    def _area_path(vals: list[int]) -> str:
        if not vals:
            return ""
        first_x = pad_l
        last_x = pad_l + (len(vals) - 1) * step
        base_y = pad_t + chart_h
        line = _points(vals)
        return f"M{first_x:.1f},{base_y:.1f} L{line.replace(' ', ' L')} L{last_x:.1f},{base_y:.1f} Z"

    parts = [
        f'<svg class="waf-chart waf-chart-area sentinel-chart" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" aria-label="{_esc(title)}">',
        f'<rect class="sentinel-chart-bg" width="{width}" height="{height}" rx="10"/>',
        f'<text class="sentinel-chart-title" x="{pad_l}" y="20">{_esc(title)}</text>',
        f'<text class="sentinel-chart-legend" x="{width - pad_r}" y="20" text-anchor="end">'
        f'<tspan fill="#64748b">●</tspan> {_esc(primary_label)}  '
        f'<tspan fill="#ef4444">●</tspan> {_esc(secondary_label)}</text>',
    ]
    for i in range(4):
        gy = pad_t + int(chart_h * i / 3)
        parts.append(
            f'<line class="sentinel-chart-grid" x1="{pad_l}" y1="{gy}" x2="{width - pad_r}" y2="{gy}"/>'
        )
    parts.append(f'<path class="sentinel-area-primary" d="{_area_path(p_vals)}"/>')
    parts.append(f'<path class="sentinel-area-secondary" d="{_area_path(s_vals)}"/>')
    parts.append(f'<polyline class="sentinel-line-primary" fill="none" points="{_points(p_vals)}"/>')
    parts.append(f'<polyline class="sentinel-line-secondary" fill="none" points="{_points(s_vals)}"/>')
    for i, point in enumerate(series):
        if len(series) <= 12 or i % max(1, len(series) // 6) == 0:
            x = pad_l + i * step
            parts.append(
                f'<text class="sentinel-chart-axis" x="{x:.1f}" y="{height - 12}" '
                f'text-anchor="middle">{_esc(str(point.get("label", ""))[:5])}</text>'
            )
        if i < len(p_vals):
            x = pad_l + i * step
            py = pad_t + chart_h - int((p_vals[i] / max_v) * chart_h)
            sy = pad_t + chart_h - int((s_vals[i] / max_v) * chart_h)
            lbl = _esc(str(point.get("label", "")))
            parts.append(
                f'<circle class="sentinel-dot-primary" cx="{x:.1f}" cy="{py:.1f}" r="3">'
                f'<title>{lbl}: {_esc(primary_label)} {p_vals[i]}</title></circle>'
            )
            parts.append(
                f'<circle class="sentinel-dot-secondary" cx="{x:.1f}" cy="{sy:.1f}" r="3">'
                f'<title>{lbl}: {_esc(secondary_label)} {s_vals[i]}</title></circle>'
            )
    parts.append("</svg>")
    return "".join(parts)


def render_health_gauge(
    score: int,
    *,
    title: str = "Score de santé",
    width: int = 140,
    height: int = 140,
) -> str:
    """Circular health gauge 0–100."""
    score = max(0, min(100, int(score)))
    cx, cy, r = width // 2, height // 2 + 4, 48
    circ = 2 * math.pi * r
    offset = circ * (1 - score / 100)
    color = "#10b981" if score >= 75 else "#f59e0b" if score >= 50 else "#ef4444"
    parts = [
        f'<svg class="waf-chart waf-chart-gauge sentinel-chart" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" aria-label="{_esc(title)}: {score}%">',
        f'<circle class="sentinel-gauge-track" cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke-width="10"/>',
        f'<circle class="sentinel-gauge-fill" cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke-width="10" '
        f'stroke="{color}" stroke-dasharray="{circ:.1f}" stroke-dashoffset="{offset:.1f}" '
        f'transform="rotate(-90 {cx} {cy})"/>',
        f'<text class="sentinel-gauge-value" x="{cx}" y="{cy + 2}" text-anchor="middle">{score}</text>',
        f'<text class="sentinel-gauge-label" x="{cx}" y="{cy + 18}" text-anchor="middle">/100</text>',
        "</svg>",
    ]
    return "".join(parts)


def render_attack_heatmap(
    matrix: list[list[int]],
    *,
    row_labels: list[str],
    col_labels: list[str],
    title: str = "Origine des attaques (réseaux /24 × heure)",
    width: int = 560,
    row_height: int = 22,
) -> str:
    if not matrix or not row_labels:
        return _empty_panel(
            title=title,
            message="Aucune origine agrégée sur 24 h",
            variant="measured_zero",
            width=width,
            height=160,
        )
    cols = len(col_labels) or len(matrix[0]) if matrix else 0
    label_w, pad_t = 88, 28
    cell_w = max(8, (width - label_w - 16) // max(cols, 1))
    height = pad_t + len(matrix) * row_height + 24
    max_v = max(max(row) for row in matrix) if matrix else 1
    max_v = max(max_v, 1)

    parts = [
        f'<svg class="waf-chart waf-chart-heatmap sentinel-chart" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" aria-label="{_esc(title)}">',
        f'<rect class="sentinel-chart-bg" width="{width}" height="{height}" rx="10"/>',
        f'<text class="sentinel-chart-title" x="12" y="18">{_esc(title)}</text>',
    ]
    for ri, row in enumerate(matrix):
        y = pad_t + ri * row_height
        parts.append(
            f'<text class="sentinel-heatmap-row" x="8" y="{y + 15}">{_esc(row_labels[ri][:12])}</text>'
        )
        for ci, val in enumerate(row[:cols]):
            x = label_w + ci * cell_w
            intensity = val / max_v
            fill = f"rgba(239,68,68,{0.12 + intensity * 0.88:.2f})"
            parts.append(
                f'<rect x="{x:.1f}" y="{y + 2}" width="{cell_w - 2}" height="{row_height - 4}" '
                f'rx="2" fill="{fill}">'
                f'<title>{_esc(row_labels[ri])} · {_esc(col_labels[ci] if ci < len(col_labels) else "")}: {val}</title>'
                f"</rect>"
            )
    if col_labels:
        for ci in range(0, cols, max(1, cols // 6)):
            x = label_w + ci * cell_w + cell_w / 2
            parts.append(
                f'<text class="sentinel-chart-axis" x="{x:.1f}" y="{height - 6}" '
                f'text-anchor="middle">{_esc(str(col_labels[ci])[:4])}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def render_owasp_bars(
    items: list[dict[str, Any]],
    *,
    title: str = "Top 5 règles OWASP",
    width: int = 560,
) -> str:
    """Horizontal bars with readable CRS id + label (Sentinel threat intel)."""
    if not items:
        return _empty_panel(
            title=title,
            message="Aucune règle déclenchée",
            variant="measured_zero",
            width=width,
            height=140,
        )
    return render_horizontal_bars(
        items,
        label_key="label",
        value_key="count",
        title=title,
        width=width,
        label_chars=48,
        label_col_w=248,
    )
