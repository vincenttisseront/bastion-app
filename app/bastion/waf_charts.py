"""Server-side SVG charts for WAF efficiency (no CDN, no client library)."""

from __future__ import annotations

import html
from typing import Any


def _esc(text: Any) -> str:
    return html.escape(str(text), quote=True)


def _empty_panel(
    *,
    title: str,
    message: str,
    resolution: str | None = None,
    variant: str = "unavailable",
    width: int = 320,
    height: int = 160,
) -> str:
    fill = {"unavailable": "#3d2f1f", "unverifiable": "#2f2f3d", "measured_zero": "#1f2f24"}.get(
        variant, "#2a2a2a"
    )
    stroke = {"unavailable": "#b45309", "unverifiable": "#6366f1", "measured_zero": "#059669"}.get(
        variant, "#555"
    )
    lines = [
        f'<text x="{width // 2}" y="36" text-anchor="middle" fill="#e5e7eb" font-size="13" font-weight="600">{_esc(title)}</text>',
        f'<text x="{width // 2}" y="58" text-anchor="middle" fill="#9ca3af" font-size="11">{_esc(message[:80])}</text>',
    ]
    y = 78
    if resolution:
        for chunk in _wrap(resolution, 46)[:3]:
            lines.append(
                f'<text x="{width // 2}" y="{y}" text-anchor="middle" fill="#6b7280" font-size="10">{_esc(chunk)}</text>'
            )
            y += 14
    inner = "\n".join(lines)
    return (
        f'<svg class="waf-chart waf-chart-{variant}" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" aria-label="{_esc(title)}">'
        f'<rect width="{width}" height="{height}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1"/>'
        f"{inner}</svg>"
    )


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


def render_series_chart(
    series: list[dict[str, Any]],
    *,
    value_key: str = "detections",
    title: str,
    width: int = 360,
    height: int = 140,
    empty_variant: str = "measured_zero",
    empty_message: str = "Aucune donnée sur la période",
) -> str:
    values = [max(0, int(p.get(value_key) or 0)) for p in series]
    if not series:
        return _empty_panel(title=title, message=empty_message, variant=empty_variant, width=width, height=height)
    if sum(values) == 0 and empty_variant == "measured_zero":
        return _empty_panel(
            title=title,
            message="Mesure effectuée — résultat nul",
            variant="measured_zero",
            width=width,
            height=height,
        )

    pad_l, pad_b, pad_t, pad_r = 28, 28, 22, 8
    chart_w = width - pad_l - pad_r
    chart_h = height - pad_t - pad_b
    max_v = max(values) or 1
    bar_w = max(2, chart_w // max(len(values), 1) - 2)
    parts = [
        f'<svg class="waf-chart waf-chart-series" viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" aria-label="{_esc(title)}">',
        f'<text x="{pad_l}" y="14" fill="#9ca3af" font-size="11">{_esc(title)}</text>',
    ]
    for i, (point, val) in enumerate(zip(series, values)):
        x = pad_l + i * (bar_w + 2)
        h = int((val / max_v) * chart_h) if val else 0
        y = pad_t + chart_h - h
        parts.append(
            f'<rect x="{x}" y="{y}" width="{bar_w}" height="{h}" fill="#10b981" rx="1">'
            f'<title>{_esc(point.get("label", ""))}: {val}</title></rect>'
        )
        if len(series) <= 12 or i % max(1, len(series) // 6) == 0:
            parts.append(
                f'<text x="{x + bar_w // 2}" y="{height - 8}" text-anchor="middle" fill="#6b7280" font-size="9">{_esc(str(point.get("label", ""))[:6])}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def render_horizontal_bars(
    items: list[dict[str, Any]],
    *,
    label_key: str,
    value_key: str = "count",
    title: str,
    width: int = 360,
    row_height: int = 22,
) -> str:
    if not items:
        return _empty_panel(
            title=title,
            message="Aucune entrée sur la période",
            variant="measured_zero",
            width=width,
            height=100,
        )
    height = 28 + len(items) * row_height
    max_v = max(int(it.get(value_key) or 0) for it in items) or 1
    parts = [
        f'<svg class="waf-chart waf-chart-hbars" viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" aria-label="{_esc(title)}">',
        f'<text x="0" y="14" fill="#9ca3af" font-size="11">{_esc(title)}</text>',
    ]
    bar_max_w = width - 140
    for i, it in enumerate(items):
        y = 24 + i * row_height
        label = str(it.get(label_key) or "—")
        short = label if len(label) <= 18 else label[:16] + "…"
        val = int(it.get(value_key) or 0)
        bw = int((val / max_v) * bar_max_w)
        parts.append(f'<text x="0" y="{y + 14}" fill="#d1d5db" font-size="10">{_esc(short)}</text>')
        parts.append(f'<rect x="120" y="{y + 2}" width="{bw}" height="14" fill="#6366f1" rx="2"><title>{_esc(label)}: {val}</title></rect>')
        parts.append(f'<text x="{120 + bw + 6}" y="{y + 13}" fill="#9ca3af" font-size="10">{val}</text>')
    parts.append("</svg>")
    return "".join(parts)


def render_family_breakdown(
    families: list[dict[str, Any]],
    *,
    title: str = "Répartition par famille",
    width: int = 360,
) -> str:
    if not families or sum(int(f.get("count") or 0) for f in families) == 0:
        return _empty_panel(
            title=title,
            message="Aucune détection classée",
            variant="measured_zero",
            width=width,
            height=120,
        )
    colors = ["#10b981", "#6366f1", "#f59e0b", "#ef4444", "#8b5cf6", "#6b7280"]
    total = sum(int(f.get("count") or 0) for f in families) or 1
    height = 24 + len(families) * 20
    parts = [
        f'<svg class="waf-chart waf-chart-families" viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" aria-label="{_esc(title)}">',
        f'<text x="0" y="14" fill="#9ca3af" font-size="11">{_esc(title)}</text>',
    ]
    x_off = 0
    bar_y = 22
    bar_h = 12
    for i, fam in enumerate(families):
        cnt = int(fam.get("count") or 0)
        w = int((cnt / total) * (width - 20))
        color = colors[i % len(colors)]
        parts.append(
            f'<rect x="{10 + x_off}" y="{bar_y}" width="{max(w, 2)}" height="{bar_h}" fill="{color}"><title>{_esc(fam.get("label", ""))}: {cnt}</title></rect>'
        )
        x_off += w
    legend_y = bar_y + bar_h + 16
    for i, fam in enumerate(families):
        color = colors[i % len(colors)]
        ly = legend_y + i * 16
        parts.append(f'<rect x="0" y="{ly - 9}" width="8" height="8" fill="{color}"/>')
        parts.append(
            f'<text x="14" y="{ly - 1}" fill="#d1d5db" font-size="10">{_esc(fam.get("label", ""))} ({int(fam.get("count") or 0)})</text>'
        )
    parts.append("</svg>")
    return "".join(parts)
