"""UI lot 5: no native dialogs, no hardcoded colours, motion tokens, sessions wording."""

from __future__ import annotations

import pathlib
import re

from app.bastion.waf_charts import render_attack_heatmap, render_family_breakdown, render_health_gauge

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "app" / "templates"
CSS = ROOT / "app" / "static" / "css"
JS = ROOT / "app" / "static" / "js"

NATIVE_DIALOG = re.compile(r"(?<![\w.])(?:window\.)?(alert|confirm|prompt)\(")
HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")


def _sources(base: pathlib.Path, pattern: str):
    for path in base.rglob(pattern):
        if "vendor" in path.parts:
            continue
        yield path, path.read_text(encoding="utf-8")


def test_no_native_alert_confirm_or_prompt():
    offenders = []
    for base, pattern in ((TEMPLATES, "*.html"), (JS, "*.js")):
        for path, text in _sources(base, pattern):
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue
                if NATIVE_DIALOG.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}: {stripped[:80]}")
    assert offenders == []


def test_component_css_uses_tokens_not_hex():
    # Tokens live in bastion-tokens.css; the WAF print sheet keeps a white page on purpose.
    allowed = {"bastion-tokens.css"}
    offenders = []
    for path, text in _sources(CSS, "*.css"):
        if path.name in allowed:
            continue
        for m in HEX.finditer(text):
            line = text[: m.start()].count("\n") + 1
            context = text.splitlines()[line - 1]
            if "@media print" in text and "body.app-layout{display:block!important;background:#fff!important}" in context:
                continue
            offenders.append(f"{path.name}:{line}: {m.group(0)}")
    assert offenders == []


def test_waf_charts_take_colours_from_classes():
    svg = "".join(
        [
            render_family_breakdown([{"label": "SQLi", "count": 3}, {"label": "XSS", "count": 1}]),
            render_health_gauge(42),
            render_attack_heatmap([[1, 3]], row_labels=["10.0.0.0/24"], col_labels=["00h", "01h"]),
        ]
    )
    assert not HEX.search(svg)
    assert "rgba(" not in svg
    assert "waf-series-0" in svg
    assert "sentinel-gauge-fill--err" in svg
    assert "sentinel-heatmap-cell" in svg


def test_drawers_use_motion_tokens():
    """Side drawers enter with --dur-3 / --ease-out and leave 25 % faster with --ease-in."""
    drawers = {
        "bastion-layout.css": "body.app-layout .sidebar{",
        "bastion-components.css": ".logs-drawer{",
        "bastion-sessions.css": ".session-detail-drawer {",
    }
    for name, selector in drawers.items():
        text = (CSS / name).read_text(encoding="utf-8")
        start = text.index(selector)
        rule = text[start : text.index("}", start)]
        assert "calc(var(--dur-3) * .75) var(--ease-in)" in rule, name
        assert not re.search(r"transition:\s*transform\s+[0-9.]+m?s", rule), name


def test_sessions_page_never_says_session_s():
    text = (TEMPLATES / "sessions" / "index.html").read_text(encoding="utf-8")
    assert "session(s)')" not in text
    js = (JS / "bastion-sessions.js").read_text(encoding="utf-8")
    assert "BastionI18n.t('session(s)')" not in js
    assert "sessionsLabel(" in js
