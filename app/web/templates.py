"""Jinja2 template engine and render helper."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from markupsafe import Markup
from starlette.templating import Jinja2Templates

from app.access_modes import app_launch_url
from app.bastion.bastion_fields import app_driver_badge_label
from app.i18n.catalog import t as translate
from app.i18n.middleware import get_request_locale
from app.i18n.resolve import DEFAULT_LOCALE

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _initials(value: str) -> str:
    parts = (value or "?").replace("@", " ").split()
    if len(parts) >= 2:
        return (parts[0][0] + parts[1][0]).upper()
    return (value or "?")[:2].upper()


def _format_datetime(value: datetime | str | None, fmt: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.strftime(fmt)


def _tojson(value: Any) -> Markup:
    """HTML-safe JSON for data-* attributes (Flask-compatible tojson).

    Safe in single-quoted attributes and ``<script>`` contexts. Do not wrap in
    double-quoted HTML attributes — structural ``"`` must remain for JSON.parse.
    """
    dumped = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    dumped = (
        dumped.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("'", "\\u0027")
    )
    return Markup(dumped)


def _make_gettext(locale: str):
    def _gettext(msgid: str, **kwargs: Any) -> str:
        return translate(str(msgid), locale, **kwargs)

    return _gettext


templates.env.filters["initials"] = _initials
templates.env.filters["format_datetime"] = _format_datetime
templates.env.filters["tojson"] = _tojson
templates.env.globals["app_launch_url"] = app_launch_url
templates.env.globals["app_driver_badge_label"] = app_driver_badge_label
# Default no-op until render() binds the request locale (keeps import-time safe).
templates.env.globals["_"] = _make_gettext(DEFAULT_LOCALE)
templates.env.globals["t"] = templates.env.globals["_"]


def render(template_name: str, **context: Any):
    request = context.pop("request")
    status_code = context.pop("status_code", 200)
    locale = context.get("locale") or get_request_locale(request)
    context.setdefault("locale", locale)
    gettext = _make_gettext(locale)
    # Per-render context (thread-safe) — overrides env globals for this template.
    context.setdefault("_", gettext)
    context.setdefault("t", gettext)
    response = templates.TemplateResponse(request, template_name, context, status_code=status_code)
    from app.web.flash import consume_flash_on_response

    consume_flash_on_response(request, response)
    return response
