"""Jinja2 template engine and render helper."""

from datetime import datetime
from pathlib import Path
from typing import Any

from app.access_modes import app_launch_url
from starlette.templating import Jinja2Templates

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


templates.env.filters["initials"] = _initials
templates.env.filters["format_datetime"] = _format_datetime
templates.env.globals["app_launch_url"] = app_launch_url


def render(template_name: str, **context: Any):
    request = context.pop("request")
    status_code = context.pop("status_code", 200)
    return templates.TemplateResponse(request, template_name, context, status_code=status_code)
