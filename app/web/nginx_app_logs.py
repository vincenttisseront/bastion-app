"""Read nginx per-app access logs (public_proxy / subdomain_proxy).

Logs live under NGINX_APP_LOGS_DIR (shared volume with bastion-nginx
``/var/log/nginx/apps``). Only DB-known proxy app slugs are readable.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.access_modes import normalize_access_mode
from app.models import App
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

_SAFE_SLUG = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
_LOGGABLE_MODES = frozenset({"public_proxy", "subdomain_proxy"})
_DEFAULT_TAIL = 200
_MAX_TAIL = 5000


def resolve_nginx_app_logs_dir(settings: Settings) -> Path:
    raw = (getattr(settings, "nginx_app_logs_dir", None) or "").strip()
    if raw:
        return Path(raw)
    portal = (settings.portal_data_dir or "").strip() or "./data/sso-portal"
    return Path(portal) / "nginx-logs"


def list_loggable_apps(db: Session) -> list[dict[str, str]]:
    """Enabled proxy apps that write ``{slug}.access.log`` (ordered by slug)."""
    apps = db.query(App).filter_by(enabled=True).order_by(App.slug).all()
    out: list[dict[str, str]] = []
    for app in apps:
        mode = normalize_access_mode(app.access_mode)
        if mode not in _LOGGABLE_MODES:
            continue
        fqdn = (app.public_fqdn or "").strip()
        if not fqdn:
            continue
        if not _SAFE_SLUG.match(app.slug or ""):
            continue
        out.append(
            {
                "slug": app.slug,
                "label": app.label or app.slug,
                "access_mode": mode,
                "public_fqdn": fqdn,
            }
        )
    return out


def assert_loggable_slug(db: Session, slug: str) -> str:
    """Return validated slug or raise 403 (no existence leak for unknown paths)."""
    raw = (slug or "").strip()
    if not raw or not _SAFE_SLUG.match(raw):
        raise HTTPException(status_code=403, detail="Forbidden")
    allowed = {a["slug"] for a in list_loggable_apps(db)}
    if raw not in allowed:
        raise HTTPException(status_code=403, detail="Forbidden")
    return raw


def access_log_path(settings: Settings, slug: str) -> Path:
    root = resolve_nginx_app_logs_dir(settings).resolve()
    path = (root / f"{slug}.access.log").resolve()
    if path != root and root not in path.parents:
        raise HTTPException(status_code=403, detail="Forbidden")
    return path


def read_access_log_tail(
    settings: Settings,
    slug: str,
    *,
    lines: int | None = None,
) -> str:
    """Return last N lines of the access log (empty string if file missing)."""
    n = lines if lines is not None else _DEFAULT_TAIL
    n = max(1, min(int(n), _MAX_TAIL))
    path = access_log_path(settings, slug)
    if not path.is_file():
        return ""
    try:
        raw = path.read_bytes()
    except OSError:
        logger.exception("nginx access log read failed slug=%s", slug)
        raise HTTPException(status_code=502, detail="Access log unavailable") from None
    text = raw.decode("utf-8", errors="replace")
    parts = text.splitlines()
    if len(parts) <= n:
        return "\n".join(parts) + ("\n" if parts else "")
    return "\n".join(parts[-n:]) + "\n"


async def iter_access_log_follow(
    settings: Settings,
    slug: str,
    *,
    lines: int | None = None,
    poll_seconds: float = 0.8,
) -> AsyncIterator[str]:
    """Yield new lines appended to the access log (poll-based follow)."""
    path = access_log_path(settings, slug)
    initial = read_access_log_tail(settings, slug, lines=lines)
    if initial:
        yield initial
    offset = 0
    try:
        if path.is_file():
            offset = path.stat().st_size
    except OSError:
        offset = 0
    while True:
        await asyncio.sleep(poll_seconds)
        try:
            if not path.is_file():
                continue
            size = path.stat().st_size
            if size < offset:
                # Log rotated — re-emit recent tail.
                offset = 0
                chunk = read_access_log_tail(settings, slug, lines=lines)
                if chunk:
                    yield chunk
                offset = path.stat().st_size if path.is_file() else 0
                continue
            if size == offset:
                continue
            with path.open("rb") as fh:
                fh.seek(offset)
                data = fh.read()
            offset = size
            if data:
                yield data.decode("utf-8", errors="replace")
        except OSError:
            logger.exception("nginx access log follow failed slug=%s", slug)
            break
