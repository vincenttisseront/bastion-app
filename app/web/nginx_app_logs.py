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

# Bastion nginx ``log_format app`` (see docker/nginx/nginx.conf).
# remote_user may contain spaces (ActiveSync: ``A.R. Systems\user@…``).
# Fixed head + flexible trailing kv (old and new formats parse the same way).
_APP_ACCESS_HEAD_RE = re.compile(
    r"^(?P<remote_addr>\S+) - (?P<remote_user>.+?) \[(?P<time_local>[^\]]+)\] "
    r"host=(?P<host>\S+) \"(?P<request>[^\"]*)\" (?P<status>\d+) (?P<body_bytes_sent>\S+) "
    r"\"(?P<referer>[^\"]*)\" \"(?P<user_agent>[^\"]*)\"\s*(?P<kv>.*)$"
)
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S*))')
_NGINX_HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")

# Short nginx log keys → entry field names.
_KV_ALIASES: dict[str, str] = {
    "rt": "request_time",
    "uct": "upstream_connect_time",
    "uht": "upstream_header_time",
    "ut": "upstream_response_time",
    "upstream": "upstream_addr",
    "us": "upstream_status",
    "req_len": "request_length",
    "xff": "x_forwarded_for",
    "xpci": "x_portal_client_ip",
    "proto": "forwarded_proto",
    "rid": "request_id",
    "auth_err": "auth_err",
    "auth_email": "auth_email",
    "auth_user": "auth_user",
    "auth_app": "auth_app",
    "auth_src": "auth_source",
    "auth_pref": "auth_preferred",
}

_EMPTY_META_FIELDS = (
    "request_time",
    "upstream_connect_time",
    "upstream_header_time",
    "upstream_response_time",
    "upstream_addr",
    "upstream_status",
    "request_length",
    "x_forwarded_for",
    "x_portal_client_ip",
    "forwarded_proto",
    "request_id",
    "auth_err",
    "auth_email",
    "auth_user",
    "auth_app",
    "auth_source",
    "auth_preferred",
)


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


def describe_access_log(settings: Settings, slug: str) -> dict[str, object]:
    """Admin diagnostics for why Accès apps may appear empty."""
    root = resolve_nginx_app_logs_dir(settings)
    try:
        root_resolved = root.resolve()
    except OSError:
        root_resolved = root
    path = access_log_path(settings, slug)
    exists = False
    size = 0
    try:
        exists = path.is_file()
        if exists:
            size = int(path.stat().st_size)
    except OSError:
        exists = False
        size = 0
    siblings: list[str] = []
    root_exists = False
    try:
        root_exists = root_resolved.is_dir()
        if root_exists:
            siblings = sorted(p.name for p in root_resolved.glob("*.access.log"))[:40]
    except OSError:
        root_exists = False
    if exists and size > 0:
        hint = ""
    elif exists and size == 0:
        hint = (
            "Fichier présent mais vide : le vhost nginx n'a pas encore écrit de ligne, "
            "ou le trafic n'atteint pas bastion-nginx (DNS/Traefik direct)."
        )
    elif root_exists and siblings:
        hint = (
            f"Autres access.log visibles ({', '.join(siblings[:5])}"
            f"{'…' if len(siblings) > 5 else ''}) — vérifier le slug de l'app."
        )
    elif root_exists:
        hint = (
            "Répertoire nginx-logs monté mais aucun *.access.log : recreer bastion-nginx "
            "avec le volume partagé, puis générer du trafic via le FQDN public."
        )
    else:
        hint = (
            "Répertoire nginx-logs absent côté bastion-app. "
            "docker compose up -d --force-recreate nginx bastion-app "
            "(volume …/nginx-logs → /var/log/nginx/apps)."
        )
    return {
        "path": str(path),
        "root": str(root_resolved),
        "root_exists": root_exists,
        "exists": exists,
        "size_bytes": size,
        "sibling_access_logs": siblings,
        "hint": hint,
    }


def empty_access_log_message(settings: Settings, slug: str) -> str:
    meta = describe_access_log(settings, slug)
    lines = [
        "(fichier d'accès vide ou absent)",
        f"chemin: {meta['path']}",
        f"existe: {'oui' if meta['exists'] else 'non'} · taille: {meta['size_bytes']} o",
    ]
    siblings = meta.get("sibling_access_logs") or []
    if siblings:
        lines.append("autres: " + ", ".join(str(s) for s in siblings[:8]))
    hint = str(meta.get("hint") or "").strip()
    if hint:
        lines.append(f"astuce: {hint}")
    return "\n".join(lines) + "\n"


def _split_request(request: str) -> tuple[str, str, str]:
    parts = (request or "").split()
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    if len(parts) == 1:
        return "", parts[0], ""
    return "", "", ""


def _decode_nginx_escapes(value: str) -> str:
    """Decode nginx-style ``\\xNN`` escapes (e.g. ``\\x5C`` → ``\\``)."""
    if not value or "\\x" not in value:
        return value

    def _repl(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return _NGINX_HEX_ESCAPE_RE.sub(_repl, value)


def _status_class(status: str) -> str:
    try:
        status_i = int(status)
    except ValueError:
        return "muted"
    if 200 <= status_i < 300:
        return "ok"
    if 300 <= status_i < 400:
        return "warn"
    if status_i >= 400:
        return "err"
    return "muted"


def _parse_kv_tail(kv: str) -> dict[str, str]:
    """Map trailing ``key=value`` / ``key="value"`` tokens to entry fields."""
    out = {name: "" for name in _EMPTY_META_FIELDS}
    for short, quoted, bare in _KV_RE.findall(kv or ""):
        field = _KV_ALIASES.get(short)
        if field:
            out[field] = quoted if quoted else bare
    return out


def _entry_from_groups(
    raw: str,
    g: dict[str, str],
    *,
    index: int,
    parse_ok: bool,
) -> dict[str, object]:
    method, path, protocol = _split_request(g.get("request") or "")
    status = g.get("status") or ""
    upstream = g.get("upstream_addr") or ""
    is_internal = upstream.startswith("127.0.0.1:") or upstream.startswith("[::1]:")
    remote_user = _decode_nginx_escapes(g.get("remote_user") or "")
    client_ip = (g.get("x_portal_client_ip") or "").strip() or (g.get("remote_addr") or "")
    return {
        "id": f"{index}-{g.get('time_local') or 't'}-{status}-{path[:48]}",
        "parse_ok": parse_ok,
        "ecosystem": "nginx_access",
        "raw": raw,
        "remote_addr": g.get("remote_addr") or "",
        "client_ip": client_ip,
        "remote_user": remote_user,
        "time_local": g.get("time_local") or "",
        "host": g.get("host") or "",
        "method": method,
        "path": path,
        "protocol": protocol,
        "request": g.get("request") or "",
        "status": status,
        "status_class": _status_class(status),
        "body_bytes_sent": g.get("body_bytes_sent") or "",
        "referer": g.get("referer") or "",
        "user_agent": g.get("user_agent") or "",
        "request_time": g.get("request_time") or "",
        "upstream_connect_time": g.get("upstream_connect_time") or "",
        "upstream_header_time": g.get("upstream_header_time") or "",
        "upstream_response_time": g.get("upstream_response_time") or "",
        "upstream_addr": upstream,
        "upstream_status": g.get("upstream_status") or "",
        "request_length": g.get("request_length") or "",
        "x_forwarded_for": g.get("x_forwarded_for") or "",
        "x_portal_client_ip": g.get("x_portal_client_ip") or "",
        "forwarded_proto": g.get("forwarded_proto") or "",
        "request_id": g.get("request_id") or "",
        "auth_err": g.get("auth_err") or "",
        "auth_email": g.get("auth_email") or "",
        "auth_user": g.get("auth_user") or "",
        "auth_app": g.get("auth_app") or "",
        "auth_source": g.get("auth_source") or "",
        "auth_preferred": g.get("auth_preferred") or "",
        "is_internal_hop": is_internal,
    }


def parse_app_access_line(line: str, *, index: int = 0) -> dict[str, object] | None:
    """Parse one nginx ``log_format app`` line into a structured dict."""
    raw = (line or "").rstrip("\r\n")
    if not raw.strip():
        return None
    m = _APP_ACCESS_HEAD_RE.match(raw)
    if m:
        g = m.groupdict()
        kv = g.pop("kv", "") or ""
        g.update(_parse_kv_tail(kv))
        return _entry_from_groups(raw, g, index=index, parse_ok=True)
    empty = {name: "" for name in _EMPTY_META_FIELDS}
    return {
        "id": f"raw-{index}",
        "parse_ok": False,
        "ecosystem": "nginx_access",
        "raw": raw,
        "remote_addr": "",
        "client_ip": "",
        "remote_user": "",
        "time_local": "",
        "host": "",
        "method": "",
        "path": "",
        "protocol": "",
        "request": raw,
        "status": "",
        "status_class": "muted",
        "body_bytes_sent": "",
        "referer": "",
        "user_agent": "",
        **empty,
        "is_internal_hop": False,
    }


def parse_app_access_text(text: str) -> list[dict[str, object]]:
    """Parse multi-line access log text (newest last, as stored by nginx)."""
    out: list[dict[str, object]] = []
    for i, line in enumerate((text or "").splitlines()):
        entry = parse_app_access_line(line, index=i)
        if entry is not None:
            out.append(entry)
    return out


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
