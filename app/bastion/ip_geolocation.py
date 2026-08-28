"""IP geolocation via ip-api.com (batch + file cache, rate-limit aware)."""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from app.sso_settings import Settings

logger = logging.getLogger(__name__)

CACHE_SCHEMA_VERSION = 1
BATCH_MAX = 100
DEFAULT_FIELDS = (
    "status,message,country,countryCode,regionName,city,isp,org,query,proxy,hosting"
)
USER_AGENT = "BastionPro-WAF/1.0"

_lock = threading.Lock()
_rate_remaining: int | None = None
_rate_reset_at: float = 0.0
_cache_mtime: float = 0.0
_cache_data: dict[str, Any] | None = None


def clear_geoloc_state_for_tests() -> None:
    """Reset in-memory cache and rate-limit state (pytest)."""
    global _rate_remaining, _rate_reset_at, _cache_mtime, _cache_data
    with _lock:
        _rate_remaining = None
        _rate_reset_at = 0.0
        _cache_mtime = 0.0
        _cache_data = None


def country_flag(country_code: str | None) -> str:
    code = (country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code)


def is_public_ip(ip: str) -> bool:
    raw = (ip or "").strip()
    if not raw or raw == "—":
        return False
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def _cache_path(settings: Settings) -> Path:
    root = Path(settings.portal_data_dir) / "cache"
    root.mkdir(parents=True, exist_ok=True)
    return root / "ip-geoloc-v1.json"


def _load_cache(settings: Settings) -> dict[str, Any]:
    global _cache_mtime, _cache_data
    path = _cache_path(settings)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {"schema_version": CACHE_SCHEMA_VERSION, "entries": {}}
    with _lock:
        if _cache_data is not None and mtime == _cache_mtime:
            return _cache_data
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raw = {"schema_version": CACHE_SCHEMA_VERSION, "entries": {}}
    if raw.get("schema_version") != CACHE_SCHEMA_VERSION:
        raw = {"schema_version": CACHE_SCHEMA_VERSION, "entries": {}}
    entries = raw.setdefault("entries", {})
    if not isinstance(entries, dict):
        raw["entries"] = {}
    with _lock:
        _cache_data = raw
        _cache_mtime = mtime
    return raw


def _save_cache(settings: Settings, data: dict[str, Any]) -> None:
    global _cache_mtime, _cache_data
    path = _cache_path(settings)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    with _lock:
        _cache_data = data
        try:
            _cache_mtime = path.stat().st_mtime
        except OSError:
            _cache_mtime = time.time()


def _cache_ttl_seconds(settings: Settings) -> int:
    hours = int(getattr(settings, "ip_geoloc_cache_ttl_hours", 168) or 168)
    return max(1, hours) * 3600


def _cached_entry(entries: dict[str, Any], ip: str, ttl: int) -> dict[str, Any] | None:
    row = entries.get(ip)
    if not isinstance(row, dict):
        return None
    fetched = row.get("fetched_at")
    data = row.get("data")
    if not isinstance(data, dict):
        return None
    if not fetched:
        return data
    try:
        ts = datetime.fromisoformat(str(fetched).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - ts).total_seconds()
        if age > ttl:
            return None
    except (TypeError, ValueError):
        return None
    return data


def _rate_limit_blocked() -> bool:
    global _rate_remaining, _rate_reset_at
    if _rate_remaining is not None and _rate_remaining <= 0:
        if time.time() < _rate_reset_at:
            return True
    return False


def _update_rate_limit_headers(headers: httpx.Headers) -> None:
    global _rate_remaining, _rate_reset_at
    rl = headers.get("X-Rl")
    ttl = headers.get("X-Ttl")
    try:
        if rl is not None:
            _rate_remaining = int(rl)
        if ttl is not None:
            _rate_reset_at = time.time() + max(0, int(ttl))
    except ValueError:
        pass


def _fetch_batch(
    settings: Settings, ips: list[str]
) -> dict[str, dict[str, Any]]:
    if not ips:
        return {}
    base = (getattr(settings, "ip_geoloc_base_url", None) or "http://ip-api.com").rstrip(
        "/"
    )
    lang = getattr(settings, "ip_geoloc_lang", "fr") or "fr"
    url = f"{base}/batch?fields={DEFAULT_FIELDS}&lang={lang}"
    try:
        with httpx.Client(timeout=httpx.Timeout(4.0), follow_redirects=True) as client:
            response = client.post(
                url,
                json=ips,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": USER_AGENT,
                },
            )
            _update_rate_limit_headers(response.headers)
            if response.status_code == 429:
                logger.warning("ip-api.com rate limit (429) — using cache/fallback")
                return {}
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, json.JSONDecodeError, TypeError) as exc:
        logger.warning("ip-api.com batch failed: %s", exc)
        return {}

    out: dict[str, dict[str, Any]] = {}
    if not isinstance(payload, list):
        return out
    for item in payload:
        if not isinstance(item, dict):
            continue
        query = str(item.get("query") or "").strip()
        if query:
            out[query] = item
    return out


def lookup_ip_origins(settings: Settings, ips: list[str]) -> dict[str, dict[str, Any]]:
    """Resolve public IPs to ip-api.com records (cached, batch)."""
    if not getattr(settings, "ip_geoloc_enabled", True):
        return {}

    unique: list[str] = []
    seen: set[str] = set()
    for raw in ips:
        ip = (raw or "").strip()
        if not is_public_ip(ip) or ip in seen:
            continue
        seen.add(ip)
        unique.append(ip)
    if not unique:
        return {}

    cache = _load_cache(settings)
    entries: dict[str, Any] = cache.setdefault("entries", {})
    ttl = _cache_ttl_seconds(settings)
    result: dict[str, dict[str, Any]] = {}
    missing: list[str] = []

    for ip in unique:
        hit = _cached_entry(entries, ip, ttl)
        if hit is not None:
            result[ip] = hit
        else:
            missing.append(ip)

    if missing and not _rate_limit_blocked():
        for offset in range(0, len(missing), BATCH_MAX):
            chunk = missing[offset : offset + BATCH_MAX]
            fetched = _fetch_batch(settings, chunk)
            now = datetime.now(timezone.utc).isoformat()
            for ip in chunk:
                data = fetched.get(ip)
                if data is None:
                    data = {"status": "fail", "message": "unavailable", "query": ip}
                entries[ip] = {"fetched_at": now, "data": data}
                result[ip] = data
        _save_cache(settings, cache)
    elif missing:
        logger.info(
            "ip-api.com rate limit active — %d IP(s) without fresh geoloc",
            len(missing),
        )

    return result


def origin_from_geoloc(
    ip: str, geo: dict[str, Any] | None, *, fallback: dict[str, str] | None = None
) -> dict[str, str]:
    """Merge ip-api record with network fallback label."""
    base = fallback or _network_fallback(ip)
    if not geo or geo.get("status") != "success":
        return base
    city = str(geo.get("city") or "").strip()
    country = str(geo.get("country") or "").strip()
    cc = str(geo.get("countryCode") or "").strip().upper()
    region = str(geo.get("regionName") or "").strip()
    isp = str(geo.get("isp") or "").strip()
    parts = [p for p in (city, region, country) if p]
    hint = ", ".join(dict.fromkeys(parts)) or base.get("hint", "Internet")
    if isp and isp not in hint:
        hint = f"{hint} · {isp}"
    return {
        **base,
        "hint": hint[:120],
        "flag": country_flag(cc),
        "country": country,
        "country_code": cc,
        "city": city,
        "isp": isp,
        "proxy": "1" if geo.get("proxy") else "",
        "hosting": "1" if geo.get("hosting") else "",
    }


def _network_fallback(ip: str) -> dict[str, str]:
    """Heuristic origin when geoloc is unavailable."""
    raw = (ip or "").strip()
    if not raw or raw == "—":
        return {
            "network": "—",
            "hint": "Inconnu",
            "flag": "🌐",
            "country": "",
            "country_code": "",
            "city": "",
            "isp": "",
        }
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return {
            "network": raw[:16],
            "hint": "Invalide",
            "flag": "🌐",
            "country": "",
            "country_code": "",
            "city": "",
            "isp": "",
        }
    if addr.is_private or addr.is_loopback:
        return {
            "network": str(addr),
            "hint": "Réseau interne",
            "flag": "🏠",
            "country": "",
            "country_code": "",
            "city": "",
            "isp": "",
        }
    if isinstance(addr, ipaddress.IPv4Address):
        parts = raw.split(".")
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else raw
    else:
        network = raw
    return {
        "network": network,
        "hint": "Internet",
        "flag": "🌐",
        "country": "",
        "country_code": "",
        "city": "",
        "isp": "",
    }


def collect_waf_dashboard_ips(
    settings: Settings,
    db: Any | None,
    *,
    summary: dict[str, Any] | None = None,
) -> list[str]:
    """IPs to geolocate for the WAF dashboard (recent events, bans, unknown hosts)."""
    from app.bastion.modsec_audit_aggregator import read_audit_summary
    from app.security.banning.service import list_active_bans

    ips: list[str] = []
    seen: set[str] = set()

    def add(raw: str | None) -> None:
        ip = (raw or "").strip()
        if ip and ip != "—" and ip not in seen:
            seen.add(ip)
            ips.append(ip)

    data = summary if summary is not None else read_audit_summary(settings)
    for ev in data.get("recent_events") or []:
        if isinstance(ev, dict):
            add(str(ev.get("client_ip") or ""))
    window = (data.get("windows") or {}).get("24h") or {}
    for atk in window.get("top_attackers") or []:
        if isinstance(atk, dict):
            add(str(atk.get("ip") or ""))

    if db is not None:
        from app.models import PendingHost
        from datetime import timedelta

        since = datetime.now(timezone.utc) - timedelta(hours=24)
        rows = (
            db.query(PendingHost.last_client_ip)
            .filter(PendingHost.last_seen_at >= since, PendingHost.last_client_ip.isnot(None))
            .distinct()
            .limit(50)
            .all()
        )
        for row in rows:
            add(str(row.last_client_ip or ""))
        for ban in list_active_bans(db):
            if ban.target_type == "ip":
                add(str(ban.target or ""))

    return ips
