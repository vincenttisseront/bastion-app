"""Incremental ModSecurity audit log aggregator for WAF UI (lot 4 / lot 3 shared).

Reads ``modsec_audit.log`` incrementally (offset + inode), maintains hourly buckets,
writes pre-computed ``waf-audit-summary.json``. Never invoked per HTTP request.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.sso_settings import Settings

logger = logging.getLogger(__name__)

SUMMARY_SCHEMA_VERSION = 1
STATE_SCHEMA_VERSION = 1
MAX_RECENT_EVENTS = 100
TOP_N = 5

# Short CRS labels for common rules (lot 4 readability; extend over time).
CRS_RULE_LABELS: dict[str, str] = {
    "942100": "Injection SQL",
    "941100": "XSS (tag)",
    "941110": "XSS (script)",
    "930100": "Traversée de répertoire",
    "932100": "Injection commande OS",
    "913100": "Scanner / sonde",
    "920350": "Méthode HTTP anormale",
}


def resolve_modsec_audit_log_path(settings: Settings) -> Path:
    env = os.environ.get("BASTION_MODSEC_AUDIT_LOG_PATH", "").strip()
    if env:
        return Path(env)
    logs_dir = (settings.nginx_app_logs_dir or "").strip()
    if not logs_dir:
        logs_dir = str(Path(settings.portal_data_dir) / "nginx-logs")
    return Path(logs_dir) / "modsec_audit.log"


def resolve_aggregator_state_path(settings: Settings) -> Path:
    logs_dir = resolve_modsec_audit_log_path(settings).parent
    return logs_dir / "waf-audit-aggregator-state.json"


def resolve_audit_summary_path(settings: Settings) -> Path:
    logs_dir = resolve_modsec_audit_log_path(settings).parent
    return logs_dir / "waf-audit-summary.json"


def _rule_label(rule_id: str) -> str:
    rid = str(rule_id).strip()
    return CRS_RULE_LABELS.get(rid, f"Règle CRS {rid}")


def _rule_family(rule_id: str) -> str:
    rid = str(rule_id).strip()
    if not rid.isdigit():
        return "autre"
    prefix = rid[:3]
    if prefix == "942":
        return "sqli"
    if prefix == "941":
        return "xss"
    if prefix in ("932", "933"):
        return "rce"
    if prefix == "930":
        return "lfi"
    if prefix == "913":
        return "scanner"
    return "autre"


RULE_FAMILY_LABELS = {
    "sqli": "SQLi",
    "xss": "XSS",
    "rce": "RCE",
    "lfi": "LFI",
    "scanner": "Scanner",
    "autre": "Autre",
}


def _parse_audit_timestamp(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _hour_key(dt: datetime) -> str:
    return dt.strftime("%Y%m%d%H")


def _empty_bucket() -> dict[str, Any]:
    return {
        "inspected": 0,
        "detections": 0,
        "blocks": 0,
        "rules": {},
        "hosts": {},
        "families": {},
        "attackers": {},
        "critical": 0,
    }


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def _file_identity(path: Path) -> tuple[int, int]:
    st = path.stat()
    return int(st.st_ino), int(st.st_size)


def _parse_audit_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None

    tx = data.get("transaction") or {}
    if not isinstance(tx, dict):
        tx = {}

    req = tx.get("request") or {}
    headers = req.get("headers") or {}
    host = ""
    if isinstance(headers, dict):
        for key, val in headers.items():
            if str(key).lower() == "host":
                host = val[0] if isinstance(val, list) and val else str(val)
                break

    client_ip = ""
    for key in ("client_ip", "remote_address", "remote_addr"):
        raw = tx.get(key)
        if raw:
            client_ip = str(raw).strip()
            break
    if not client_ip and isinstance(headers, dict):
        for key, val in headers.items():
            if str(key).lower() in ("x-forwarded-for", "x-real-ip", "cf-connecting-ip"):
                v = val[0] if isinstance(val, list) and val else str(val)
                client_ip = v.split(",")[0].strip()
                break

    messages = tx.get("messages") or []
    rule_ids: list[str] = []
    max_score = 0
    msg_text = ""
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            details = msg.get("details") or {}
            rid = details.get("ruleId") or details.get("rule_id")
            if rid is not None:
                rule_ids.append(str(rid))
            sev = details.get("severity")
            try:
                if sev is not None:
                    max_score = max(max_score, int(sev))
            except (TypeError, ValueError):
                pass
            if not msg_text and msg.get("message"):
                msg_text = str(msg.get("message"))[:200]

    response = tx.get("response") or {}
    http_code = response.get("http_code") if isinstance(response, dict) else None
    try:
        code = int(http_code) if http_code is not None else None
    except (TypeError, ValueError):
        code = None

    blocked = code in (403, 406) or any(
        "denied" in str((m or {}).get("message", "")).lower()
        for m in (messages if isinstance(messages, list) else [])
        if isinstance(m, dict)
    )

    ts = _parse_audit_timestamp(tx.get("time_stamp") or tx.get("timestamp"))
    families = [_rule_family(rid) for rid in rule_ids]
    critical = any(f in ("sqli", "xss", "rce", "lfi") for f in families)

    return {
        "timestamp": ts,
        "client_ip": client_ip or "—",
        "host": host.strip().lower() or "—",
        "uri": (req.get("uri") or "—") if isinstance(req, dict) else "—",
        "rule_ids": rule_ids,
        "score": max_score,
        "blocked": blocked,
        "has_detection": bool(rule_ids),
        "message": msg_text,
        "critical": critical,
        "families": families,
    }


def _merge_event_into_bucket(bucket: dict[str, Any], event: dict[str, Any]) -> None:
    bucket["inspected"] += 1
    if event.get("has_detection"):
        bucket["detections"] += 1
    if event.get("blocked"):
        bucket["blocks"] += 1
    if event.get("critical"):
        bucket["critical"] = int(bucket.get("critical") or 0) + 1
    rules: dict[str, int] = bucket.setdefault("rules", {})
    for rid in event.get("rule_ids") or []:
        rules[rid] = int(rules.get(rid, 0)) + 1
        if event.get("has_detection"):
            fam = _rule_family(str(rid))
            families: dict[str, int] = bucket.setdefault("families", {})
            families[fam] = int(families.get(fam, 0)) + 1
    host = event.get("host") or "—"
    hosts: dict[str, int] = bucket.setdefault("hosts", {})
    hosts[host] = int(hosts.get(host, 0)) + 1
    if event.get("has_detection"):
        ip = event.get("client_ip") or "—"
        attackers: dict[str, int] = bucket.setdefault("attackers", {})
        attackers[ip] = int(attackers.get(ip, 0)) + 1


def _prune_hourly(hourly: dict[str, Any], *, keep_days: int = 7) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
    cutoff_key = _hour_key(cutoff)
    for key in list(hourly.keys()):
        if key < cutoff_key:
            hourly.pop(key, None)


def _sum_window(hourly: dict[str, Any], hours: int) -> dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_key = _hour_key(cutoff)
    inspected = detections = blocks = critical = 0
    rules: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    attackers: Counter[str] = Counter()
    fam_counter: Counter[str] = Counter()
    for key, bucket in hourly.items():
        if key < cutoff_key:
            continue
        if not isinstance(bucket, dict):
            continue
        inspected += int(bucket.get("inspected") or 0)
        detections += int(bucket.get("detections") or 0)
        blocks += int(bucket.get("blocks") or 0)
        critical += int(bucket.get("critical") or 0)
        for rid, count in (bucket.get("rules") or {}).items():
            rules[str(rid)] += int(count)
        for host, count in (bucket.get("hosts") or {}).items():
            hosts[str(host)] += int(count)
        for ip, count in (bucket.get("attackers") or {}).items():
            attackers[str(ip)] += int(count)
        for fam, count in (bucket.get("families") or {}).items():
            fam_counter[str(fam)] += int(count)

    block_rate = round((blocks / inspected) * 100, 1) if inspected else 0.0
    top_rules = [
        {"rule_id": rid, "label": _rule_label(rid), "count": cnt}
        for rid, cnt in rules.most_common(TOP_N)
    ]
    top_hosts = [{"host": h, "count": cnt} for h, cnt in hosts.most_common(TOP_N)]
    top_attackers = [{"ip": ip, "count": cnt} for ip, cnt in attackers.most_common(TOP_N)]
    rule_families = [
        {"family": fam, "label": RULE_FAMILY_LABELS.get(fam, fam), "count": cnt}
        for fam, cnt in fam_counter.most_common()
    ]

    return {
        "inspected": inspected,
        "detections": detections,
        "blocks": blocks,
        "critical": critical,
        "block_rate_pct": block_rate,
        "top_rules": top_rules,
        "top_hosts": top_hosts,
        "top_attackers": top_attackers,
        "rule_families": rule_families,
    }


def _hourly_series(hourly: dict[str, Any], hours: int) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    series: list[dict[str, Any]] = []
    for i in range(hours - 1, -1, -1):
        dt = now - timedelta(hours=i)
        key = _hour_key(dt)
        bucket = hourly.get(key) or {}
        series.append(
            {
                "key": key,
                "label": dt.strftime("%Hh"),
                "detections": int(bucket.get("detections") or 0),
                "inspected": int(bucket.get("inspected") or 0),
            }
        )
    return series


def _daily_series(hourly: dict[str, Any], days: int) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    series: list[dict[str, Any]] = []
    for i in range(days - 1, -1, -1):
        day = (now - timedelta(days=i)).date()
        day_key = day.strftime("%Y%m%d")
        detections = inspected = 0
        for key, bucket in hourly.items():
            if not str(key).startswith(day_key):
                continue
            if not isinstance(bucket, dict):
                continue
            detections += int(bucket.get("detections") or 0)
            inspected += int(bucket.get("inspected") or 0)
        series.append(
            {
                "key": day_key,
                "label": day.strftime("%d/%m"),
                "detections": detections,
                "inspected": inspected,
            }
        )
    return series


def run_aggregation(settings: Settings) -> dict[str, Any]:
    """Incremental pass over modsec_audit.log; update state + summary JSON."""
    log_path = resolve_modsec_audit_log_path(settings)
    state_path = resolve_aggregator_state_path(settings)
    summary_path = resolve_audit_summary_path(settings)

    state = _load_json(state_path)
    if state.get("schema_version") != STATE_SCHEMA_VERSION:
        state = {"schema_version": STATE_SCHEMA_VERSION, "hourly": {}, "recent_events": []}

    hourly: dict[str, Any] = state.setdefault("hourly", {})
    recent: list[dict[str, Any]] = state.setdefault("recent_events", [])
    file_state = (state.setdefault("files", {})).get(str(log_path)) or {}

    if not log_path.is_file():
        summary = {
            "schema_version": SUMMARY_SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "log_available": False,
            "log_path": str(log_path),
            "windows": {},
            "recent_events": [],
            "status": "unavailable",
            "status_message": "Journal d'audit ModSecurity absent — données indisponibles.",
        }
        _save_json(summary_path, summary)
        return summary

    try:
        inode, size = _file_identity(log_path)
    except OSError as exc:
        logger.warning("modsec audit stat failed: %s", exc)
        return _load_json(summary_path)

    offset = int(file_state.get("offset") or 0)
    prev_inode = file_state.get("inode")
    prev_size = int(file_state.get("size") or 0)
    if prev_inode is not None and int(prev_inode) != inode:
        offset = 0
    elif size < offset or size < prev_size:
        offset = 0

    try:
        with log_path.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read()
            new_offset = fh.tell()
    except OSError as exc:
        logger.warning("modsec audit read failed: %s", exc)
        return _load_json(summary_path)

    text = chunk.decode("utf-8", errors="replace")
    lines = text.splitlines()
    partial = state.get("partial_line") or ""
    if partial:
        lines[0] = partial + lines[0]
        partial = ""
    if text and not text.endswith("\n") and lines:
        partial = lines.pop()

    for line in lines:
        event = _parse_audit_line(line)
        if event is None:
            continue
        ts = event.get("timestamp") or datetime.now(timezone.utc)
        if not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)
        key = _hour_key(ts)
        bucket = hourly.setdefault(key, _empty_bucket())
        _merge_event_into_bucket(bucket, event)

        recent.append(
            {
                "timestamp": ts.isoformat(),
                "client_ip": event.get("client_ip"),
                "host": event.get("host"),
                "uri": event.get("uri"),
                "rule_id": (event.get("rule_ids") or ["—"])[0],
                "score": event.get("score") or 0,
                "blocked": bool(event.get("blocked")),
                "critical": bool(event.get("critical")),
                "message": event.get("message") or "",
                "families": list(event.get("families") or []),
            }
        )

    if len(recent) > MAX_RECENT_EVENTS:
        recent[:] = recent[-MAX_RECENT_EVENTS:]

    _prune_hourly(hourly)
    state["partial_line"] = partial
    state["files"][str(log_path)] = {"inode": inode, "offset": new_offset, "size": size}
    state["recent_events"] = recent
    _save_json(state_path, state)

    window_24h = _sum_window(hourly, 24)
    window_7d = _sum_window(hourly, 24 * 7)
    series_24h = _hourly_series(hourly, 24)
    series_7d = _daily_series(hourly, 7)

    summary = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "log_available": True,
        "log_path": str(log_path),
        "windows": {"24h": window_24h, "7d": window_7d},
        "series": {"24h": series_24h, "7d": series_7d},
        "recent_events": list(recent[-20:]),
        "status": "ok",
        "status_message": None,
        "aggregator": {
            "state_path": str(state_path),
            "summary_path": str(summary_path),
            "log_offset": new_offset,
            "log_size": size,
            "log_inode": inode,
        },
    }
    _save_json(summary_path, summary)
    return summary


def read_aggregator_state(settings: Settings) -> dict[str, Any]:
    path = resolve_aggregator_state_path(settings)
    data = _load_json(path)
    if not data:
        return {"present": False}
    data["present"] = True
    data["path"] = str(path)
    file_states = data.get("files") or {}
    log_path = str(resolve_modsec_audit_log_path(settings))
    data["log_file_state"] = file_states.get(log_path) or {}
    return data


def read_audit_summary(settings: Settings) -> dict[str, Any]:
    """Read pre-computed summary only (UI hot path)."""
    path = resolve_audit_summary_path(settings)
    data = _load_json(path)
    if not data:
        return {
            "present": False,
            "log_available": False,
            "status": "unavailable",
            "status_message": "Données d'efficacité indisponibles — agrégateur pas encore exécuté.",
        }
    data["present"] = True
    data.setdefault("log_available", path.parent.joinpath("modsec_audit.log").is_file())
    return data
