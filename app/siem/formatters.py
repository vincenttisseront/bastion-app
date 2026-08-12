"""SIEM event formatters — CEF (syslog) and ECS-like JSON (webhook)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from app.audit.event_catalog import (
    CEF_SEVERITY,
    Severity,
    get_event_by_code,
    historical_severity_from_result,
    resolve_event,
)
from app.web.constants import APP_VERSION

VENDOR = "iBanFirst"
PRODUCT = "BastionPro-Sentinel"

# CEF extension values escape: \ = |
_CEF_ESCAPE = re.compile(r"([\\|=])")

# Practical syslog payload budget (bytes) for cs1 + framing overhead.
_CEF_CS1_MAX = 3500


def catalog_severity_for_entry(entry: dict[str, Any]) -> Severity:
    """Resolve catalogue severity for a serialized audit entry."""
    code = (entry.get("event_code") or "").strip()
    raw_sev = (entry.get("catalog_severity") or entry.get("severity_catalog") or "").strip()
    if raw_sev:
        try:
            return Severity(raw_sev.upper())
        except ValueError:
            pass
    if code:
        ev = get_event_by_code(code)
        if ev is not None:
            return ev.severity
        if code.endswith("-0000"):
            return Severity.WARNING
    # Historical fallback from result bucket
    return historical_severity_from_result(str(entry.get("result") or "info"))


def cef_severity(entry_or_result: dict[str, Any] | str | None) -> int:
    """CEF severity 0-10 from catalogue criticité (not from result alone)."""
    if isinstance(entry_or_result, dict):
        sev = catalog_severity_for_entry(entry_or_result)
        return CEF_SEVERITY[sev]
    # Legacy callers passing result string — map conservatively via historical rule
    sev = historical_severity_from_result(str(entry_or_result or "info"))
    return CEF_SEVERITY[sev]


def _cef_escape(value: str) -> str:
    return _CEF_ESCAPE.sub(r"\\\1", value.replace("\n", " ").replace("\r", " "))


def _iso_ts(entry: dict[str, Any]) -> str:
    raw = (entry.get("timestamp") or "").strip()
    if raw.endswith(" UTC"):
        raw = raw[: -len(" UTC")].strip()
        try:
            dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _detail_object(entry: dict[str, Any]) -> Any:
    """Prefer structured detail from payload; fall back to parsing detail_full."""
    if "detail" in entry and isinstance(entry["detail"], (dict, list)):
        return entry["detail"]
    full = entry.get("detail_full") or ""
    if isinstance(full, (dict, list)):
        return full
    if isinstance(full, str) and full.strip().startswith(("{", "[")):
        try:
            return json.loads(full)
        except json.JSONDecodeError:
            return {"raw": full}
    if full:
        return {"raw": full}
    return {}


def _resolve_code_label(entry: dict[str, Any]) -> tuple[str, str, list[str]]:
    action = str(entry.get("action") or "unknown")
    code = (entry.get("event_code") or "").strip()
    label = (entry.get("event_label") or "").strip()
    cats = entry.get("ecs_category") if isinstance(entry.get("ecs_category"), list) else None
    if code and label:
        return code, label, list(cats or [])
    ev = resolve_event(action=action, code=code or None)
    return ev.code, ev.label, list(ev.ecs_category)


def format_cef(entry: dict[str, Any], *, version: str | None = None) -> str:
    """Map audit entry → CEF:0|… string (syslog_tls transport)."""
    ver = version or APP_VERSION
    action = str(entry.get("action") or "unknown")
    result = str(entry.get("result") or "info")
    code, label, _cats = _resolve_code_label(entry)
    sev = cef_severity(entry)
    desc = label.replace("|", "_")[:128] or action.replace("|", "_")[:128]
    detail = _detail_object(entry)
    compact = json.dumps(detail, ensure_ascii=False, separators=(",", ":"))
    truncated = False
    if len(compact.encode("utf-8")) > _CEF_CS1_MAX:
        encoded = compact.encode("utf-8")[: _CEF_CS1_MAX - 32]
        compact = encoded.decode("utf-8", errors="ignore") + "…[truncated]"
        truncated = True
    rt = _iso_ts(entry)
    suser = _cef_escape(str(entry.get("actor") or ""))
    src = _cef_escape(str(entry.get("ip_address") or ""))
    outcome = _cef_escape(result)
    cs1 = _cef_escape(compact)
    extensions = [
        f"rt={_cef_escape(rt)}",
        f"suser={suser}",
        f"src={src}",
        f"outcome={outcome}",
        "cs1Label=detail",
        f"cs1={cs1}",
    ]
    if truncated:
        extensions.append("cs2Label=truncated")
        extensions.append("cs2=true")
    header = (
        f"CEF:0|{VENDOR}|{PRODUCT}|{_cef_escape(ver)}|"
        f"{_cef_escape(code)}|{_cef_escape(desc)}|{sev}"
    )
    return header + "|" + " ".join(extensions)


def format_ecs(entry: dict[str, Any], *, version: str | None = None) -> dict[str, Any]:
    """Map audit entry → ECS-like JSON (webhook_https transport, no truncation)."""
    action = str(entry.get("action") or "unknown")
    result = str(entry.get("result") or "info")
    code, label, cats = _resolve_code_label(entry)
    sev = catalog_severity_for_entry(entry)
    if not cats:
        cats = (
            ["authentication"]
            if "login" in action or "breakglass" in action or "session" in action
            else ["api"]
        )
    return {
        "@timestamp": _iso_ts(entry),
        "event": {
            "code": code,
            "action": label,
            "outcome": result,
            "kind": "event",
            "category": cats,
            "severity": CEF_SEVERITY[sev],
            "id": str(entry.get("id") or ""),
        },
        "log": {"level": sev.value.lower()},
        "user": {"name": str(entry.get("actor") or "")},
        "source": {"ip": str(entry.get("ip_address") or "")},
        "bastion": {
            "target": entry.get("target") or "",
            "detail": _detail_object(entry),
            "legacy_action": action,
            "domain": entry.get("domain") or (code.split("-")[1] if code.count("-") >= 2 else ""),
        },
        "observer": {
            "vendor": VENDOR,
            "product": PRODUCT,
            "version": version or APP_VERSION,
        },
    }


def format_ecs_json(entry: dict[str, Any], *, version: str | None = None) -> str:
    return json.dumps(format_ecs(entry, version=version), ensure_ascii=False)
