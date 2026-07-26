"""SIEM event formatters — CEF (syslog) and ECS-like JSON (webhook)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from app.web.constants import APP_VERSION

VENDOR = "iBanFirst"
PRODUCT = "BastionPro-Sentinel"

# CEF extension values escape: \ = |
_CEF_ESCAPE = re.compile(r"([\\|=])")

# Practical syslog payload budget (bytes) for cs1 + framing overhead.
_CEF_CS1_MAX = 3500


def cef_severity(result: str | None) -> int:
    r = (result or "info").strip().lower()
    if r == "error":
        return 7
    if r == "success":
        return 1
    return 3


def _cef_escape(value: str) -> str:
    return _CEF_ESCAPE.sub(r"\\\1", value.replace("\n", " ").replace("\r", " "))


def _iso_ts(entry: dict[str, Any]) -> str:
    raw = (entry.get("timestamp") or "").strip()
    if raw.endswith(" UTC"):
        raw = raw[: -len(" UTC")].strip()
        try:
            dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def format_cef(entry: dict[str, Any], *, version: str | None = None) -> str:
    """Map audit entry → CEF:0|… string (syslog_tls transport)."""
    ver = version or APP_VERSION
    action = str(entry.get("action") or "unknown")
    result = str(entry.get("result") or "info")
    sev = cef_severity(result)
    desc = action.replace("|", "_")[:128]
    detail = _detail_object(entry)
    compact = json.dumps(detail, ensure_ascii=False, separators=(",", ":"))
    truncated = False
    if len(compact.encode("utf-8")) > _CEF_CS1_MAX:
        # Truncate on character boundary with explicit marker.
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
        f"{_cef_escape(action)}|{_cef_escape(desc)}|{sev}"
    )
    return header + "|" + " ".join(extensions)


def format_ecs(entry: dict[str, Any], *, version: str | None = None) -> dict[str, Any]:
    """Map audit entry → ECS-like JSON (webhook_https transport, no truncation)."""
    action = str(entry.get("action") or "unknown")
    result = str(entry.get("result") or "info")
    category = ["authentication"] if "login" in action or "breakglass" in action or "session" in action else ["api"]
    return {
        "@timestamp": _iso_ts(entry),
        "event": {
            "action": action,
            "outcome": result,
            "kind": "event",
            "category": category,
            "id": str(entry.get("id") or ""),
        },
        "user": {"name": str(entry.get("actor") or "")},
        "source": {"ip": str(entry.get("ip_address") or "")},
        "bastion": {
            "target": entry.get("target") or "",
            "detail": _detail_object(entry),
        },
        "observer": {
            "product": PRODUCT,
            "vendor": VENDOR,
            "version": version or APP_VERSION,
        },
    }


def format_ecs_json(entry: dict[str, Any], *, version: str | None = None) -> str:
    return json.dumps(format_ecs(entry, version=version), ensure_ascii=False)
