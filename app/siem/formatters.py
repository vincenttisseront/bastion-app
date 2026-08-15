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
from app.subdomain.eas_device import device_id_from_detail
from app.web.constants import APP_VERSION

VENDOR = "Bastion"
PRODUCT = "BastionPro-Sentinel"

# CEF extension values MUST escape: backslash, equals, pipe (ArcSight CEF).
# Order in the character class does not matter — single-pass replacement is fine.
_CEF_ESCAPE = re.compile(r"([\\|=])")

# Practical syslog payload budget (bytes) for cs1 + framing overhead.
_CEF_CS1_MAX = 3500

_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)
# Markdown / mail-client artefacts sometimes leak into pasted or proxied values.
_MAILTO_RE = re.compile(r"\[?\s*mailto:([^\]\s?]+)\s*\]?", re.IGNORECASE)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


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
    """Escape CEF extension (and header) reserved characters: \\ = |."""
    return _CEF_ESCAPE.sub(r"\\\1", value.replace("\n", " ").replace("\r", " "))


def _strip_mailto_artifacts(value: str) -> str:
    """Remove ``mailto:`` / ``[mailto:…]`` wrappers if a client injected them."""
    prev = None
    out = value
    while prev != out:
        prev = out
        out = _MAILTO_RE.sub(r"\1", out)
    return out


def _iso_ts(entry: dict[str, Any]) -> str:
    raw = (entry.get("timestamp") or "").strip()
    if raw.endswith("UTC"):
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


def _looks_like_email(value: str) -> bool:
    return bool(_EMAIL_RE.fullmatch(value.strip()))


def _looks_like_uuid(value: str) -> bool:
    return bool(_UUID_RE.match(value.strip()))


def _extract_email(text: str) -> str | None:
    m = _EMAIL_RE.search(text or "")
    return m.group(0) if m else None


def canonical_siem_actor(entry: dict[str, Any]) -> tuple[str, str | None]:
    """Return ``(suser, display_name)`` for SIEM correlation.

    Preference order for the stable key:
    1. ``details.keycloak_user_id`` / ``sub`` (UUID)
    2. email in details (``email`` / ``user_email`` / email-shaped ``username``)
    3. email extracted from the display ``actor`` string
    4. raw actor (last resort)

    Display names (everything else in ``actor``) go to the optional second value
    so CEF can put them in ``cs3`` without polluting ``suser``.
    """
    detail = _detail_object(entry)
    detail_dict = detail if isinstance(detail, dict) else {}

    raw_actor = _strip_mailto_artifacts(str(entry.get("actor") or "")).strip()
    display: str | None = None

    kc = detail_dict.get("keycloak_user_id") or detail_dict.get("sub")
    if isinstance(kc, str) and _looks_like_uuid(kc):
        # Keep a human label when actor is not the UUID itself.
        if raw_actor and not _looks_like_uuid(raw_actor):
            email_in_actor = _extract_email(raw_actor)
            if email_in_actor and raw_actor != email_in_actor:
                display = raw_actor.replace(email_in_actor, "").strip(" -|,;") or None
            elif not _looks_like_email(raw_actor):
                display = raw_actor
        return kc.strip(), display

    for key in ("email", "user_email", "actor_email"):
        cand = detail_dict.get(key)
        if isinstance(cand, str) and _looks_like_email(_strip_mailto_artifacts(cand)):
            email = _strip_mailto_artifacts(cand).strip()
            if raw_actor and raw_actor != email and not _looks_like_uuid(raw_actor):
                if email in raw_actor:
                    display = raw_actor.replace(email, "").strip(" -|,;") or None
                elif not _looks_like_email(raw_actor):
                    display = raw_actor
            return email, display

    username = detail_dict.get("username")
    if isinstance(username, str):
        cleaned = _strip_mailto_artifacts(username).strip()
        if _looks_like_email(cleaned):
            if raw_actor and raw_actor != cleaned and cleaned in raw_actor:
                display = raw_actor.replace(cleaned, "").strip(" -|,;") or None
            return cleaned, display

    if raw_actor and _looks_like_email(raw_actor):
        return raw_actor, None

    if raw_actor and _looks_like_uuid(raw_actor):
        return raw_actor, None

    email_in_actor = _extract_email(raw_actor) if raw_actor else None
    if email_in_actor:
        remainder = raw_actor.replace(email_in_actor, "").strip(" -|,;") or None
        return email_in_actor, remainder

    return raw_actor or "unknown", None


def _device_id_from_detail(detail: Any) -> str | None:
    """Promote ActiveSync DeviceId to a first-class CEF field when present."""
    return device_id_from_detail(detail)


def _sanitize_detail_for_siem(detail: Any) -> Any:
    """Strip mailto artefacts from string leaves; keep structure intact."""
    if isinstance(detail, dict):
        return {k: _sanitize_detail_for_siem(v) for k, v in detail.items()}
    if isinstance(detail, list):
        return [_sanitize_detail_for_siem(v) for v in detail]
    if isinstance(detail, str):
        return _strip_mailto_artifacts(detail)
    return detail


def format_cef(entry: dict[str, Any], *, version: str | None = None) -> str:
    """Map audit entry → CEF:0|… string (syslog_tls transport)."""
    ver = version or APP_VERSION
    action = str(entry.get("action") or "unknown")
    result = str(entry.get("result") or "info")
    code, label, _cats = _resolve_code_label(entry)
    sev = cef_severity(entry)
    desc = label.replace("|", "_")[:128] or action.replace("|", "_")[:128]
    detail = _sanitize_detail_for_siem(_detail_object(entry))
    compact = json.dumps(detail, ensure_ascii=False, separators=(",", ":"))
    truncated = False
    if len(compact.encode("utf-8")) > _CEF_CS1_MAX:
        encoded = compact.encode("utf-8")[: _CEF_CS1_MAX - 32]
        compact = encoded.decode("utf-8", errors="ignore") + "…[truncated]"
        truncated = True
    rt = _iso_ts(entry)
    suser, display_name = canonical_siem_actor(entry)
    src = _cef_escape(str(entry.get("ip_address") or ""))
    outcome = _cef_escape(result)
    cs1 = _cef_escape(compact)
    extensions = [
        f"rt={_cef_escape(rt)}",
        f"suser={_cef_escape(suser)}",
        f"src={src}",
        f"outcome={outcome}",
        "cs1Label=detail",
        f"cs1={cs1}",
    ]
    if display_name:
        extensions.append("cs3Label=displayName")
        extensions.append(f"cs3={_cef_escape(display_name)}")
    device_id = _device_id_from_detail(detail)
    if device_id:
        # Intentional: ActiveSync DeviceId is a stable terminal identifier.
        extensions.append(f"deviceExternalId={_cef_escape(device_id)}")
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
    suser, display_name = canonical_siem_actor(entry)
    detail = _sanitize_detail_for_siem(_detail_object(entry))
    user: dict[str, Any] = {"name": suser}
    if _looks_like_email(suser):
        user["email"] = suser
    if _looks_like_uuid(suser):
        user["id"] = suser
    if display_name:
        user["full_name"] = display_name
    device_id = _device_id_from_detail(detail)
    doc: dict[str, Any] = {
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
        "user": user,
        "source": {"ip": str(entry.get("ip_address") or "")},
        "bastion": {
            "target": entry.get("target") or "",
            "detail": detail,
            "legacy_action": action,
            "domain": entry.get("domain") or (code.split("-")[1] if code.count("-") >= 2 else ""),
        },
        "observer": {
            "vendor": VENDOR,
            "product": PRODUCT,
            "version": version or APP_VERSION,
        },
    }
    if device_id:
        doc["device"] = {"id": device_id}
    return doc


def format_ecs_json(entry: dict[str, Any], *, version: str | None = None) -> str:
    return json.dumps(format_ecs(entry, version=version), ensure_ascii=False)
