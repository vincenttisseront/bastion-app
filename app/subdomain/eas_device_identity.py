"""Human-readable identity for an ActiveSync device sighting.

EAS gives us three opaque strings — DeviceId, DeviceType, User-Agent — and
nothing like a marketing name. This module turns them into labels an admin can
actually use to tell two phones of the same user apart, and extracts the Apple
serial when the DeviceId carries one (``Appl`` + serial is the common iOS form).
"""

from __future__ import annotations

import re

# Product-type tokens seen in Apple EAS User-Agents (``Apple-iPhone14,5/…``).
# Keep the map short: unknown tokens still surface as raw ``iPhone14,5``.
_APPLE_PRODUCT_TYPES: dict[str, str] = {
    "iPhone10,1": "iPhone 8",
    "iPhone10,2": "iPhone 8 Plus",
    "iPhone10,3": "iPhone X",
    "iPhone10,4": "iPhone 8",
    "iPhone10,5": "iPhone 8 Plus",
    "iPhone10,6": "iPhone X",
    "iPhone11,2": "iPhone XS",
    "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max",
    "iPhone11,8": "iPhone XR",
    "iPhone12,1": "iPhone 11",
    "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max",
    "iPhone12,8": "iPhone SE (2e gén.)",
    "iPhone13,1": "iPhone 12 mini",
    "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro",
    "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13",
    "iPhone14,6": "iPhone SE (3e gén.)",
    "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16",
    "iPhone17,4": "iPhone 16 Plus",
    "iPad13,1": "iPad Air (4e gén.)",
    "iPad13,2": "iPad Air (4e gén.)",
    "iPad13,4": "iPad Pro 11\" (3e gén.)",
    "iPad13,16": "iPad Air (5e gén.)",
    "iPad14,1": "iPad mini (6e gén.)",
}

_APPLE_PRODUCT_RE = re.compile(
    r"Apple-(?P<kind>iPhone|iPad|iPod)(?P<product>\d+,\d+)?(?:C\d+)?/(?P<build>[\d.]+)",
    re.I,
)
_APPL_SERIAL_RE = re.compile(r"^Appl(?P<serial>[A-Za-z0-9]{8,20})$", re.I)
# Bare serials on some iOS builds (no ``Appl`` prefix) — Apple serials are 10–12.
_BARE_APPLE_SERIAL_RE = re.compile(r"^[A-Z0-9]{10,12}$", re.I)
_APPLE_DEVICE_TYPES = frozenset({"iphone", "ipad", "ipod"})
_CLIENT_KIND_LABELS = {
    "iphone": "iPhone",
    "ipad": "iPad",
    "apple_mail": "Apple Mail",
    "outlook": "Outlook",
    "android": "Android",
    "activesync_generic": "ActiveSync",
    "other": "Autre",
}


def apple_serial_from_device_id(
    device_id: str | None,
    *,
    device_type: str | None = None,
    client_kind: str | None = None,
) -> str | None:
    """Serial embedded in an iOS EAS DeviceId, when we can tell it apart from noise."""
    raw = (device_id or "").strip()
    if not raw:
        return None
    match = _APPL_SERIAL_RE.match(raw)
    if match:
        return match.group("serial")
    kind = (device_type or client_kind or "").strip().lower()
    if kind in _APPLE_DEVICE_TYPES and _BARE_APPLE_SERIAL_RE.match(raw):
        return raw
    return None


def describe_eas_device(
    *,
    device_id: str | None = None,
    device_type: str | None = None,
    user_agent: str | None = None,
    client_kind: str | None = None,
    friendly_name: str | None = None,
) -> dict[str, str | None]:
    """Labels for admin tables / fiche — never invents hardware we did not see."""
    device_id = (device_id or "").strip() or None
    device_type = (device_type or "").strip() or None
    user_agent = (user_agent or "").strip() or None
    client_kind = (client_kind or "").strip() or None
    friendly_name = (friendly_name or "").strip() or None

    serial = apple_serial_from_device_id(
        device_id, device_type=device_type, client_kind=client_kind
    )
    model_label, ua_summary = _model_from_user_agent(user_agent)
    if not model_label and device_type:
        model_label = device_type
    if not model_label and client_kind:
        model_label = _CLIENT_KIND_LABELS.get(client_kind, client_kind)

    if friendly_name:
        display_name = friendly_name
    elif model_label and serial:
        display_name = f"{model_label} · {serial}"
    elif model_label and device_id:
        short = device_id if len(device_id) <= 14 else f"{device_id[:8]}…{device_id[-4:]}"
        display_name = f"{model_label} · {short}"
    elif serial:
        display_name = serial
    elif device_id:
        display_name = device_id if len(device_id) <= 14 else f"{device_id[:8]}…{device_id[-4:]}"
    else:
        display_name = "Appareil"

    identity_bits = [b for b in (model_label, device_type, ua_summary) if b]
    # Drop duplicates while preserving order (DeviceType often equals model).
    seen: set[str] = set()
    identity_line_parts: list[str] = []
    for bit in identity_bits:
        key = bit.lower()
        if key in seen:
            continue
        seen.add(key)
        identity_line_parts.append(bit)

    return {
        "display_name": display_name,
        "apple_serial": serial,
        "model_label": model_label,
        "ua_summary": ua_summary,
        "identity_line": " · ".join(identity_line_parts) or None,
        "client_kind_label": (
            _CLIENT_KIND_LABELS.get(client_kind, client_kind) if client_kind else None
        ),
    }


def _model_from_user_agent(user_agent: str | None) -> tuple[str | None, str | None]:
    raw = (user_agent or "").strip()
    if not raw:
        return None, None

    match = _APPLE_PRODUCT_RE.search(raw)
    if match:
        kind = match.group("kind")
        product = match.group("product")
        build = match.group("build")
        token = f"{kind}{product}" if product else kind
        model = _APPLE_PRODUCT_TYPES.get(token, token)
        summary = f"{model}" + (f" · build {build}" if build else "")
        return model, summary

    lower = raw.lower()
    if "outlook" in lower:
        return "Outlook", raw[:64] + ("…" if len(raw) > 64 else "")
    if "android" in lower:
        return "Android", raw[:64] + ("…" if len(raw) > 64 else "")
    if len(raw) <= 64:
        return None, raw
    return None, raw[:64] + "…"
