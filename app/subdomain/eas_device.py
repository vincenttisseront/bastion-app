"""Exchange ActiveSync device identification from the request URI.

Pure parsing helpers — no DB, no ORM, no FastAPI — so both the auth_request
handler and the SIEM formatter can share one implementation.

Two wire formats exist for the EAS query string (MS-ASHTTP):
  - plain: ``?User=…&DeviceId=…&DeviceType=iPhone&Cmd=Ping``
  - base64: ``?jAAJBBCgAAAA…`` — a binary blob, length-prefixed fields.

Every function is fail-safe: an unparsable request yields ``None`` rather than
raising, because a device we cannot identify must never be denied.
"""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import parse_qs, urlsplit

# DeviceId is an opaque client-generated token: never lowercased, only bounded.
MAX_DEVICE_ID_LEN = 128
MAX_DEVICE_TYPE_LEN = 64

_DEVICE_ID_KEYS = ("DeviceId", "deviceId", "device_id", "DeviceID", "deviceid")
_DEVICE_TYPE_KEYS = ("DeviceType", "deviceType", "device_type", "devicetype")

_AUTODISCOVER_PATH_RE = re.compile(r"(?i)^/(AutoDiscover|autodiscover)(/|$)")
_ACTIVESYNC_PATH_RE = re.compile(r"(?i)^/Microsoft-Server-ActiveSync")

# A base64 query has no key/value separator and no parameter separator; '=' may
# only appear as trailing padding.
_BASE64_QUERY_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")

# Why no device could be extracted. Reported on the unidentified audit event so
# the gap can be diagnosed instead of merely counted.
MISS_NONE = "none"
MISS_NO_QUERY = "no_query"
MISS_NAMED_QUERY_WITHOUT_DEVICE_ID = "named_query_without_device_id"
MISS_QUERY_NOT_BASE64 = "query_not_base64"
MISS_BASE64_UNDECODABLE = "base64_undecodable"
MISS_BASE64_TRUNCATED = "base64_truncated"
MISS_BASE64_EMPTY_DEVICE_ID = "base64_empty_device_id"
MISS_PARSE_ERROR = "parse_error"

# The two families decide opposite things before the per-device gate is armed:
# a decoder failure is ours to fix, while a client that sends no DeviceId at all
# will still send none after any fix — it is the one that gets cut on switchover.
MISS_FAMILY_NONE = "none"
MISS_FAMILY_DECODER = "decoder_failure"
MISS_FAMILY_NO_DEVICE_SENT = "no_device_sent"

_MISS_FAMILIES: dict[str, str] = {
    MISS_NONE: MISS_FAMILY_NONE,
    MISS_BASE64_UNDECODABLE: MISS_FAMILY_DECODER,
    MISS_BASE64_TRUNCATED: MISS_FAMILY_DECODER,
    MISS_QUERY_NOT_BASE64: MISS_FAMILY_DECODER,
    MISS_PARSE_ERROR: MISS_FAMILY_DECODER,
    MISS_NO_QUERY: MISS_FAMILY_NO_DEVICE_SENT,
    MISS_NAMED_QUERY_WITHOUT_DEVICE_ID: MISS_FAMILY_NO_DEVICE_SENT,
    MISS_BASE64_EMPTY_DEVICE_ID: MISS_FAMILY_NO_DEVICE_SENT,
}


def miss_family(miss_reason: str) -> str:
    """Group a ``MISS_*`` reason into the family that drives the decision."""
    return _MISS_FAMILIES.get(miss_reason, MISS_FAMILY_DECODER)

# Enough for a real MS-ASHTTP blob (typically 40-90 chars) without turning the
# audit table into a request log.
QUERY_SAMPLE_MAX = 120


def split_query(uri: str) -> str:
    """Query part of an absolute-path URI (nginx ``$request_uri``)."""
    if not uri:
        return ""
    query = urlsplit(uri).query
    if not query and "?" in uri:
        query = uri.split("?", 1)[1]
    return query


def path_of(uri: str) -> str:
    return (uri or "/").split("?", 1)[0]


def is_autodiscover_uri(uri: str) -> bool:
    return bool(_AUTODISCOVER_PATH_RE.match(path_of(uri)))


def is_activesync_path(uri: str) -> bool:
    return bool(_ACTIVESYNC_PATH_RE.match(path_of(uri)))


def _clean(value: str | None, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped[:limit] if stripped else None


def _from_plain_query(query: str) -> tuple[str | None, str | None]:
    params = parse_qs(query, keep_blank_values=False)
    device_id = None
    for key in _DEVICE_ID_KEYS:
        values = params.get(key) or []
        if values:
            device_id = _clean(values[0], MAX_DEVICE_ID_LEN)
            if device_id:
                break
    device_type = None
    for key in _DEVICE_TYPE_KEYS:
        values = params.get(key) or []
        if values:
            device_type = _clean(values[0], MAX_DEVICE_TYPE_LEN)
            if device_type:
                break
    return device_id, device_type


def _b64decode(query: str) -> bytes | None:
    candidate = query.strip()
    if not candidate or not _BASE64_QUERY_RE.match(candidate):
        return None
    candidate = candidate.rstrip("=")
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        return base64.urlsafe_b64decode(padded.replace("+", "-").replace("/", "_"))
    except (binascii.Error, ValueError):
        return None


def _from_base64_query(query: str) -> tuple[str | None, str | None, str]:
    """Decode the MS-ASHTTP base64 query, reporting why it failed.

    Layout: protocol version (1), command code (1), locale (2), then
    length-prefixed DeviceID, policy key and DeviceType. DeviceID is binary and
    conventionally rendered as uppercase hex by EAS servers.
    """
    raw = _b64decode(query)
    if raw is None:
        return None, None, MISS_BASE64_UNDECODABLE
    if len(raw) < 6:
        return None, None, MISS_BASE64_TRUNCATED

    pos = 4  # skip version, command code, locale
    device_id_len = raw[pos]
    pos += 1
    if device_id_len == 0:
        return None, None, MISS_BASE64_EMPTY_DEVICE_ID
    if pos + device_id_len > len(raw):
        return None, None, MISS_BASE64_TRUNCATED
    device_id = raw[pos : pos + device_id_len].hex().upper()
    pos += device_id_len

    if pos >= len(raw):
        return _clean(device_id, MAX_DEVICE_ID_LEN), None, MISS_NONE
    policy_key_len = raw[pos]
    pos += 1 + policy_key_len

    if pos >= len(raw):
        return _clean(device_id, MAX_DEVICE_ID_LEN), None, MISS_NONE
    device_type_len = raw[pos]
    pos += 1
    device_type = None
    if device_type_len and pos + device_type_len <= len(raw):
        device_type = raw[pos : pos + device_type_len].decode("ascii", errors="replace")

    return (
        _clean(device_id, MAX_DEVICE_ID_LEN),
        _clean(device_type, MAX_DEVICE_TYPE_LEN),
        MISS_NONE,
    )


def _extract(uri: str) -> tuple[str | None, str | None, str]:
    try:
        query = split_query(uri)
        if not query:
            return None, None, MISS_NO_QUERY
        device_id, device_type = _from_plain_query(query)
        if device_id:
            return device_id, device_type, MISS_NONE
        # Shape first: base64 padding ends in '=', which a naive key=value test
        # mistakes for a named parameter.
        if _BASE64_QUERY_RE.match(query.strip()):
            return _from_base64_query(query)
        if "=" in query:
            return None, None, MISS_NAMED_QUERY_WITHOUT_DEVICE_ID
        return None, None, MISS_QUERY_NOT_BASE64
    except Exception:  # parsing must never break the auth path
        return None, None, MISS_PARSE_ERROR


def extract_eas_device(uri: str) -> tuple[str | None, str | None]:
    """``(device_id, device_type)`` from an EAS URI. Never raises."""
    device_id, device_type, _miss = _extract(uri)
    return device_id, device_type


def explain_eas_device_miss(uri: str) -> str:
    """Why ``extract_eas_device`` found nothing — ``MISS_*``, ``"none"`` on success.

    The unidentified counter says how many requests we fail to identify; this
    says which of the parsing paths gave up, which is what tells us whether the
    decoder is wrong or the client simply sent no device.
    """
    return _extract(uri)[2]


def query_sample(uri: str, limit: int = QUERY_SAMPLE_MAX) -> str | None:
    """Bounded, explicitly-truncated copy of the raw query for diagnostics.

    Only ever attached to unidentified requests: the query carries
    DeviceId/DeviceType/User, which the allow log already records in clear for
    the non-encoded form. Credentials travel in ``Authorization``, never here,
    and the request body (which holds mail content) is never touched.
    """
    try:
        query = split_query(uri)
    except Exception:
        return None
    if not query:
        return None
    return query[:limit] + "…" if len(query) > limit else query


def device_id_from_detail(detail: object) -> str | None:
    """DeviceId from an audit detail dict — explicit keys first, then the URI."""
    if not isinstance(detail, dict):
        return None
    for key in _DEVICE_ID_KEYS:
        value = _clean(detail.get(key), MAX_DEVICE_ID_LEN)
        if value:
            return value
    uri = detail.get("uri")
    if not isinstance(uri, str):
        return None
    device_id, _device_type = extract_eas_device(uri)
    return device_id
