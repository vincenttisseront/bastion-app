"""Declarative machine-to-machine (M2M) policy for subdomain_proxy apps.

No product-name heuristics: flags and path lists live on the App row and are
configured in the admin UI. Upstream must authenticate when Bastion skips SSO.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.access_modes import normalize_access_mode

MAX_BYPASS_PATHS = 32
MAX_PATH_LEN = 256

# Characters that would turn a path into an nginx regex / injection hazard.
_FORBIDDEN_PATH_CHARS = re.compile(r"[*?\[\]{}()\\<>\s\"'`|;$]")

# Teleport agent paths historically hard-coded — used only by one-shot migration seed.
TELEPORT_SEED_BYPASS_PATHS: tuple[str, ...] = (
    "/webapi/find",
    "/webapi/ping",
    "/webapi/connectionupgrade",
    "/webapi/host/",
    "/v1/webapi/",
    "/v2/webapi/",
)


def path_only(uri: str) -> str:
    raw = (uri or "").split("?", 1)[0].strip() or "/"
    if not raw.startswith("/"):
        raw = f"/{raw}"
    # Collapse duplicate slashes; keep a single leading slash.
    while "//" in raw:
        raw = raw.replace("//", "/")
    return raw or "/"


def parse_bypass_paths(raw: str | list[str] | None) -> list[str]:
    """Parse JSON list or newline-separated UI text into a path list (unvalidated)."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    text = str(raw).strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, list):
            return [str(x).strip() for x in data if str(x).strip()]
    return [ln.strip() for ln in text.replace("\r\n", "\n").split("\n") if ln.strip()]


def serialize_bypass_paths(paths: list[str]) -> str | None:
    cleaned = [p for p in paths if p]
    if not cleaned:
        return None
    return json.dumps(cleaned, ensure_ascii=False)


def validate_bypass_path(path: str) -> str | None:
    """Return normalized path or None if invalid."""
    p = path_only(path)
    if p == "/":
        return None
    if len(p) > MAX_PATH_LEN:
        return None
    if _FORBIDDEN_PATH_CHARS.search(p):
        return None
    # No scheme / host smuggling
    if "://" in p or p.startswith("//"):
        return None
    return p


def normalize_bypass_paths(
    raw: str | list[str] | None,
) -> tuple[list[str], list[str]]:
    """Return ``(valid_paths, error_messages)``."""
    errors: list[str] = []
    seen: set[str] = set()
    out: list[str] = []
    for item in parse_bypass_paths(raw):
        norm = validate_bypass_path(item)
        if norm is None:
            errors.append(f"Chemin M2M invalide : {item!r}")
            continue
        if norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    if len(out) > MAX_BYPASS_PATHS:
        errors.append(f"Maximum {MAX_BYPASS_PATHS} chemins M2M sans SSO.")
        out = out[:MAX_BYPASS_PATHS]
    return out, errors


def m2m_flags_for(
    access_mode: str | None,
    *,
    m2m_accept_basic: bool = False,
    m2m_accept_bearer: bool = False,
    m2m_bypass_paths: str | list[str] | None = None,
    m2m_bypass_long_timeout: bool = False,
) -> dict[str, Any]:
    """Coerce M2M fields: only meaningful on subdomain_proxy."""
    if normalize_access_mode(access_mode) != "subdomain_proxy":
        return {
            "m2m_accept_basic": False,
            "m2m_accept_bearer": False,
            "m2m_bypass_paths": None,
            "m2m_bypass_long_timeout": False,
        }
    paths, _errs = normalize_bypass_paths(m2m_bypass_paths)
    return {
        "m2m_accept_basic": bool(m2m_accept_basic),
        "m2m_accept_bearer": bool(m2m_accept_bearer),
        "m2m_bypass_paths": serialize_bypass_paths(paths),
        "m2m_bypass_long_timeout": bool(m2m_bypass_long_timeout) and bool(paths),
    }


def bypass_paths_for_app(app: Any) -> list[str]:
    raw = getattr(app, "m2m_bypass_paths", None)
    paths, _ = normalize_bypass_paths(raw)
    return paths


def uri_matches_bypass(uri: str, paths: list[str]) -> bool:
    """True when request path equals an exact entry or sits under a prefix entry."""
    req = path_only(uri).rstrip("/") or "/"
    for entry in paths:
        if entry.endswith("/"):
            prefix = entry.rstrip("/") or "/"
            if req == prefix or req.startswith(prefix + "/"):
                return True
            # Also match the bare prefix with trailing slash form
            if path_only(uri).startswith(entry):
                return True
        else:
            exact = entry.rstrip("/") or "/"
            if req == exact:
                return True
    return False


def app_uri_is_m2m_bypass(app: Any, uri: str) -> bool:
    return uri_matches_bypass(uri, bypass_paths_for_app(app))


def authorization_scheme(header: str | None) -> str | None:
    """Return ``basic`` / ``bearer`` / None from an Authorization header value."""
    raw = (header or "").strip()
    if not raw:
        return None
    parts = raw.split(None, 1)
    if not parts:
        return None
    scheme = parts[0].lower()
    if scheme in ("basic", "bearer") and len(parts) >= 2 and parts[1].strip():
        return scheme
    return None


def m2m_credential_allows(app: Any, authorization_header: str | None) -> str | None:
    """
    If the app accepts this Authorization scheme for M2M, return auth source tag
    (``m2m-basic`` / ``m2m-bearer``); else None.
    """
    scheme = authorization_scheme(authorization_header)
    if scheme == "basic" and bool(getattr(app, "m2m_accept_basic", False)):
        return "m2m-basic"
    if scheme == "bearer" and bool(getattr(app, "m2m_accept_bearer", False)):
        return "m2m-bearer"
    return None


def nginx_location_specs(paths: list[str]) -> list[tuple[str, str]]:
    """
    Map declared paths to nginx location directives.

    Returns list of ``(modifier_and_path, kind)`` where kind is ``exact`` or ``prefix``.
    Exact paths also get a trailing-slash twin when they do not already end with ``/``.
    """
    specs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for p in paths:
        if p.endswith("/"):
            key = f"^~ {p}"
            if key not in seen:
                seen.add(key)
                specs.append((key, "prefix"))
        else:
            for form in (p, f"{p}/"):
                key = f"= {form}"
                if key not in seen:
                    seen.add(key)
                    specs.append((key, "exact"))
    return specs
