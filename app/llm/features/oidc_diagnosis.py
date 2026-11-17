"""Idea 6 — read the "Test OIDC" result and point at the probable fix.

Input is the check list the existing test already returned (names, statuses,
messages) plus the issuer URL and client id. The client secret is never sent.
Fallback: the technical check messages shown today.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.llm.insights import STATUS_INFO, generate_insight
from app.sso_settings import Settings

_CHECK_NAMES = {"discovery", "metadata", "issuer_match", "jwks", "client_credentials"}
_STATUSES = {"ok", "warning", "error", "warn"}

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "probable_cause": {"type": "string", "maxLength": 600},
        "fix_steps": {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 6},
        "field_to_check": {
            "type": "string",
            "enum": ["issuer_url", "client_id", "client_secret", "keycloak", "reseau", "aucun"],
        },
        "confidence": {"type": "string", "enum": ["faible", "moyenne", "elevee"]},
    },
    "required": ["probable_cause", "fix_steps", "field_to_check", "confidence"],
    "additionalProperties": False,
}

INSTRUCTIONS = (
    "Un administrateur configure un realm Keycloak (OIDC) dans le portail Bastion "
    "et le test de connexion a échoué ou averti. À partir des étapes du test "
    "(discovery .well-known, métadonnées, cohérence de l'issuer, JWKS, client "
    "credentials), indique la cause la plus probable et la correction concrète "
    "(ex. URL d'issuer sans /realms/<nom>, http au lieu de https, client "
    "confidentiel non activé, mauvais secret, service account désactivé, "
    "pare-feu/DNS). Réponse brève et actionnable."
)


def sanitize_checks(checks: Any) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for c in (checks or [])[:10]:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or "")[:40]
        status = str(c.get("status") or "")[:10]
        if name not in _CHECK_NAMES or status not in _STATUSES:
            continue
        out.append({"name": name, "status": status, "message": str(c.get("message") or "")[:300]})
    return out


async def diagnose_oidc_test(
    db: Session,
    settings: Settings,
    *,
    issuer_url: str,
    client_id: str,
    checks: Any,
    realm_id: int | None = None,
    requested_by: str | None = None,
) -> Any:
    clean = sanitize_checks(checks)
    if not clean or all(c["status"] == "ok" for c in clean):
        return None
    parts = urlsplit((issuer_url or "").strip())
    data = {
        "issuer_url": (issuer_url or "").strip()[:300],
        "issuer_scheme": parts.scheme,
        "issuer_path": parts.path,
        "client_id": (client_id or "").strip()[:120],
        "etapes_du_test": clean,
    }
    return await generate_insight(
        db,
        kind="oidc_diagnosis",
        subject_type="realm" if realm_id else "realm_draft",
        subject_id=realm_id or (client_id or "draft")[:120],
        instructions=INSTRUCTIONS,
        data=data,
        schema=SCHEMA,
        status=STATUS_INFO,
        requested_by=requested_by,
        settings=settings,
    )
