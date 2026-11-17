"""Idea 2 — explain a WAF event and, when it looks like a false positive,
propose a narrowly scoped exclusion for an admin to validate.

The proposal is re-checked against the event (same rule id, same host, an
excludable CRS rule, a valid scope) before it is shown; applying it still goes
through the existing ``/admin/security/waf/actions/exclude-rule`` form and the
WAF "Apply" step. Fallback: the raw event, unchanged.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy.orm import Session

from app.llm.insights import STATUS_INFO, STATUS_PROPOSED, generate_insight
from app.sso_settings import Settings

_SCOPES = ["rule", "args", "args_names", "cookies", "headers"]
_URI_MATCH = ["exact", "prefix"]
_EVENT_FIELDS = (
    "timestamp", "client_ip", "host", "uri", "rule_id", "all_rule_ids", "message",
    "score", "blocked", "families", "matched_scope_kind", "matched_target_name",
)

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "explanation": {"type": "string", "maxLength": 1200},
        "rule_summary": {"type": "string", "maxLength": 400},
        "legitimacy": {
            "type": "string",
            "enum": ["faux_positif_probable", "attaque_probable", "indetermine"],
        },
        "confidence": {"type": "string", "enum": ["faible", "moyenne", "elevee"]},
        "propose_exclusion": {"type": "boolean"},
        "exclusion": {
            "type": "object",
            "properties": {
                "crs_rule_id": {"type": "integer"},
                "scope_kind": {"type": "string", "enum": _SCOPES},
                "target_name": {"type": "string", "maxLength": 128},
                "uri_pattern": {"type": "string", "maxLength": 256},
                "uri_match": {"type": "string", "enum": _URI_MATCH},
                "reason": {"type": "string", "maxLength": 200},
            },
            "required": ["crs_rule_id", "scope_kind", "target_name", "uri_pattern", "uri_match", "reason"],
            "additionalProperties": False,
        },
        "risks": {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 5},
    },
    "required": [
        "explanation", "rule_summary", "legitimacy", "confidence",
        "propose_exclusion", "exclusion", "risks",
    ],
    "additionalProperties": False,
}

INSTRUCTIONS = (
    "Explique à un administrateur pourquoi le pare-feu applicatif (ModSecurity + "
    "OWASP CRS) a déclenché cet événement : ce que détecte la règle, ce qui dans "
    "la requête l'a probablement déclenchée, et si c'est plutôt un faux positif ou "
    "une attaque. Ne propose une exclusion (propose_exclusion=true) que pour un faux "
    "positif probable, avec la portée la plus étroite possible : une règle de "
    "l'événement, sur le même hôte et la même URI (uri_match 'exact' de préférence), "
    "limitée au paramètre/cookie/en-tête concerné s'il est connu. Sinon "
    "propose_exclusion=false et remplis 'exclusion' avec des valeurs neutres."
)


def event_key(event: dict[str, Any]) -> str:
    parts = [str(event.get(k) or "") for k in ("timestamp", "client_ip", "host", "uri", "rule_id")]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]


def _clean_event(event: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in _EVENT_FIELDS:
        value = event.get(key)
        if value in (None, "", "—"):
            continue
        if isinstance(value, str):
            value = value[:500]
        out[key] = value
    ids = out.get("all_rule_ids")
    if isinstance(ids, str):
        out["all_rule_ids"] = [x.strip() for x in ids.split(",") if x.strip()][:20]
    return out


def validate_proposal(event: dict[str, Any], exclusion: dict[str, Any]) -> dict[str, Any] | None:
    """Return a safe exclusion form payload, or ``None`` if out of bounds."""
    from app.bastion.nginx_waf_export import is_excludable_rule_id

    try:
        rule_id = int(exclusion.get("crs_rule_id"))
    except (TypeError, ValueError):
        return None
    event_rules = {str(event.get("rule_id") or "")}
    event_rules.update(str(r) for r in (event.get("all_rule_ids") or []))
    if str(rule_id) not in event_rules or not is_excludable_rule_id(rule_id):
        return None
    host = str(event.get("host") or "").strip().lower()
    uri = str(event.get("uri") or "").strip()
    if not host or host == "—" or not uri or uri == "—":
        return None  # never propose a host-wide or global exclusion
    scope = exclusion.get("scope_kind")
    target = str(exclusion.get("target_name") or "").strip()
    if scope not in _SCOPES or (scope != "rule" and not target):
        return None
    proposed_uri = str(exclusion.get("uri_pattern") or "").strip() or uri
    match = exclusion.get("uri_match") if exclusion.get("uri_match") in _URI_MATCH else "exact"
    if match == "exact" and proposed_uri != uri:
        proposed_uri = uri
    if match == "prefix" and (not uri.startswith(proposed_uri) or len(proposed_uri) < 2):
        return None
    return {
        "crs_rule_id": rule_id,
        "host": host,
        "uri_pattern": proposed_uri,
        "uri_match": match,
        "scope_kind": scope,
        "target_name": target if scope != "rule" else "",
        "reason": ("IA (validé) — " + str(exclusion.get("reason") or f"règle {rule_id}"))[:200],
    }


async def explain_waf_event(
    db: Session,
    settings: Settings,
    event: dict[str, Any],
    *,
    requested_by: str | None = None,
) -> Any:
    from app.bastion.modsec_audit_aggregator import rule_label
    from app.bastion.nginx_waf_export import ensure_active_profile
    from app.security.waf.service import list_exclusions

    clean = _clean_event(event)
    if not clean.get("rule_id"):
        return None
    rules = [str(clean["rule_id"])] + [str(r) for r in clean.get("all_rule_ids") or []]
    profile = ensure_active_profile(db)
    host = str(clean.get("host") or "").lower()
    existing = [
        {"rule": ex.crs_rule_id, "scope": ex.scope_kind, "target": ex.target_name, "uri": ex.uri_pattern}
        for ex in list_exclusions(db, active_only=True)
        if not host or (ex.host or "").lower() in ("", host)
    ][:20]
    data = {
        "evenement": clean,
        "libelles_regles": {r: rule_label(r) for r in dict.fromkeys(rules)},
        "profil_waf": {
            "mode": profile.mode,
            "paranoia_level": profile.paranoia_level,
            "seuil_anomalie": profile.anomaly_threshold,
        },
        "exclusions_existantes_sur_cet_hote": existing,
    }
    insight = await generate_insight(
        db,
        kind="waf_explain",
        subject_type="waf_event",
        subject_id=event_key(event),
        instructions=INSTRUCTIONS,
        data=data,
        schema=SCHEMA,
        status=STATUS_INFO,
        requested_by=requested_by,
        settings=settings,
    )
    if insight is None:
        return None
    payload = dict(insight.payload)
    proposal = None
    if payload.get("propose_exclusion") and payload.get("legitimacy") == "faux_positif_probable":
        proposal = validate_proposal(clean, payload.get("exclusion") or {})
    payload.pop("exclusion", None)
    payload.pop("propose_exclusion", None)
    if proposal:
        payload["proposed_exclusion"] = proposal
        insight.status = STATUS_PROPOSED
    insight.payload = payload
    db.commit()
    return insight
