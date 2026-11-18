"""Idea 4 — decision support on an AccessRequest (self-registration).

Compares the request with the same organisation's existing accounts, its
company RBAC group(s) and their application grants, and flags duplicates or
bursts from the same IP. The approver still uses the existing approve /
reject buttons. Fallback: the request as shown today.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.llm.insights import STATUS_INFO, generate_insight
from app.models import AccessRequest, App, BastionAccount
from app.sso_settings import Settings

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "maxLength": 600},
        "recommendation": {"type": "string", "enum": ["approuver", "rejeter", "demander_precisions"]},
        "justification": {"type": "string", "maxLength": 1000},
        "suggested_realm": {"type": "string", "maxLength": 64},
        "suggested_applications": {"type": "array", "items": {"type": "string", "maxLength": 64}, "maxItems": 20},
        "risks": {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 6},
    },
    "required": ["summary", "recommendation", "justification", "suggested_realm", "suggested_applications", "risks"],
    "additionalProperties": False,
}

INSTRUCTIONS = (
    "Aide un administrateur à décider d'une demande de création de compte sur le "
    "portail Bastion. Compare la demande aux comptes existants de la même "
    "organisation, au groupe RBAC de l'entreprise et aux applications que ce groupe "
    "ouvre (principe du moindre privilège : ne suggère que des applications déjà "
    "accordées aux pairs). Signale les doublons, les domaines d'email incohérents "
    "avec l'organisation, les messages vagues et les rafales depuis une même IP. "
    "'suggested_realm' doit être l'un des realms fournis, ou vide."
)


def _email_domain(email: str | None) -> str:
    return email.rsplit("@", 1)[-1].lower() if email and "@" in email else ""


def _peer_context(db: Session, organization: str | None, realms: list[Any]) -> dict[str, Any]:
    from app.rbac.account_service import find_rbac_company_group
    from app.rbac.grants_service import list_grants
    from app.rbac.organization_names import organization_match_key

    key = organization_match_key(organization)
    if not key:
        return {"organisation_reconnue": False}
    peers = [
        a for a in db.query(BastionAccount).limit(5000).all()
        if organization_match_key(a.organization) == key
    ]
    apps = {a.id: a.slug for a in db.query(App.id, App.slug).all()}
    groups: list[dict[str, Any]] = []
    for realm in realms:
        group = find_rbac_company_group(db, realm_id=realm.id, organization=organization or "")
        if group is None:
            continue
        grants = list_grants(db, rbac_group_id=group.id, limit=100)
        groups.append({
            "realm": realm.slug,
            "groupe": group.name,
            "membres": group.member_count,
            "applications": sorted({
                apps.get(g.application_id, "?") for g in grants
                if g.resource_type == "application" and g.application_id
            }),
        })
    return {
        "organisation_reconnue": True,
        "comptes_pairs": len(peers),
        "domaines_email_pairs": sorted({_email_domain(p.email) for p in peers if p.email})[:10],
        "realms_pairs": sorted({str(p.realm_id) for p in peers}),
        "comptes_pairs_desactives": sum(1 for p in peers if p.disabled_at),
        "groupes_entreprise": groups,
    }


async def analyze_access_request(
    db: Session,
    settings: Settings,
    *,
    request_id: int,
    requested_by: str | None = None,
) -> Any:
    from app.rbac.access_request_service import realms_for_access_request_approve

    req = db.get(AccessRequest, request_id)
    if req is None:
        return None
    realms = realms_for_access_request_approve(db)
    email_l = (req.email or "").lower()
    username_l = (req.username or "").lower()
    duplicates = (
        db.query(BastionAccount)
        .filter(
            (func.lower(BastionAccount.email) == email_l)
            | (func.lower(BastionAccount.username) == username_l)
        )
        .count()
    )
    same_ip_pending = 0
    if req.client_ip:
        same_ip_pending = (
            db.query(AccessRequest)
            .filter(AccessRequest.client_ip == req.client_ip, AccessRequest.status == "pending")
            .count()
        )
    previous = (
        db.query(AccessRequest.status, func.count())
        .filter(func.lower(AccessRequest.email) == email_l, AccessRequest.id != req.id)
        .group_by(AccessRequest.status)
        .all()
    )
    data = {
        "demande": {
            "username": req.username,
            "email_domaine": _email_domain(req.email),
            "prenom": req.first_name,
            "nom": req.last_name,
            "organisation": req.organization,
            "message": (req.message or "")[:1000],
            "date": req.created_at.isoformat() if req.created_at else None,
        },
        "signaux": {
            "comptes_existants_meme_email_ou_username": duplicates,
            "demandes_en_attente_meme_ip": same_ip_pending,
            "demandes_precedentes_meme_email": {s: n for s, n in previous},
        },
        "realms_disponibles": [r.slug for r in realms],
        "pairs": _peer_context(db, req.organization, realms),
    }
    insight = await generate_insight(
        db,
        kind="access_request",
        subject_type="access_request",
        subject_id=req.id,
        instructions=INSTRUCTIONS,
        data=data,
        schema=SCHEMA,
        status=STATUS_INFO,
        requested_by=requested_by,
        settings=settings,
    )
    if insight is not None:
        # Keep suggestions inside what exists: no invented realm or app.
        payload = dict(insight.payload)
        realm_slugs = {r.slug for r in realms}
        if payload.get("suggested_realm") not in realm_slugs:
            payload["suggested_realm"] = ""
        allowed_apps = {
            app for g in data["pairs"].get("groupes_entreprise", []) for app in g["applications"]
        }
        payload["suggested_applications"] = [
            a for a in payload.get("suggested_applications") or [] if a in allowed_apps
        ]
        insight.payload = payload
        db.commit()
    return insight
