"""Idea 1 — natural-language audit search → structured filters (never SQL).

The model only fills a closed JSON schema; every value is re-validated with
the same parsers as the manual filter form before it reaches the query layer.
Fallback: the manual filters, unchanged.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urlencode

from sqlalchemy.orm import Session

from app import re_safe
from app.audit.event_catalog import DOMAINS, EVENTS, Severity
from app.llm.insights import generate_insight
from app.sso_settings import Settings

_STATUSES = ["success", "error", "info"]
_SEVERITIES = [s.value for s in Severity]
_DATE_RE = re_safe.compile(r"^\d{4}-\d{2}-\d{2}$")
_CODE_RE = re_safe.compile(r"^BST-[A-Z]{3,5}-\d{4}$")
_WORD_RE = re_safe.compile(r"[a-zà-ÿ0-9]{4,}")

_DOMAIN_HELP = {
    "AUTH": "authentification / login",
    "BGL": "break-glass (accès de secours)",
    "SESS": "sessions",
    "RBAC": "droits, groupes, comptes",
    "VLT": "coffre de mots de passe",
    "FILE": "fichiers",
    "WAF": "pare-feu applicatif",
    "PROXY": "proxy applicatif",
    "ADM": "administration du portail",
    "MTA": "messagerie / MTA-STS",
    "SIEM": "transfert SIEM",
    "PROV": "provisioning de comptes",
    "SYS": "système",
}

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "q": {"type": "string", "maxLength": 200},
        "action": {"type": "string", "maxLength": 120},
        "actor": {"type": "string", "maxLength": 200},
        "ip": {"type": "string", "maxLength": 64},
        "event_code": {"type": "string", "maxLength": 16},
        "date_from": {"type": "string", "maxLength": 10},
        "date_to": {"type": "string", "maxLength": 10},
        "status": {"type": "array", "items": {"type": "string", "enum": _STATUSES}, "maxItems": 3},
        "domain": {"type": "array", "items": {"type": "string", "enum": sorted(DOMAINS)}, "maxItems": 13},
        "severity": {"type": "array", "items": {"type": "string", "enum": _SEVERITIES}, "maxItems": 5},
        "explanation": {"type": "string", "maxLength": 400},
    },
    "required": [
        "q", "action", "actor", "ip", "event_code", "date_from", "date_to",
        "status", "domain", "severity", "explanation",
    ],
    "additionalProperties": False,
}

INSTRUCTIONS = (
    "Traduis la question d'un administrateur en filtres de recherche du journal "
    "d'audit. Laisse une chaîne vide ou une liste vide pour tout filtre inutile. "
    "Dates au format AAAA-MM-JJ, calculées à partir de la date du jour fournie. "
    "N'utilise 'action' ou 'event_code' que s'ils figurent exactement dans le "
    "catalogue fourni ; sinon mets des mots-clés dans 'q'. 'explanation' résume en "
    "une phrase les filtres choisis."
)


def _catalog_hints(question: str, limit: int = 40) -> list[dict[str, str]]:
    words = {w for w in _WORD_RE.findall(question.lower())}
    hits: list[dict[str, str]] = []
    for ev in EVENTS.values():
        if ev.deprecated:
            continue
        text = f"{ev.title_fr} {ev.label} {ev.legacy_action or ''}".lower()
        if words and any(w in text for w in words):
            hits.append({"code": ev.code, "action": ev.legacy_action or "", "titre": ev.title_fr})
        if len(hits) >= limit:
            break
    return hits


def _valid_date(value: str) -> str:
    value = (value or "").strip()
    if not _DATE_RE.match(value):
        return ""
    try:
        date.fromisoformat(value)
    except ValueError:
        return ""
    return value


def _valid_ip(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        return ""


def sanitize_filters(raw: dict[str, Any]) -> dict[str, Any]:
    """Keep only values the manual filter form could have produced."""
    known_actions = {ev.legacy_action for ev in EVENTS.values() if ev.legacy_action}
    action = str(raw.get("action") or "").strip()
    code = str(raw.get("event_code") or "").strip().upper()
    out: dict[str, Any] = {
        "q": str(raw.get("q") or "").strip()[:200],
        "action": action if action in known_actions else "",
        "actor": str(raw.get("actor") or "").strip()[:200],
        "ip": _valid_ip(str(raw.get("ip") or "")),
        "event_code": code if _CODE_RE.match(code) and code in EVENTS else "",
        "date_from": _valid_date(str(raw.get("date_from") or "")),
        "date_to": _valid_date(str(raw.get("date_to") or "")),
        "status": [s for s in raw.get("status") or [] if s in _STATUSES],
        "domain": [d for d in raw.get("domain") or [] if d in DOMAINS],
        "severity": [s for s in raw.get("severity") or [] if s in _SEVERITIES],
    }
    return out


def filters_query_string(filters: dict[str, Any]) -> str:
    pairs: list[tuple[str, str]] = []
    for key, value in filters.items():
        if isinstance(value, list):
            pairs.extend((key, v) for v in value)
        elif value:
            pairs.append((key, str(value)))
    return urlencode(pairs)


async def translate_audit_question(
    db: Session,
    settings: Settings,
    question: str,
    *,
    requested_by: str,
) -> dict[str, Any] | None:
    """Return ``{"filters": {...}, "explanation": str}`` or ``None``."""
    question = (question or "").strip()[:500]
    if not question:
        return None
    data = {
        "question": question,
        "date_du_jour": datetime.now(UTC).date().isoformat(),
        "domaines": _DOMAIN_HELP,
        "statuts": _STATUSES,
        "gravites": _SEVERITIES,
        "catalogue_pertinent": _catalog_hints(question),
    }
    insight = await generate_insight(
        db,
        kind="audit_search",
        subject_type="question",
        subject_id=question[:255],
        instructions=INSTRUCTIONS,
        data=data,
        schema=SCHEMA,
        requested_by=requested_by,
        settings=settings,
    )
    if insight is None:
        return None
    filters = sanitize_filters(insight.payload)
    if not any(filters.values()):
        return None
    return {"filters": filters, "explanation": str(insight.payload.get("explanation") or "")}
