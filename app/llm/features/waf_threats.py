"""Automatic WAF threat analysis: injections, scans, abuse and fraud attempts.

Leader job (every 10 min) plus an "Analyser maintenant" button. Reads the
WAF events already collected by the ModSecurity aggregator (no new log
parsing), keeps only those newer than the last analysed one, groups them by
client IP with ban/rate context, and asks the model to qualify each source:
category (SQL injection, XSS, command injection, traversal, scan, credential
stuffing, business abuse / fraud, bot, false positive…), severity and the
recommended action. By default a ban is only a *proposal*: the admin
accepts it, then applies it with the existing WAF "ban IP" form. With the
admin option "réponse automatique" on, a recommended ban is applied without
validation **only after raw-event verification** (``app.llm.responder.verify_waf_ban``:
fresh, blocked and critical ModSecurity events in sufficient number, several
rules, IP not known to the app, not allowlisted, hourly cap); a refused
verification leaves the proposal for the admin, with the reasons. Fallback: the
WAF works exactly as before, the analysis simply does not appear.
"""

from __future__ import annotations

import ipaddress
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.llm.insights import STATUS_ACCEPTED, STATUS_INFO, STATUS_PROPOSED, latest_insight
from app.llm.service import run_task
from app.models import LlmInsight, PortalSettings, SecurityBan, SecurityRateEvent, utcnow
from app.sso_settings import Settings, get_settings

logger = logging.getLogger(__name__)

KIND = "waf_threat"
_MAX_SOURCES = 12
_REANALYSE_AFTER = timedelta(minutes=60)
_RATE_WINDOW = timedelta(hours=1)

CATEGORIES = [
    "injection_sql", "xss", "injection_commande_rce", "traversee_lfi_rfi",
    "scan_reconnaissance", "bruteforce_credential_stuffing", "fraude_abus_metier",
    "bot_automatisation", "faux_positif", "autre",
]
ACTIONS = ["aucune", "surveiller", "bannir_temporairement", "verifier_faux_positif"]
SEVERITIES = ["faible", "moyenne", "elevee", "critique"]

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "threats": {
            "type": "array",
            "maxItems": _MAX_SOURCES,
            "items": {
                "type": "object",
                "properties": {
                    "client_ip": {"type": "string", "maxLength": 64},
                    "category": {"type": "string", "enum": CATEGORIES},
                    "severity": {"type": "string", "enum": SEVERITIES},
                    "confidence": {"type": "string", "enum": ["faible", "moyenne", "elevee"]},
                    "summary": {"type": "string", "maxLength": 600},
                    "evidence": {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 6},
                    "recommended_action": {"type": "string", "enum": ACTIONS},
                    "ban_minutes": {"type": "integer", "minimum": 15, "maximum": 10080},
                },
                "required": [
                    "client_ip", "category", "severity", "confidence", "summary",
                    "evidence", "recommended_action", "ban_minutes",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["threats"],
    "additionalProperties": False,
}

INSTRUCTIONS = (
    "Tu es analyste SOC. Voici, par adresse IP source, les événements récents du "
    "pare-feu applicatif (ModSecurity + OWASP CRS) devant le portail Bastion, avec "
    "le contexte de bannissement et de limitation de débit. Pour chaque IP, "
    "qualifie l'activité : injection SQL, XSS, injection de commande / RCE, "
    "traversée de chemin / inclusion de fichier, scan ou reconnaissance, force "
    "brute / credential stuffing, fraude ou abus métier (manipulation de "
    "paramètres, contournement de parcours, énumération de comptes ou "
    "d'identifiants, automatisation abusive), bot, ou faux positif d'une "
    "application légitime. Donne une gravité, une confiance, un résumé et les "
    "preuves tirées des données (règles, URI, paramètres, volumes). Recommande "
    "'bannir_temporairement' seulement pour une activité clairement malveillante ; "
    "'verifier_faux_positif' si le trafic ressemble à un usage normal d'une "
    "application ; jamais de bannissement pour une IP privée ou déjà bannie. "
    "N'analyse que les IP fournies."
)


def _parse_ts(value: Any) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        from datetime import UTC

        ts = ts.replace(tzinfo=UTC)
    return ts


_INTERNAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def _is_private(ip: str) -> bool:
    """Internal source (never a ban proposal). Explicit list: ``is_private`` also
    flags documentation / reserved ranges that real attackers never use."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local:
        return True
    return any(addr.version == net.version and addr in net for net in _INTERNAL_NETS)


def new_events(settings: Settings, since: datetime | None) -> list[dict[str, Any]]:
    """WAF events collected by the aggregator, newer than ``since``."""
    from app.bastion.modsec_audit_aggregator import read_aggregator_state

    try:
        state = read_aggregator_state(settings)
    except Exception:  # noqa: BLE001 — missing / unreadable state = nothing to do
        return []
    out = []
    for event in state.get("recent_events") or []:
        ts = _parse_ts(event.get("timestamp"))
        if ts is None or (since is not None and ts <= since):
            continue
        if not event.get("client_ip"):
            continue
        out.append({**event, "_ts": ts})
    return out


def _active_ban(db: Session, ip: str) -> bool:
    now = utcnow()
    rows = (
        db.query(SecurityBan)
        .filter(SecurityBan.target_type == "ip", SecurityBan.target == ip, SecurityBan.lifted_at.is_(None))
        .all()
    )
    return any(r.permanent or (r.expires_at and r.expires_at > now) for r in rows)


def _rate_context(db: Session, ip: str) -> dict[str, int]:
    since = utcnow() - _RATE_WINDOW
    rows = (
        db.query(SecurityRateEvent.kind)
        .filter(SecurityRateEvent.key == ip, SecurityRateEvent.occurred_at >= since)
        .limit(5000)
        .all()
    )
    return dict(Counter(kind for (kind,) in rows))


def build_sources(db: Session, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One compact, redaction-friendly summary per client IP (most active first)."""
    from app.bastion.modsec_audit_aggregator import rule_label

    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        by_ip[str(event["client_ip"])].append(event)
    ranked = sorted(
        by_ip.items(),
        key=lambda kv: (sum(1 for e in kv[1] if e.get("critical")), len(kv[1]),
                        max(int(e.get("score") or 0) for e in kv[1])),
        reverse=True,
    )
    sources: list[dict[str, Any]] = []
    for ip, evs in ranked[:_MAX_SOURCES]:
        rules = Counter(str(r) for e in evs for r in (e.get("all_rule_ids") or [e.get("rule_id")]) if r)
        families = Counter(f for e in evs for f in (e.get("families") or []))
        uris = list(dict.fromkeys(str(e.get("uri") or "")[:160] for e in evs))
        targets = Counter(
            f"{e.get('matched_scope_kind')}:{e.get('matched_target_name')}"
            for e in evs if e.get("matched_target_name")
        )
        sources.append({
            "client_ip": ip,
            "ip_privee": _is_private(ip),
            "deja_banni": _active_ban(db, ip),
            "evenements": len(evs),
            "bloques": sum(1 for e in evs if e.get("blocked")),
            "critiques": sum(1 for e in evs if e.get("critical")),
            "score_max": max(int(e.get("score") or 0) for e in evs),
            "premier": min(e["_ts"] for e in evs).isoformat(),
            "dernier": max(e["_ts"] for e in evs).isoformat(),
            "hotes": sorted({str(e.get("host") or "") for e in evs})[:5],
            "uris": uris[:8],
            "familles": dict(families.most_common(6)),
            "regles": {r: rule_label(r) for r, _ in rules.most_common(8)},
            "parametres_vises": dict(targets.most_common(6)),
            "messages": list(dict.fromkeys(str(e.get("message") or "")[:160] for e in evs))[:4],
            "debit_derniere_heure": _rate_context(db, ip),
        })
    return sources


async def analyse_waf_threats(
    db: Session,
    settings: Settings | None = None,
    *,
    requested_by: str | None = None,
    force: bool = False,
) -> list[LlmInsight]:
    """Analyse WAF events since the last run. Empty list when off or quiet."""
    from app.llm.service import auto_response_enabled, llm_enabled

    settings = settings or get_settings()
    if not llm_enabled(settings, db):
        return []
    auto = auto_response_enabled(settings, db)
    row = db.get(PortalSettings, 1)
    if row is None or (not force and not row.llm_waf_auto_enabled):
        return []
    events = new_events(settings, None if force else row.llm_waf_last_event_at)
    if not events:
        return []
    newest = max(e["_ts"] for e in events)
    sources = build_sources(db, events)
    if not force:
        sources = [
            s for s in sources
            if (last := latest_insight(db, KIND, "ip", s["client_ip"])) is None
            or not last.created_at or utcnow() - last.created_at > _REANALYSE_AFTER
        ]
    if not sources:
        row.llm_waf_last_event_at = newest
        db.commit()
        return []
    result = await run_task(
        KIND, instructions=INSTRUCTIONS,
        data={"fenetre": "depuis la dernière analyse", "sources": sources},
        schema=SCHEMA, db=db, settings=settings,
        actor=f"admin:{requested_by}" if requested_by else "system:llm",
        think=True,
    )
    if result is None or result.outcome != "ok" or not result.value:
        return []  # cursor unchanged: the same events are retried next run
    known = {s["client_ip"]: s for s in sources}
    stored: list[LlmInsight] = []
    for item in result.value.get("threats") or []:
        source = known.get(str(item.get("client_ip") or "").strip())
        if source is None:
            continue  # the model talked about an IP we did not send
        can_ban = not source["ip_privee"] and not source["deja_banni"]
        propose = (
            item.get("recommended_action") == "bannir_temporairement"
            and item.get("severity") in ("elevee", "critique")
            and can_ban
        )
        payload: dict[str, Any] = {
            "summary": item.get("summary"),
            "category": item.get("category"),
            "severity": item.get("severity"),
            "confidence": item.get("confidence"),
            "recommended_action": item.get("recommended_action"),
            "evidence": item.get("evidence") or [],
            "stats": {
                "evenements": source["evenements"],
                "bloques": source["bloques"],
                "score_max": source["score_max"],
                "hotes": source["hotes"],
                "dernier": source["dernier"],
            },
        }
        status = STATUS_PROPOSED if propose else STATUS_INFO
        decided: dict[str, Any] = {}
        if propose:
            payload["proposed_ban"] = {
                "ip": source["client_ip"],
                "ban_minutes": int(item.get("ban_minutes") or 1440),
                "reason": f"IA (validé) — {item.get('category')}, gravité {item.get('severity')}",
            }
            if auto:
                from app.llm.responder import apply_verified_waf_ban

                applied, refusals = apply_verified_waf_ban(db, source, item)
                if applied:
                    payload["auto_applied"] = {
                        "ip": source["client_ip"],
                        "ban_minutes": min(int(item.get("ban_minutes") or 60), 1440),
                        "verified_on": "événements ModSecurity bruts",
                    }
                    payload.pop("proposed_ban", None)  # already applied: nothing to validate
                    status = STATUS_ACCEPTED
                    decided = {"decided_by": "system:llm", "decided_at": utcnow()}
                else:
                    payload["auto_refused"] = refusals  # stays a proposal for the admin
        row_insight = LlmInsight(
            kind=KIND,
            subject_type="ip",
            subject_id=source["client_ip"],
            status=status,
            payload=payload,
            model=result.model,
            prompt_sha256=result.prompt_sha256,
            requested_by=requested_by,
            **decided,
        )
        db.add(row_insight)
        stored.append(row_insight)
    row.llm_waf_last_event_at = newest
    db.commit()
    return stored


async def waf_threat_job_body(db: Session) -> None:
    await analyse_waf_threats(db)


def recent_threats(db: Session, *, hours: int = 24, limit: int = 20) -> list[LlmInsight]:
    try:
        return (
            db.query(LlmInsight)
            .filter(LlmInsight.kind == KIND, LlmInsight.created_at >= utcnow() - timedelta(hours=hours))
            .order_by(LlmInsight.id.desc())
            .limit(limit)
            .all()
        )
    except Exception:  # noqa: BLE001 — optional block on the WAF page
        return []
