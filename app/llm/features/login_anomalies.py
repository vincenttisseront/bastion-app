"""Idea 3 — login anomaly detection (periodic, leader only).

Deterministic pre-filter first: only IPs / usernames that cross simple
thresholds are sent to the model, so a quiet hour costs no LLM call. The
model scores and explains; a suggested ban is a *proposal* — the admin
applies it with the existing manual-ban form. ``SecurityBanRule`` rows are
seeded singletons and are never touched here. Fallback: the existing ban /
rate-limit rules, unchanged.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.llm.insights import STATUS_INFO, STATUS_PROPOSED, generate_insight, latest_insight
from app.models import ActiveSession, AuditLog, utcnow
from app.sso_settings import Settings, get_settings

WINDOW = timedelta(minutes=60)
_DEDUP = timedelta(hours=6)
_MAX_CANDIDATES = 15

FAIL_ACTIONS = frozenset({
    "oidc_login_failed", "oidc_login_otp_failed", "oidc_login_passkey_failed",
    "breakglass.login_failed", "breakglass.login_denied_non_lan", "security.sso_login_failed",
})
OK_ACTIONS = frozenset({
    "oidc_login_success", "oidc_login_otp_success", "oidc_login_passkey_success", "breakglass.login",
})
SIGNAL_ACTIONS = frozenset({
    "security.hack_attempt.detected", "security.successful_login_hammering.detected",
})

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "anomalies": {
            "type": "array",
            "maxItems": _MAX_CANDIDATES,
            "items": {
                "type": "object",
                "properties": {
                    "target_type": {"type": "string", "enum": ["ip", "username"]},
                    "target": {"type": "string", "maxLength": 200},
                    "score": {"type": "integer", "minimum": 0, "maximum": 100},
                    "pattern": {"type": "string", "enum": [
                        "bruteforce", "password_spraying", "credential_stuffing",
                        "voyage_impossible", "partage_de_compte", "benin", "autre",
                    ]},
                    "explanation": {"type": "string", "maxLength": 600},
                    "suggest_ban": {"type": "boolean"},
                    "ban_minutes": {"type": "integer", "minimum": 15, "maximum": 10080},
                },
                "required": ["target_type", "target", "score", "pattern", "explanation", "suggest_ban", "ban_minutes"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["anomalies"],
    "additionalProperties": False,
}

INSTRUCTIONS = (
    "Analyse ces statistiques de connexion (fenêtre glissante d'une heure) sur le "
    "portail Bastion. Pour chaque candidat, donne un score de risque 0-100, le "
    "motif le plus probable et une explication courte. Ne suggère un bannissement "
    "temporaire (suggest_ban) que pour un comportement clairement malveillant "
    "(force brute, password spraying, credential stuffing) ; jamais pour un "
    "utilisateur légitime qui s'est trompé quelques fois. N'analyse que les "
    "candidats fournis."
)


def collect_candidates(db: Session, *, now=None) -> list[dict[str, Any]]:
    """Aggregate the last hour of login audit events per IP and per username."""
    now = now or utcnow()
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.created_at >= now - WINDOW)
        .filter(AuditLog.action.in_(FAIL_ACTIONS | OK_ACTIONS | SIGNAL_ACTIONS))
        .order_by(AuditLog.id.desc())
        .limit(20_000)
        .all()
    )
    by_ip: dict[str, dict[str, Any]] = defaultdict(lambda: {"fail": 0, "ok": 0, "signals": 0, "users": set()})
    by_user: dict[str, dict[str, Any]] = defaultdict(lambda: {"fail": 0, "ok": 0, "ips": set()})
    for r in rows:
        ip = (r.ip_address or "").strip()
        user = (r.actor or "").strip().lower()
        kind = "fail" if r.action in FAIL_ACTIONS else "ok" if r.action in OK_ACTIONS else "signal"
        if ip:
            slot = by_ip[ip]
            slot["signals" if kind == "signal" else kind] += 1
            if user:
                slot["users"].add(user)
        if user and kind != "signal":
            uslot = by_user[user]
            uslot[kind] += 1
            if ip:
                uslot["ips"].add(ip)

    live_ips: dict[str, set[str]] = defaultdict(set)
    try:
        for s in db.query(ActiveSession).filter(ActiveSession.kind == "user").limit(5000).all():
            if s.user_email and s.source_ip:
                live_ips[s.user_email.lower()].add(s.source_ip)
    except Exception:  # noqa: BLE001 — live sessions are an optional signal
        live_ips.clear()

    out: list[dict[str, Any]] = []
    for ip, st in by_ip.items():
        if st["fail"] >= 10 or len(st["users"]) >= 4 or st["signals"]:
            out.append({
                "target_type": "ip", "target": ip, "echecs": st["fail"], "succes": st["ok"],
                "usernames_distincts": len(st["users"]), "signaux_moteur_ban": st["signals"],
            })
    for user, st in by_user.items():
        ips = st["ips"] | live_ips.get(user, set())
        if st["fail"] >= 8 or len(ips) >= 4:
            out.append({
                "target_type": "username", "target": user, "echecs": st["fail"], "succes": st["ok"],
                "ips_distinctes": len(ips), "sessions_actives_ips": len(live_ips.get(user, ())),
            })
    out.sort(key=lambda c: (c.get("echecs", 0), c.get("usernames_distincts", 0)), reverse=True)
    return out[:_MAX_CANDIDATES]


async def scan_login_anomalies(
    db: Session,
    settings: Settings | None = None,
    *,
    requested_by: str | None = None,
) -> list[Any]:
    """Return stored insights (one per flagged candidate). Empty when off or quiet."""
    from app.llm.service import llm_enabled

    settings = settings or get_settings()
    if not llm_enabled(settings, db):
        return []
    candidates = collect_candidates(db)
    fresh = []
    for c in candidates:
        last = latest_insight(db, "login_anomaly", c["target_type"], c["target"])
        if last is None or not last.created_at or utcnow() - last.created_at > _DEDUP:
            fresh.append(c)
    if not fresh:
        return []
    batch = await generate_insight(
        db,
        kind="login_anomaly_batch",
        subject_type="window",
        subject_id=utcnow().strftime("%Y-%m-%dT%H:%M"),
        instructions=INSTRUCTIONS,
        data={"fenetre_minutes": int(WINDOW.total_seconds() // 60), "candidats": fresh},
        schema=SCHEMA,
        requested_by=requested_by,
        settings=settings,
    )
    if batch is None:
        return []
    allowed = {(c["target_type"], c["target"]): c for c in fresh}
    stored: list[Any] = []
    from app.models import LlmInsight

    for item in batch.payload.get("anomalies") or []:
        key = (item.get("target_type"), str(item.get("target") or "").strip().lower())
        cand = allowed.get(key) or allowed.get((key[0], str(item.get("target") or "").strip()))
        if cand is None:
            continue  # model talked about something we did not send
        proposal = bool(item.get("suggest_ban")) and int(item.get("score") or 0) >= 70
        row = LlmInsight(
            kind="login_anomaly",
            subject_type=cand["target_type"],
            subject_id=cand["target"],
            status=STATUS_PROPOSED if proposal else STATUS_INFO,
            payload={
                "summary": item.get("explanation"),
                "score": item.get("score"),
                "pattern": item.get("pattern"),
                "stats": {k: v for k, v in cand.items() if k not in ("target_type", "target")},
                **({"proposed_ban": {
                    "target_type": cand["target_type"],
                    "target": cand["target"],
                    "ban_minutes": int(item.get("ban_minutes") or 60),
                    "reason": f"IA (validé) — {item.get('pattern')}, score {item.get('score')}",
                }} if proposal else {}),
            },
            model=batch.model,
            prompt_sha256=batch.prompt_sha256,
            requested_by=requested_by,
        )
        db.add(row)
        stored.append(row)
    db.delete(batch)  # the per-target rows carry the result
    db.commit()
    return stored


async def login_anomaly_job_body(db: Session) -> None:
    await scan_login_anomalies(db)
