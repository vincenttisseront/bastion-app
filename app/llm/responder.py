"""Réponse autonome aux situations dangereuses (sans validation admin).

Décision de conception : **le modèle classe, des règles fixes décident**. Le LLM ne
choisit jamais une action ; il produit un *signal* (enum) et une confiance. Ce
module transforme signal + seuils + garde-fous en actions, toutes :

* **bornées au demandeur** : ses autres sessions, son IP, son accès au compagnon.
  Aucune action sur un tiers ; l'IP vient de la connexion (jamais du texte) ;
* **temporaires et réversibles** : ban d'IP de 15 à 60 min (levable depuis
  Sécurité → WAF), suspension du compagnon, sessions qui se rouvrent par un login ;
* **gardées** : jamais d'action sur une IP interne, en liste blanche, break-glass
  LAN, utilisée par un autre utilisateur actif (NAT partagé), ni contre un admin ;
  plafond de bans automatiques par heure ;
* **journalisées et signalées** : chaque signal produit un audit transmis au SIEM et
  une alerte visible dans Admin → Assistant IA ; l'admin est prévenu après coup,
  sans rien à valider ;
* **arrêtables** : ``PortalSettings.llm_auto_response_enabled`` (désactivé par
  défaut). Éteint, les signaux alertent seulement ; ``LLM_ENABLED=false`` coupe tout.

ModSecurity : un ban IP issu d'une analyse WAF n'est appliqué qu'après
**vérification sur les événements bruts** (fraîcheur, volumes bloqués / critiques,
diversité des règles, IP non connue de l'application). Sinon la proposition reste
à valider, avec les raisons du refus.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app import re_safe
from app.audit import log_action
from app.i18n.catalog import t
from app.llm.insights import STATUS_INFO
from app.models import ActiveSession, LlmInsight, SecurityBan, SecurityRateEvent, utcnow
from app.sso_settings import Settings
from app.web.user_context import UserContext

logger = logging.getLogger(__name__)

ACTOR = "system:companion"

SIGNAL_NONE = "aucun"
SIGNAL_COMPROMISED = "compte_compromis"
SIGNAL_PHISHING_HIT = "phishing_interaction"
SIGNAL_PHISHING_RECEIVED = "phishing_recu"
SIGNAL_ATTACK = "attaque_chat"
SIGNAL_ABUSE = "abus_chat"
SIGNALS = (
    SIGNAL_NONE,
    SIGNAL_COMPROMISED,
    SIGNAL_PHISHING_HIT,
    SIGNAL_PHISHING_RECEIVED,
    SIGNAL_ATTACK,
    SIGNAL_ABUSE,
)

# ── policy (fixed thresholds — the model never sets these) ──────────────────
REVOKE_COOLDOWN = timedelta(minutes=30)
ALERT_DEDUP = timedelta(minutes=10)
ATTACK_WINDOW = timedelta(minutes=15)
ATTACK_BAN_THRESHOLD = 3
BAN_MINUTES = 15
BAN_MINUTES_REPEAT = 60
BAN_REPEAT_LOOKBACK = timedelta(hours=24)
MAX_AUTO_BANS_PER_HOUR = 5
OOS_WINDOW = timedelta(minutes=10)
ABUSE_THRESHOLD = 5
MUTE_ATTACK_MINUTES = 15
MUTE_ABUSE_MINUTES = 30
NAT_LOOKBACK = timedelta(minutes=15)

# ModSecurity verification (raw events, not the model's words).
WAF_MIN_EVENTS = 5
WAF_MIN_BLOCKED = 3
WAF_MIN_CRITICAL = 3
WAF_MIN_RULES = 2
WAF_FRESHNESS = timedelta(minutes=30)
WAF_MAX_BAN_MINUTES = 24 * 60
WAF_MAX_AUTO_BANS_PER_HOUR = 10
WAF_REFUSED_CATEGORIES = ("faux_positif", "autre")

_INTERNAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def is_internal_ip(ip: str | None) -> bool:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return True  # unparsable: never ban
    if addr.is_loopback or addr.is_link_local:
        return True
    return any(addr.version == net.version and addr in net for net in _INTERNAL_NETS)


# ── deterministic detectors (run on the raw message, before any LLM call) ───

_ATTACK_PATTERNS: tuple[tuple[str, Any], ...] = (
    (
        "sqli",
        re_safe.compile(
            r"(?i)(?:\bunion\b[\s\S]{0,40}\bselect\b"
            r"|\bselect\b[\s\S]{0,80}\bfrom\b[\s\S]{0,40}(?:information_schema|mysql\.|pg_catalog|sqlite_master)"
            r"|'\s*(?:or|and)\s+'?\d+'?\s*=\s*'?\d+"
            r"|;\s*(?:drop|truncate)\s+table\b"
            r"|\bsleep\s*\(\s*\d+\s*\)"
            r"|\bshow\s+databases\b|\bxp_cmdshell\b)"
        ),
    ),
    (
        "xss",
        re_safe.compile(
            r"(?i)(?:<\s*script\b|javascript\s*:|\bon(?:error|load|click|mouseover)\s*="
            r"|<\s*(?:img|svg|iframe|body)\b[^>]{0,80}\bon\w+\s*=)"
        ),
    ),
    (
        "traversal",
        re_safe.compile(r"(?i)(?:\.\./\.\./|\.\.\\\.\.\\|/etc/(?:passwd|shadow)|%2e%2e%2f|\bphpinfo\b)"),
    ),
    (
        "cmd",
        re_safe.compile(
            r"(?i)(?:;\s*(?:cat|ls|id|whoami|curl|wget|nc|bash|sh)\s+[^\s]"
            r"|\$\(\s*[a-z]+|\|\s*(?:bash|sh)\b)"
        ),
    ),
    (
        "jndi_ssti",
        re_safe.compile(r"(?i)(?:\$\{\s*jndi\s*:|\{\{\s*(?:config|self|[\w.]*__\w+__)|\$\{\s*7\s*\*\s*7\s*\})"),
    ),
)

_INJECTION_RE = re_safe.compile(
    r"(?i)(?:ignore\s+(?:all\s+|the\s+|your\s+)?(?:previous|above|prior)\s+(?:instructions?|prompts?)"
    r"|(?:oublie|ignore)\s+(?:toutes?\s+)?(?:les\s+|tes\s+|vos\s+)?(?:instructions|consignes)"
    r"|system\s*prompt|prompt\s+syst[eè]me|jailbreak|developer\s+mode|mode\s+d[ée]veloppeur"
    r"|affiche\s+(?:tes|vos)\s+(?:instructions|consignes))"
)


def detect_local(text: str) -> tuple[str, str] | None:
    """(signal, detector) for an obvious attack payload or prompt-injection phrase."""
    for name, pattern in _ATTACK_PATTERNS:
        if pattern.search(text):
            return SIGNAL_ATTACK, name
    if _INJECTION_RE.search(text):
        return SIGNAL_ABUSE, "prompt_injection"
    return None


# ── persistence of strikes / mutes (shared across workers) ──────────────────


def _record(db: Session, kind: str, key: str) -> None:
    try:
        now = utcnow()
        db.add(SecurityRateEvent(kind=kind, key=key, occurred_at=now))
        db.query(SecurityRateEvent).filter(
            SecurityRateEvent.kind == kind,
            SecurityRateEvent.key == key,
            SecurityRateEvent.occurred_at < now - timedelta(hours=24),
        ).delete(synchronize_session=False)
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.debug("companion strike record failed", exc_info=True)


def _count(db: Session, kind: str, key: str, window: timedelta) -> int:
    try:
        return int(
            db.query(func.count(SecurityRateEvent.id))
            .filter(
                SecurityRateEvent.kind == kind,
                SecurityRateEvent.key == key,
                SecurityRateEvent.occurred_at >= utcnow() - window,
            )
            .scalar()
            or 0
        )
    except Exception:  # noqa: BLE001
        db.rollback()
        return 0


def mute_remaining_minutes(db: Session, user_key: str) -> int:
    """Minutes left on a companion suspension for this user (0 = not muted)."""
    now = utcnow()
    best = 0.0
    for minutes in (MUTE_ATTACK_MINUTES, MUTE_ABUSE_MINUTES):
        try:
            last = (
                db.query(func.max(SecurityRateEvent.occurred_at))
                .filter(
                    SecurityRateEvent.kind == f"companion_mute:{minutes}",
                    SecurityRateEvent.key == user_key,
                )
                .scalar()
            )
        except Exception:  # noqa: BLE001
            db.rollback()
            continue
        if last is not None:
            left = (last + timedelta(minutes=minutes) - now).total_seconds() / 60.0
            best = max(best, left)
    return int(best) + 1 if best > 0 else 0


def note_out_of_scope(db: Session, user_key: str) -> int:
    """Count one refused out-of-scope question; returns how many in the window."""
    _record(db, "companion_oos", user_key)
    return _count(db, "companion_oos", user_key, OOS_WINDOW)


# ── result types ────────────────────────────────────────────────────────────


@dataclass
class ActionResult:
    kind: str  # alert | revoke_sessions | ban_ip | mute
    applied: bool
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "applied": self.applied, "detail": self.detail}


@dataclass
class Outcome:
    signal: str = SIGNAL_NONE
    actions: list[ActionResult] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)


# ── alert (always, even when autonomous actions are off) ────────────────────


def _alert(
    db: Session,
    *,
    signal: str,
    severity: str,
    summary: str,
    user_key: str,
    ip: str | None,
    detector: str,
    confidence: str,
    actions: list[ActionResult],
    auto: bool,
    force: bool = False,
) -> bool:
    """Audit (SIEM-forwarded) + insight on Admin → Assistant IA. Deduplicated."""
    dedup_kind = f"companion_alert:{signal}"
    if not force and _count(db, dedup_kind, user_key, ALERT_DEDUP) > 0:
        return False
    _record(db, dedup_kind, user_key)
    details = {
        "signal": signal,
        "severity": severity,
        "detector": detector,
        "confidence": confidence,
        "auto_response_enabled": auto,
        "actions": [a.as_dict() for a in actions],
    }
    log_action(
        db,
        ACTOR,
        "companion.security_signal",
        target=f"user:{user_key}",
        details=details,
        ip_address=ip,
    )
    try:
        db.add(
            LlmInsight(
                kind="companion_alert",
                subject_type="user",
                subject_id=user_key[:255],
                status=STATUS_INFO,
                payload={**details, "summary": summary, "ip": ip, "user": user_key},
                generated_by="companion",
                requested_by=None,
            )
        )
        db.commit()
    except Exception:  # noqa: BLE001 — the audit above already carries the signal
        db.rollback()
        logger.debug("companion alert insight failed", exc_info=True)
    return True


def _audit_action(db: Session, action: ActionResult, *, signal: str, user_key: str, ip: str | None) -> None:
    log_action(
        db,
        ACTOR,
        "ai.auto_response" if action.applied else "ai.auto_response_skipped",
        target=f"user:{user_key}",
        details={"signal": signal, **action.as_dict()},
        ip_address=ip,
    )


# ── actions ─────────────────────────────────────────────────────────────────


async def _revoke_other_sessions(
    db: Session,
    settings: Settings,
    user: UserContext,
    request: Any,
    user_key: str,
    ip: str | None,
) -> ActionResult:
    if _count(db, "companion_revoke", user_key, REVOKE_COOLDOWN) > 0:
        return ActionResult("revoke_sessions", False, "déjà effectuée il y a moins de 30 min")
    try:
        from app.web.profile_security_service import (
            ProfileSecurityError,
            current_native_session,
            revoke_all_other_sessions,
        )

        current = current_native_session(request, db, settings) if request is not None else None
        try:
            count = await revoke_all_other_sessions(
                db, user=user, settings=settings, current=current, actor=ACTOR, ip_address=ip
            )
        except ProfileSecurityError as exc:
            return ActionResult("revoke_sessions", False, str(exc)[:200])
    except Exception:  # noqa: BLE001
        logger.warning("companion session revocation failed", exc_info=True)
        return ActionResult("revoke_sessions", False, "erreur interne")
    _record(db, "companion_revoke", user_key)
    return ActionResult("revoke_sessions", True, f"{count} session(s) fermée(s)")


def _other_active_users_on_ip(db: Session, ip: str, user_key: str) -> int:
    try:
        return int(
            db.query(func.count(ActiveSession.id))
            .filter(
                ActiveSession.kind == "user",
                ActiveSession.status == "active",
                ActiveSession.source_ip == ip,
                ActiveSession.last_seen_at >= utcnow() - NAT_LOOKBACK,
                func.lower(ActiveSession.user_email) != user_key,
            )
            .scalar()
            or 0
        )
    except Exception:  # noqa: BLE001
        db.rollback()
        return 1  # unknown → assume shared: do not ban


def _recent_auto_bans(db: Session, actor: str, window: timedelta) -> int:
    try:
        return int(
            db.query(func.count(SecurityBan.id))
            .filter(SecurityBan.created_by == actor, SecurityBan.banned_at >= utcnow() - window)
            .scalar()
            or 0
        )
    except Exception:  # noqa: BLE001
        db.rollback()
        return 10**6  # unknown → refuse


def _ban_guard_reason(db: Session, ip: str | None, *, user_key: str, is_admin: bool) -> str:
    """Why this IP must not be auto-banned ('' = allowed)."""
    from app.security.banning.engine import is_breakglass_ban_exempt

    if not ip:
        return "IP inconnue"
    if is_admin:
        return "compte administrateur"
    if is_internal_ip(ip):
        return "IP interne"
    if is_breakglass_ban_exempt(db, ip):
        return "IP en liste blanche ou break-glass LAN"
    if _other_active_users_on_ip(db, ip, user_key) > 0:
        return "IP partagée avec d'autres utilisateurs actifs"
    if _recent_auto_bans(db, ACTOR, timedelta(hours=1)) >= MAX_AUTO_BANS_PER_HOUR:
        return "plafond de bans automatiques atteint"
    return ""


def _ban_ip(db: Session, ip: str | None, *, user_key: str, is_admin: bool, signal: str) -> ActionResult:
    reason = _ban_guard_reason(db, ip, user_key=user_key, is_admin=is_admin)
    if reason:
        return ActionResult("ban_ip", False, f"garde-fou : {reason}")
    from app.security.banning.engine import apply_ban

    repeat = (
        db.query(func.count(SecurityBan.id))
        .filter(
            SecurityBan.target_type == "ip",
            SecurityBan.target == ip,
            SecurityBan.created_by == ACTOR,
            SecurityBan.banned_at >= utcnow() - BAN_REPEAT_LOOKBACK,
        )
        .scalar()
        or 0
    )
    minutes = BAN_MINUTES_REPEAT if repeat else BAN_MINUTES
    ban = apply_ban(
        db,
        target_type="ip",
        target=str(ip),
        reason=f"Compagnon IA (automatique) — {signal}",
        rule_type="companion_ai",
        permanent=False,
        ban_minutes=minutes,
        actor=ACTOR,
        ip_address=ip,
    )
    if ban is None:
        return ActionResult("ban_ip", False, "refusé par le moteur de ban")
    return ActionResult("ban_ip", True, f"{minutes} min")


def _mute(db: Session, user_key: str, minutes: int) -> ActionResult:
    _record(db, f"companion_mute:{minutes}", user_key)
    return ActionResult("mute", True, f"{minutes} min")


# ── main entry point ────────────────────────────────────────────────────────


async def respond(
    db: Session,
    settings: Settings,
    *,
    signal: str,
    confidence: str,
    detector: str,
    user: UserContext,
    user_key: str,
    ip: str | None,
    request: Any,
    is_admin: bool,
    auto: bool,
    locale: str,
) -> Outcome:
    """Apply the fixed policy for one signal. Never raises."""
    out = Outcome(signal=signal)
    try:
        if signal in (SIGNAL_COMPROMISED, SIGNAL_PHISHING_HIT):
            await _on_account_risk(
                db, settings, out, user=user, user_key=user_key, ip=ip, request=request,
                detector=detector, confidence=confidence, auto=auto, locale=locale,
            )
        elif signal == SIGNAL_PHISHING_RECEIVED:
            _alert(
                db, signal=signal, severity="faible",
                summary="Hameçonnage reçu signalé par un utilisateur",
                user_key=user_key, ip=ip, detector=detector, confidence=confidence,
                actions=[], auto=auto,
            )
            out.notices.append(t(
                "Merci du signalement : l'équipe sécurité est prévenue. Ne cliquez sur aucun "
                "lien du message et n'y répondez pas.", locale))
        elif signal == SIGNAL_ATTACK:
            _on_attack(
                db, out, user_key=user_key, ip=ip, is_admin=is_admin,
                detector=detector, confidence=confidence, auto=auto, locale=locale,
            )
        elif signal == SIGNAL_ABUSE:
            _on_abuse(
                db, out, user_key=user_key, ip=ip,
                detector=detector, confidence=confidence, auto=auto, locale=locale,
            )
    except Exception:  # noqa: BLE001 — a failed response must not break the chat
        db.rollback()
        logger.warning("companion autonomous response failed", exc_info=True)
    return out


async def _on_account_risk(
    db: Session, settings: Settings, out: Outcome, *, user: UserContext, user_key: str,
    ip: str | None, request: Any, detector: str, confidence: str, auto: bool, locale: str,
) -> None:
    strong = confidence in ("moyenne", "elevee")
    actions: list[ActionResult] = []
    if strong and auto:
        actions.append(await _revoke_other_sessions(db, settings, user, request, user_key, ip))
    elif strong:
        actions.append(ActionResult("revoke_sessions", False, "réponse automatique désactivée"))
    severity = "elevee" if strong else "moyenne"
    _alert(
        db, signal=out.signal, severity=severity,
        summary=(
            "Compte potentiellement compromis signalé par l'utilisateur"
            if out.signal == SIGNAL_COMPROMISED
            else "Hameçonnage avec interaction (lien ouvert ou identifiants saisis) signalé"
        ),
        user_key=user_key, ip=ip, detector=detector, confidence=confidence,
        actions=actions, auto=auto, force=True,
    )
    for action in actions:
        out.actions.append(action)
        if auto:
            _audit_action(db, action, signal=out.signal, user_key=user_key, ip=ip)
    revoked = next((a for a in actions if a.kind == "revoke_sessions" and a.applied), None)
    if revoked:
        out.notices.append(t(
            "Par précaution, vos autres sessions ont été fermées ({detail}) et l'équipe "
            "sécurité a été prévenue. Changez votre mot de passe dans Mon profil → Sécurité.",
            locale, detail=revoked.detail))
    else:
        out.notices.append(t(
            "L'équipe sécurité a été prévenue. Changez votre mot de passe dans Mon profil → "
            "Sécurité dès que possible.", locale))


def _on_attack(
    db: Session, out: Outcome, *, user_key: str, ip: str | None, is_admin: bool,
    detector: str, confidence: str, auto: bool, locale: str,
) -> None:
    _record(db, "companion_attack", user_key)
    strikes = _count(db, "companion_attack", user_key, ATTACK_WINDOW)
    actions: list[ActionResult] = []
    if auto:
        actions.append(_mute(db, user_key, MUTE_ATTACK_MINUTES))
        if strikes >= ATTACK_BAN_THRESHOLD:
            actions.append(_ban_ip(db, ip, user_key=user_key, is_admin=is_admin, signal=out.signal))
    else:
        actions.append(ActionResult("mute", False, "réponse automatique désactivée"))
    banned = any(a.kind == "ban_ip" and a.applied for a in actions)
    _alert(
        db, signal=out.signal, severity="elevee" if banned else "moyenne",
        summary=f"Tentative d'attaque via le compagnon ({detector}), {strikes} en 15 min",
        user_key=user_key, ip=ip, detector=detector, confidence=confidence,
        actions=actions, auto=auto, force=banned,
    )
    for action in actions:
        out.actions.append(action)
        if auto:
            _audit_action(db, action, signal=out.signal, user_key=user_key, ip=ip)
    out.notices.append(t(
        "Ce message ressemble à une tentative d'attaque : il n'a pas été traité et l'équipe "
        "sécurité a été prévenue.", locale))
    ban = next((a for a in actions if a.kind == "ban_ip" and a.applied), None)
    if ban:
        out.notices.append(t(
            "Votre adresse IP est temporairement bloquée ({detail}).", locale, detail=ban.detail))
    elif any(a.kind == "mute" and a.applied for a in actions):
        out.notices.append(t(
            "Le compagnon est suspendu pour vous pendant {minutes} min.", locale,
            minutes=MUTE_ATTACK_MINUTES))


def _on_abuse(
    db: Session, out: Outcome, *, user_key: str, ip: str | None,
    detector: str, confidence: str, auto: bool, locale: str,
) -> None:
    # Strikes are recorded by the caller (note_out_of_scope) so refusals and flagged
    # messages feed a single counter.
    strikes = _count(db, "companion_oos", user_key, OOS_WINDOW)
    if strikes < ABUSE_THRESHOLD:
        return  # a few refusals are normal: no alert, no action
    actions = [
        _mute(db, user_key, MUTE_ABUSE_MINUTES)
        if auto
        else ActionResult("mute", False, "réponse automatique désactivée")
    ]
    _alert(
        db, signal=out.signal, severity="faible",
        summary=f"Abus répétés du compagnon ({strikes} en 10 min)",
        user_key=user_key, ip=ip, detector=detector, confidence=confidence,
        actions=actions, auto=auto,
    )
    for action in actions:
        out.actions.append(action)
        if auto:
            _audit_action(db, action, signal=out.signal, user_key=user_key, ip=ip)
    if actions[0].applied:
        out.notices.append(t(
            "Le compagnon est suspendu pour vous pendant {minutes} min.", locale,
            minutes=MUTE_ABUSE_MINUTES))


# ── ModSecurity: verified automatic ban ─────────────────────────────────────


def _parse_ts(value: Any) -> datetime | None:
    try:
        ts = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        from datetime import UTC

        ts = ts.replace(tzinfo=UTC)
    return ts


def verify_waf_ban(db: Session, source: dict[str, Any], item: dict[str, Any]) -> list[str]:
    """Raw-event verification of a model-recommended ban. ``[]`` = verified.

    ``source`` is what the aggregator produced (counts of real ModSecurity events),
    ``item`` is the model's verdict. The verdict only *nominates*; these checks decide.
    """
    from app.security.banning.engine import is_breakglass_ban_exempt

    ip = str(source.get("client_ip") or "")
    reasons: list[str] = []
    if item.get("confidence") not in ("moyenne", "elevee"):
        reasons.append("confiance du modèle trop faible")
    if item.get("category") in WAF_REFUSED_CATEGORIES:
        reasons.append("catégorie non malveillante ou indéterminée")
    if int(source.get("evenements") or 0) < WAF_MIN_EVENTS:
        reasons.append(f"moins de {WAF_MIN_EVENTS} événements")
    if int(source.get("bloques") or 0) < WAF_MIN_BLOCKED:
        reasons.append(f"moins de {WAF_MIN_BLOCKED} événements bloqués")
    if int(source.get("critiques") or 0) < WAF_MIN_CRITICAL:
        reasons.append(f"moins de {WAF_MIN_CRITICAL} règles critiques déclenchées")
    if len(source.get("regles") or {}) < WAF_MIN_RULES:
        reasons.append(f"moins de {WAF_MIN_RULES} règles distinctes")
    last = _parse_ts(source.get("dernier"))
    if last is None or utcnow().replace(tzinfo=last.tzinfo) - last > WAF_FRESHNESS:
        reasons.append("activité non récente (plus de 30 min)")
    if source.get("ip_privee") or is_internal_ip(ip):
        reasons.append("IP interne")
    if source.get("deja_banni"):
        reasons.append("IP déjà bannie")
    if is_breakglass_ban_exempt(db, ip):
        reasons.append("IP en liste blanche ou break-glass LAN")
    try:
        known = (
            db.query(func.count(ActiveSession.id))
            .filter(ActiveSession.kind == "user", ActiveSession.source_ip == ip,
                    ActiveSession.last_seen_at >= utcnow() - timedelta(hours=24))
            .scalar()
            or 0
        )
    except Exception:  # noqa: BLE001
        db.rollback()
        known = 1
    if known:
        reasons.append("IP utilisée par une session authentifiée récente")
    if _recent_auto_bans(db, "system:llm", timedelta(hours=1)) >= WAF_MAX_AUTO_BANS_PER_HOUR:
        reasons.append("plafond de bans automatiques atteint")
    return reasons


def apply_verified_waf_ban(
    db: Session, source: dict[str, Any], item: dict[str, Any]
) -> tuple[bool, list[str]]:
    """Ban the IP if (and only if) raw ModSecurity data verifies the verdict."""
    ip = str(source.get("client_ip") or "")
    reasons = verify_waf_ban(db, source, item)
    if not reasons:
        from app.security.banning.engine import apply_ban

        minutes = max(15, min(int(item.get("ban_minutes") or 60), WAF_MAX_BAN_MINUTES))
        ban = apply_ban(
            db,
            target_type="ip",
            target=ip,
            reason=(
                f"IA (automatique, vérifié ModSecurity) — {item.get('category')}, "
                f"gravité {item.get('severity')}"
            ),
            rule_type="llm_waf_auto",
            permanent=False,
            ban_minutes=minutes,
            actor="system:llm",
            ip_address=ip,
        )
        if ban is None:
            reasons.append("refusé par le moteur de ban")
        else:
            log_action(
                db, "system:llm", "ai.auto_response", target=f"ip:{ip}",
                details={"kind": "ban_ip", "applied": True, "minutes": minutes,
                         "category": item.get("category"), "severity": item.get("severity"),
                         "events": source.get("evenements"), "blocked": source.get("bloques"),
                         "critical": source.get("critiques")},
                ip_address=ip,
            )
            return True, []
    log_action(
        db, "system:llm", "ai.auto_response_skipped", target=f"ip:{ip}",
        details={"kind": "ban_ip", "applied": False, "reasons": reasons},
        ip_address=ip, forward_to_siem=False,
    )
    return False, reasons


__all__ = [
    "ACTOR",
    "Outcome",
    "SIGNALS",
    "SIGNAL_ABUSE",
    "SIGNAL_ATTACK",
    "SIGNAL_COMPROMISED",
    "SIGNAL_NONE",
    "SIGNAL_PHISHING_HIT",
    "SIGNAL_PHISHING_RECEIVED",
    "apply_verified_waf_ban",
    "detect_local",
    "mute_remaining_minutes",
    "note_out_of_scope",
    "respond",
    "verify_waf_ban",
]
