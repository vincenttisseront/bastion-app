"""ModSecurity virtual-patch pack catalog + export overlay.

Packs are pre-CRS rule files under docker/nginx/modsecurity/. Mode is stored on
WafProfile (off | detection | on) and rendered into
generated/bastion-virtual-patches-enabled.conf.

Detection mode Includes the pack then SecRuleUpdateActionById → pass,log for
each pack rule so the family SecRuleEngine (On / DetectionOnly) is untouched.
Using ctl:ruleEngine=On as a restore would incorrectly promote a DetectionOnly
family engine mid-request.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.bastion.modsec_audit_aggregator import (
    CRS_RULE_LABELS,
    read_audit_summary,
    resolve_audit_summary_path,
)
from app.bastion.nginx_waf_export import MODE_DETECTION, MODE_OFF, MODE_ON
from app.models import WafProfile
from app.sso_settings import Settings

PACK_PHP2SHELL = "php2shell"

PACK_MODE_OFF = "off"
PACK_MODE_DETECTION = "detection"
PACK_MODE_ON = "on"
VALID_PACK_MODES = frozenset({PACK_MODE_OFF, PACK_MODE_DETECTION, PACK_MODE_ON})

REPO_MODSEC = (
    Path(__file__).resolve().parents[2] / "docker" / "nginx" / "modsecurity"
)
VIRTUAL_PATCHES_ENABLED_FILENAME = "bastion-virtual-patches-enabled.conf"
VIRTUAL_PATCHES_SOURCE = "/etc/nginx/modsecurity/bastion-virtual-patches.conf"

AUDIT_STALE_SECONDS = 3600
AUDIT_SIZE_WARN_BYTES = 50 * 1024 * 1024

# Registry — add packs here; each needs a conf file + WafProfile mode column.
PACK_CATALOG: dict[str, dict[str, Any]] = {
    PACK_PHP2SHELL: {
        "id": PACK_PHP2SHELL,
        "name": "PHP2Shell",
        "severity": "critical",
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "summary": (
            "Mitigations edge pour RCE PHP core (session upload progress / "
            "multipart) en attendant le patch PHP origin."
        ),
        "detail": (
            "Règles pre-CRS : PHPSESSID en champ POST, PHP_SESSION_UPLOAD_PROGRESS, "
            "balises PHP dans les noms de fichiers uploadés, multipart fortement "
            "imbriqué, multipart sans Content-Length."
        ),
        "conf_basename": "bastion-virtual-patches.conf",
        "include_path": VIRTUAL_PATCHES_SOURCE,
        "profile_attr": "patch_php2shell_mode",
        "legacy_bool_attr": "patch_php2shell_enabled",
        "default_mode": PACK_MODE_ON,
        "rules": [
            {
                "id": "100096180",
                "title": "PHPSESSID en champ POST",
                "phase": 2,
                "action": "deny/403",
                "targets": "ARGS_POST_NAMES",
            },
            {
                "id": "100096181",
                "title": "PHP_SESSION_UPLOAD_PROGRESS",
                "phase": 2,
                "action": "deny/403",
                "targets": "ARGS_POST_NAMES",
            },
            {
                "id": "100096182",
                "title": "Balise PHP dans nom de fichier uploadé",
                "phase": 2,
                "action": "deny/403",
                "targets": "FILES",
            },
            {
                "id": "100096183",
                "title": "Multipart imbriqué (≥12 niveaux)",
                "phase": 2,
                "action": "deny/403",
                "targets": "ARGS_POST_NAMES|FILES_NAMES",
            },
            {
                "id": "100096184",
                "title": "Multipart sans Content-Length",
                "phase": 1,
                "action": "deny/403",
                "targets": "REQUEST_HEADERS",
            },
        ],
    },
}

PACK_IDS = frozenset(PACK_CATALOG.keys())
PHP2SHELL_RULE_IDS = frozenset(
    r["id"] for r in PACK_CATALOG[PACK_PHP2SHELL]["rules"]
)
_PACK_RULE_LABELS: dict[str, str] = {
    r["id"]: r["title"]
    for meta in PACK_CATALOG.values()
    for r in (meta.get("rules") or [])
}


def list_pack_ids() -> list[str]:
    return sorted(PACK_CATALOG.keys())


def get_pack_def(pack_id: str) -> dict[str, Any] | None:
    return PACK_CATALOG.get((pack_id or "").strip().lower())


def normalize_pack_mode(value: Any, *, default: str = PACK_MODE_ON) -> str:
    raw = str(value or "").strip().lower()
    if raw in VALID_PACK_MODES:
        return raw
    if raw in ("1", "true", "yes", "on"):
        return PACK_MODE_ON
    if raw in ("0", "false", "no", "off"):
        return PACK_MODE_OFF
    if raw in ("detection_only", "detect", "dos"):
        return PACK_MODE_DETECTION
    return default if default in VALID_PACK_MODES else PACK_MODE_OFF


def profile_pack_mode(profile: WafProfile, pack_id: str) -> str:
    meta = get_pack_def(pack_id)
    if not meta:
        return PACK_MODE_OFF
    default = normalize_pack_mode(meta.get("default_mode"), default=PACK_MODE_ON)
    attr = str(meta.get("profile_attr") or "")
    if attr and hasattr(profile, attr):
        return normalize_pack_mode(getattr(profile, attr), default=default)
    legacy = str(meta.get("legacy_bool_attr") or "")
    if legacy and hasattr(profile, legacy):
        return (
            PACK_MODE_ON
            if bool(getattr(profile, legacy, default == PACK_MODE_ON))
            else PACK_MODE_OFF
        )
    return default


def profile_pack_enabled(profile: WafProfile, pack_id: str) -> bool:
    """True when the pack Include is generated (detection or on)."""
    return profile_pack_mode(profile, pack_id) != PACK_MODE_OFF


def set_profile_pack_mode(profile: WafProfile, pack_id: str, *, mode: str) -> str:
    meta = get_pack_def(pack_id)
    if not meta:
        raise ValueError(f"pack ModSecurity inconnu: {pack_id}")
    attr = str(meta.get("profile_attr") or "")
    if not attr:
        raise ValueError(f"pack {pack_id} non pilotable (pas d'attribut profil)")
    normalized = normalize_pack_mode(mode, default=PACK_MODE_OFF)
    if normalized not in VALID_PACK_MODES:
        raise ValueError(f"mode pack invalide: {mode}")
    setattr(profile, attr, normalized)
    legacy = str(meta.get("legacy_bool_attr") or "")
    if legacy and hasattr(profile, legacy):
        setattr(profile, legacy, normalized != PACK_MODE_OFF)
    return normalized


def set_profile_pack_enabled(
    profile: WafProfile, pack_id: str, *, enabled: bool
) -> None:
    """Backward-compatible boolean toggle → on | off."""
    set_profile_pack_mode(
        profile, pack_id, mode=PACK_MODE_ON if enabled else PACK_MODE_OFF
    )


def profile_packs_modes(profile: WafProfile) -> dict[str, str]:
    return {pack_id: profile_pack_mode(profile, pack_id) for pack_id in PACK_CATALOG}


def enabled_pack_includes(profile: WafProfile) -> list[str]:
    paths: list[str] = []
    for pack_id, meta in PACK_CATALOG.items():
        if profile_pack_enabled(profile, pack_id):
            paths.append(str(meta.get("include_path") or ""))
    return [p for p in paths if p]


def _render_detection_block(meta: dict[str, Any], pack_id: str) -> list[str]:
    """Include pack rules then downgrade deny → pass,log (engine mode unchanged)."""
    include_path = str(meta.get("include_path") or "")
    rules = list(meta.get("rules") or [])
    lines = [
        f"# Pack {pack_id} mode=detection — Include then pass,log (no family engine change)",
        f"Include {include_path}",
    ]
    for rule in rules:
        rid = str(rule.get("id") or "").strip()
        if not rid.isdigit():
            continue
        phase = int(rule.get("phase") or 2)
        title = str(rule.get("title") or pack_id).replace('"', "'")[:80]
        lines.append(
            f"SecRuleUpdateActionById {rid} "
            f'"phase:{phase},pass,log,auditlog,'
            f"msg:'{pack_id} detection: {title}'\""
        )
    if len(lines) == 2:
        lines.append(f"# Pack {pack_id}: no rule ids to retarget")
    return lines


def render_virtual_patches_enabled_conf(*, php2shell_enabled: bool) -> str:
    """Backward-compatible helper used by export tests."""
    return render_virtual_patches_enabled_conf_from_modes(
        {
            PACK_PHP2SHELL: (
                PACK_MODE_ON if php2shell_enabled else PACK_MODE_OFF
            )
        }
    )


def render_virtual_patches_enabled_conf_from_flags(
    enabled_by_pack: dict[str, bool],
) -> str:
    modes = {
        pack_id: (PACK_MODE_ON if on else PACK_MODE_OFF)
        for pack_id, on in enabled_by_pack.items()
    }
    return render_virtual_patches_enabled_conf_from_modes(modes)


def render_virtual_patches_enabled_conf_from_modes(
    mode_by_pack: dict[str, str],
) -> str:
    lines = [
        "# Generated by nginx_waf_export — do not edit",
        "# Included from main-*.conf (pre-CRS virtual-patch packs).",
        "# Pack modes: off | detection | on",
    ]
    any_loaded = False
    for pack_id, meta in PACK_CATALOG.items():
        mode = normalize_pack_mode(
            mode_by_pack.get(pack_id, meta.get("default_mode")),
            default=PACK_MODE_OFF,
        )
        include_path = str(meta.get("include_path") or "")
        cves = ", ".join(meta.get("cves") or [])
        if mode == PACK_MODE_OFF or not include_path:
            lines.append(f"# Pack {pack_id} disabled.")
            continue
        any_loaded = True
        if mode == PACK_MODE_DETECTION:
            lines.append(f"# Pack {pack_id} detection ({cves}).")
            lines.extend(_render_detection_block(meta, pack_id))
        else:
            lines.append(f"# Pack {pack_id} enabled/on ({cves}).")
            lines.append(f"Include {include_path}")
    if not any_loaded:
        lines.append("# (no virtual-patch packs enabled)")
    lines.append("")
    return "\n".join(lines)


def render_virtual_patches_enabled_for_profile(profile: WafProfile) -> str:
    return render_virtual_patches_enabled_conf_from_modes(profile_packs_modes(profile))


def _audit_hints_for_pack(pack_id: str, summary: dict[str, Any]) -> dict[str, Any]:
    if pack_id != PACK_PHP2SHELL:
        return {"signal": False, "reasons": []}
    if not summary.get("present"):
        return {"signal": False, "reasons": []}
    reasons: list[str] = []
    windows = summary.get("windows") or {}
    data = windows.get("7d") or windows.get("24h") or {}
    families = data.get("families") or {}
    if int(families.get("php") or 0) > 0:
        reasons.append("famille CRS php active dans l'audit")
    if int(families.get("rce") or 0) > 0:
        reasons.append("famille CRS rce active dans l'audit")
    rules = data.get("top_rules") or summary.get("top_rules") or []
    for item in rules:
        if not isinstance(item, dict):
            continue
        rid = str(item.get("rule_id") or item.get("id") or "").strip()
        if rid in PHP2SHELL_RULE_IDS:
            reasons.append(f"règle virtual-patch {rid} déjà vue")
            break
        label = str(item.get("label") or item.get("message") or "").lower()
        if "multipart" in label or "php" in label:
            reasons.append("règles multipart/php dans le top audit")
            break
    for ev in (summary.get("recent_events") or [])[:40]:
        if not isinstance(ev, dict):
            continue
        msg = str(ev.get("message") or "").lower()
        if "php2shell" in msg or "php_session_upload" in msg:
            reasons.append("événement audit tagué php2shell / upload_progress")
            break
    seen: set[str] = set()
    uniq = [r for r in reasons if not (r in seen or seen.add(r))]  # type: ignore[func-returns-value]
    return {"signal": bool(uniq), "reasons": uniq}


def _rule_severity(rule_id: str) -> tuple[str, str]:
    """Return (level, css_badge) for a CRS / Bastion rule id."""
    rid = (rule_id or "").strip()
    if rid in _PACK_RULE_LABELS or rid in PHP2SHELL_RULE_IDS:
        return "critical", "badge-err"
    if rid.startswith("942") or rid.startswith("932") or rid.startswith("933"):
        return "high", "badge-err"
    if rid.startswith("941") or rid.startswith("930") or rid.startswith("931"):
        return "high", "badge-warn"
    if rid.startswith("92") or rid.startswith("913"):
        return "medium", "badge-warn"
    return "low", "badge-muted"


def _rule_short_label(rule_id: str, fallback: str = "") -> str:
    rid = (rule_id or "").strip()
    if rid in _PACK_RULE_LABELS:
        return _PACK_RULE_LABELS[rid]
    if rid in CRS_RULE_LABELS:
        return CRS_RULE_LABELS[rid]
    return (fallback or "").strip() or f"Règle {rid}"


def build_top_rules_live(summary: dict[str, Any], *, limit: int = 5) -> list[dict[str, Any]]:
    windows = summary.get("windows") if isinstance(summary, dict) else None
    data: dict[str, Any] = {}
    if isinstance(windows, dict):
        data = windows.get("24h") or windows.get("7d") or {}
    rules = []
    if isinstance(data, dict):
        rules = data.get("top_rules") or []
    if not rules:
        rules = (summary or {}).get("top_rules") or []
    out: list[dict[str, Any]] = []
    for item in rules:
        if not isinstance(item, dict):
            continue
        rid = str(item.get("rule_id") or item.get("id") or "").strip()
        if not rid:
            continue
        count = int(item.get("count") or item.get("hits") or 0)
        label = _rule_short_label(rid, str(item.get("label") or ""))
        sev, css = _rule_severity(rid)
        out.append(
            {
                "rule_id": rid,
                "label": label,
                "count": count,
                "severity": sev,
                "css": css,
                "source": "pack" if rid in _PACK_RULE_LABELS else "crs",
            }
        )
        if len(out) >= limit:
            break
    return out


def build_audit_health(
    settings: Settings,
    summary: dict[str, Any] | None = None,
    *,
    traffic_active: bool = False,
) -> dict[str, Any]:
    """Green / orange / red pill for waf-audit-summary.json freshness & size."""
    path = resolve_audit_summary_path(settings)
    summary = summary if summary is not None else read_audit_summary(settings)
    now = time.time()
    result: dict[str, Any] = {
        "path": str(path),
        "exists": False,
        "readable": False,
        "size_bytes": 0,
        "mtime_age_seconds": None,
        "stale": False,
        "oversized": False,
        "level": "red",
        "css": "badge-err",
        "label": "Audit indisponible",
        "detail": "Fichier waf-audit-summary.json absent ou illisible.",
    }
    try:
        st = path.stat()
    except OSError:
        return result

    result["exists"] = True
    result["size_bytes"] = int(st.st_size)
    age = max(0, int(now - st.st_mtime))
    result["mtime_age_seconds"] = age
    result["stale"] = age > AUDIT_STALE_SECONDS
    result["oversized"] = st.st_size > AUDIT_SIZE_WARN_BYTES

    readable = os.access(path, os.R_OK)
    result["readable"] = readable
    if not readable:
        result["level"] = "red"
        result["css"] = "badge-err"
        result["label"] = "Audit illisible"
        result["detail"] = "Permissions en lecture manquantes sur le résumé d'audit."
        return result

    if not summary.get("present"):
        result["level"] = "orange"
        result["css"] = "badge-warn"
        result["label"] = "Audit vide"
        result["detail"] = "Fichier présent mais résumé non exploitable."
        return result

    if result["oversized"]:
        result["level"] = "orange"
        result["css"] = "badge-warn"
        result["label"] = "Audit volumineux"
        result["detail"] = (
            f"Résumé > {AUDIT_SIZE_WARN_BYTES // (1024 * 1024)} Mo — "
            "vérifier la rotation des logs."
        )
        return result

    if result["stale"] and traffic_active:
        result["level"] = "orange"
        result["css"] = "badge-warn"
        result["label"] = "Audit périmé"
        result["detail"] = (
            f"Dernière mise à jour il y a {age // 60} min alors que le trafic "
            "WAF est actif."
        )
        return result

    if result["stale"]:
        result["level"] = "orange"
        result["css"] = "badge-warn"
        result["label"] = "Audit silencieux"
        result["detail"] = f"Pas de rafraîchissement depuis {age // 60} min."
        return result

    result["level"] = "green"
    result["css"] = "badge-ok"
    result["label"] = "Audit OK"
    result["detail"] = f"Résumé à jour ({age // 60} min)."
    return result


def _exported_pack_modes(effective: dict[str, Any] | None) -> dict[str, str]:
    effective = effective or {}
    raw = effective.get("virtual_packs")
    if isinstance(raw, dict) and raw:
        return {
            str(k): normalize_pack_mode(v, default=PACK_MODE_OFF) for k, v in raw.items()
        }
    # Legacy export only had a boolean for php2shell.
    if "patch_php2shell_enabled" in effective:
        return {
            PACK_PHP2SHELL: (
                PACK_MODE_ON
                if bool(effective.get("patch_php2shell_enabled"))
                else PACK_MODE_OFF
            )
        }
    return {}


def _engine_family_row(
    *,
    label: str,
    mode: str | None,
    armed: bool | None,
    note: str,
) -> dict[str, Any]:
    m = (mode or MODE_OFF).strip().lower() or MODE_OFF
    if m == MODE_ON:
        css, state = "badge-err", "On (blocage)"
    elif m == MODE_DETECTION:
        css, state = "badge-warn", "DetectionOnly"
    else:
        css, state = "badge-muted", "Off"
    return {
        "label": label,
        "mode": m,
        "state": state,
        "css": css,
        "armed": armed,
        "note": note,
    }


def build_modsecurity_page(
    db: Session,
    settings: Settings,
    profile: WafProfile,
    *,
    active: dict[str, Any] | None = None,
    reactivation: dict[str, Any] | None = None,
    effective: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Full ModSecurity management panel for Admin → WAF → ModSecurity."""
    from app.bastion.nginx_waf_export import read_effective_status
    from app.bastion.nginx_waf_reality import portal_engine_mode, subdomain_engine_mode

    active = active or {}
    reactivation = reactivation or {}
    if effective is None:
        effective = read_effective_status(settings)
    summary = read_audit_summary(settings)
    portal_mode = portal_engine_mode(active) if active.get("verifiable") else None
    subdomain_mode = (
        subdomain_engine_mode(active) if active.get("verifiable") else None
    )
    families = active.get("families") if isinstance(active.get("families"), dict) else {}
    public_fam = families.get("public") if isinstance(families, dict) else None
    public_mode = None
    if isinstance(public_fam, dict):
        public_mode = str(
            public_fam.get("sec_rule_engine") or public_fam.get("mode") or ""
        ).lower() or None

    engine_rows = [
        _engine_family_row(
            label="Portal",
            mode=portal_mode or (MODE_DETECTION if reactivation.get("armed") else MODE_OFF),
            armed=bool(reactivation.get("armed")),
            note="Connecteur + overlay engine-mode-generated (armé via Réactivation).",
        ),
        _engine_family_row(
            label="Subdomain",
            mode=subdomain_mode
            or (
                MODE_DETECTION
                if reactivation.get("subdomain_armed")
                else MODE_OFF
            ),
            armed=bool(reactivation.get("subdomain_armed")),
            note="FQDN subdomain_proxy — promotion On après observation.",
        ),
        _engine_family_row(
            label="Public",
            mode=public_mode or MODE_OFF,
            armed=False,
            note="Pas d'armement public : SecRuleEngine reste Off (by design).",
        ),
    ]

    traffic_active = bool(
        reactivation.get("armed")
        or reactivation.get("subdomain_armed")
        or (portal_mode in (MODE_ON, MODE_DETECTION))
        or (subdomain_mode in (MODE_ON, MODE_DETECTION))
    )
    audit_health = build_audit_health(
        settings, summary, traffic_active=traffic_active
    )
    top_rules = build_top_rules_live(summary, limit=5)
    exported_modes = _exported_pack_modes(effective if effective.get("present") else {})

    packs: list[dict[str, Any]] = []
    any_suggest = False
    any_deploy_pending = False
    enabled_count = 0
    for pack_id, meta in PACK_CATALOG.items():
        mode = profile_pack_mode(profile, pack_id)
        enabled = mode != PACK_MODE_OFF
        if enabled:
            enabled_count += 1
        hints = _audit_hints_for_pack(pack_id, summary)
        suggest = (mode == PACK_MODE_OFF) and bool(hints.get("signal"))
        if suggest:
            any_suggest = True
        conf_name = str(meta.get("conf_basename") or "")
        source_present = (REPO_MODSEC / conf_name).is_file() if conf_name else False
        exported = exported_modes.get(pack_id)
        deploy_pending = bool(
            effective.get("present") and exported is not None and exported != mode
        )
        if not effective.get("present") and mode != normalize_pack_mode(
            meta.get("default_mode"), default=PACK_MODE_ON
        ):
            # No export yet but DB differs from image default → pending apply.
            deploy_pending = True
        if deploy_pending:
            any_deploy_pending = True
        packs.append(
            {
                "id": pack_id,
                "name": meta["name"],
                "severity": meta.get("severity") or "medium",
                "cves": list(meta.get("cves") or []),
                "summary": meta.get("summary") or "",
                "detail": meta.get("detail") or "",
                "mode": mode,
                "enabled": enabled,
                "rules": list(meta.get("rules") or []),
                "rule_ids": [r["id"] for r in (meta.get("rules") or [])],
                "rule_count": len(meta.get("rules") or []),
                "source_present": source_present,
                "conf_basename": conf_name,
                "suggest_enable": suggest,
                "suggest_reasons": hints.get("reasons") or [],
                "toggleable": bool(meta.get("profile_attr")),
                "deploy_pending": deploy_pending,
                "exported_mode": exported,
            }
        )

    threshold = int(getattr(profile, "anomaly_threshold", 5) or 5)
    from app.bastion.nginx_waf_export import clamp_paranoia_level

    paranoia = clamp_paranoia_level(getattr(profile, "paranoia_level", 1))
    from app.bastion.waf_sandbox import build_sandbox_readiness

    sandbox = build_sandbox_readiness(
        settings, active=active, audit_health=audit_health
    )
    return {
        "engine_rows": engine_rows,
        "audit_health": audit_health,
        "top_rules": top_rules,
        "sandbox": sandbox,
        "crs": {
            "setup_version": "4.28.0",
            "paranoia": paranoia,
            "anomaly_threshold": threshold,
            "profile_mode": profile.mode,
            "body_access": True,
            "audit_engine": "RelevantOnly",
            "include_chain": [
                "engine-*.conf",
                "modsecurity.conf",
                "crs-setup.conf",
                "crs-setup-generated.conf",
                "bastion-virtual-patches-enabled.conf (packs)",
                "owasp-crs/rules/*.conf",
                "waf-basic.conf",
                "bastion-exclusions-generated.conf",
                "engine-*-mode-generated.conf (dernier)",
            ],
        },
        "packs": packs,
        "packs_enabled_count": enabled_count,
        "packs_total": len(packs),
        "any_suggest_enable": any_suggest,
        "any_deploy_pending": any_deploy_pending,
        "summary_present": bool(summary.get("present")),
    }


def build_virtual_patches_panel(
    db: Session,
    settings: Settings,
    profile: WafProfile,
) -> dict[str, Any]:
    """Compat shim — prefer build_modsecurity_page for the UI tab."""
    page = build_modsecurity_page(db, settings, profile)
    return {
        "packs": page["packs"],
        "any_suggest_enable": page["any_suggest_enable"],
    }
