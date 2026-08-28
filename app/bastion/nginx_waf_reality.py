"""Read nginx ModSecurity / CRS effective state for WAF admin UI (Phase B lot 2.1).

Production truth comes from a JSON snapshot written by ``bastion-nginx`` into the shared
``nginx-logs`` volume (``nginx-waf-snapshot.json``). The app never reads ``docker/nginx``
from the repo for the « réellement actif » column and never uses ``docker.sock``.

Optional repo read (``BASTION_NGINX_CONF_ROOT``) is exposed separately as « Repo (intention) »
for local dev — never as live nginx state.

Never writes SecRuleEngine or include chains.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.bastion.nginx_waf_export import (
    MODE_DETECTION,
    MODE_OFF,
    MODE_ON,
    clamp_anomaly_threshold,
    read_effective_status,
)
from app.models import WafExclusion, WafProfile
from app.sso_settings import Settings

WAF_FAMILIES = ("portal", "subdomain", "public")
SNAPSHOT_SCHEMA_VERSION = 1
DEFAULT_STALE_MINUTES = 15

_SEC_ENGINE_RE = re.compile(
    r"^\s*SecRuleEngine\s+(Off|On|DetectionOnly)\s*(?:#.*)?$",
    re.MULTILINE | re.IGNORECASE,
)
_INCLUDE_RE = re.compile(
    r'^\s*Include\s+(/etc/nginx/modsecurity/[^\s#]+|/etc/nginx/modsecurity/generated/[^\s#]+)\s*(?:#.*)?$',
    re.MULTILINE,
)
_THRESHOLD_RE = re.compile(
    r"setvar:tx\.inbound_anomaly_score_threshold=(\d+)",
    re.IGNORECASE,
)
_ADD_HEADER_RE = re.compile(
    r'add_header\s+(\S+)\s+"([^"]*)"\s+always\s*;',
    re.IGNORECASE,
)

_ENGINE_NORM = {
    "off": MODE_OFF,
    "on": MODE_ON,
    "detectiononly": MODE_DETECTION,
    "detection_only": MODE_DETECTION,
}

_UNDEFINED_HEADERS = (
    "Content-Security-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
)


def resolve_nginx_waf_snapshot_path(settings: Settings | None = None) -> Path:
    """Absolute path to the nginx-produced WAF snapshot JSON."""
    env = os.environ.get("BASTION_NGINX_WAF_SNAPSHOT_PATH", "").strip()
    if env:
        return Path(env)
    if settings is not None:
        logs_dir = (settings.nginx_app_logs_dir or "").strip()
        if not logs_dir:
            logs_dir = str(Path(settings.portal_data_dir) / "nginx-logs")
        return Path(logs_dir) / "nginx-waf-snapshot.json"
    return Path("/var/lib/sso-portal/nginx-logs/nginx-waf-snapshot.json")


def resolve_nginx_conf_root() -> Path | None:
    """Optional repo checkout root for dev « Repo (intention) » panel only."""
    env = os.environ.get("BASTION_NGINX_CONF_ROOT", "").strip()
    if env:
        root = Path(env)
        if (root / "modsecurity" / "main-portal.conf").is_file():
            return root
    return None


def snapshot_stale_minutes() -> int:
    raw = os.environ.get("BASTION_NGINX_SNAPSHOT_STALE_MINUTES", "").strip()
    if not raw:
        return DEFAULT_STALE_MINUTES
    try:
        return max(1, int(raw))
    except ValueError:
        return DEFAULT_STALE_MINUTES


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def last_sec_rule_engine(text: str) -> str | None:
    """Return normalized mode (off/on/detection_only) from last SecRuleEngine line."""
    matches = _SEC_ENGINE_RE.findall(text or "")
    if not matches:
        return None
    raw = matches[-1].lower()
    return _ENGINE_NORM.get(raw, raw)


def parse_inbound_anomaly_threshold(text: str) -> int | None:
    matches = _THRESHOLD_RE.findall(text or "")
    if not matches:
        return None
    try:
        return int(matches[-1])
    except ValueError:
        return None


def _parse_generated_at(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _freshness_minutes(generated_at: datetime | None) -> int | None:
    if generated_at is None:
        return None
    delta = datetime.now(timezone.utc) - generated_at
    return max(0, int(delta.total_seconds() // 60))


def _docker_path_to_local(nginx_root: Path, docker_path: str) -> Path | None:
    """Map ``/etc/nginx/modsecurity/...`` to files under an explicit nginx conf root."""
    prefix = "/etc/nginx/modsecurity/"
    gen_prefix = "/etc/nginx/modsecurity/generated/"
    if docker_path.startswith(gen_prefix):
        rel = docker_path[len(gen_prefix) :]
        local = nginx_root / "modsecurity" / "generated" / rel
        if local.is_file():
            return local
        exports_stub = nginx_root.parents[1] / "exports" / "modsecurity" / rel
        if exports_stub.is_file():
            return exports_stub
        return None
    if docker_path.startswith(prefix):
        rel = docker_path[len(prefix) :]
        return nginx_root / "modsecurity" / rel
    return None


def _includes_from_main(main_text: str) -> list[str]:
    return _INCLUDE_RE.findall(main_text or "")


def _effective_engine_for_family(
    nginx_root: Path,
    family: str,
    *,
    engine_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Walk main-{family}.conf include chain from an explicit repo root (dev only)."""
    main_path = nginx_root / "modsecurity" / f"main-{family}.conf"
    main_text = _read_text(main_path)
    includes = _includes_from_main(main_text)
    engine_mode_gen_loaded = any(
        "engine-mode-generated.conf" in inc for inc in includes
    )
    crs_setup_gen_loaded = any(
        "crs-setup-generated.conf" in inc for inc in includes
    )

    combined = ""
    engine_source = None
    for inc in includes:
        local = _docker_path_to_local(nginx_root, inc)
        if local is None:
            if "engine-mode-generated.conf" in inc:
                stub = "SecRuleEngine Off\n"
                if engine_overrides and family in engine_overrides:
                    stub = f"SecRuleEngine {engine_overrides[family]}\n"
                combined += stub
                engine_source = str(inc)
            continue
        chunk = _read_text(local)
        combined += chunk + "\n"
        if "engine-" in inc and inc.endswith(".conf") and "generated" not in inc:
            engine_source = str(local)

    mode = last_sec_rule_engine(combined)
    crs_path = nginx_root / "modsecurity" / "crs-setup.conf"
    threshold = parse_inbound_anomaly_threshold(_read_text(crs_path))
    threshold_source = "crs-setup.conf (statique)"
    if crs_setup_gen_loaded:
        gen = _docker_path_to_local(
            nginx_root, "/etc/nginx/modsecurity/generated/crs-setup-generated.conf"
        )
        if gen and gen.is_file():
            t2 = parse_inbound_anomaly_threshold(_read_text(gen))
            if t2 is not None:
                threshold = t2
                threshold_source = str(gen.name)

    static_engine = last_sec_rule_engine(
        _read_text(nginx_root / "modsecurity" / f"engine-{family}.conf")
    )

    return {
        "family": family,
        "main_conf": str(main_path) if main_path.is_file() else None,
        "engine_file": str(nginx_root / "modsecurity" / f"engine-{family}.conf"),
        "sec_rule_engine": mode,
        "sec_rule_engine_static": static_engine,
        "engine_source": engine_source,
        "anomaly_threshold": threshold,
        "anomaly_source": threshold_source,
        "engine_mode_generated_loaded": engine_mode_gen_loaded,
        "crs_setup_generated_loaded": crs_setup_gen_loaded,
    }


def read_nginx_waf_reality_from_repo(
    *,
    nginx_root: Path,
    engine_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Dev-only repo parse — never presented as live nginx state."""
    families: dict[str, dict[str, Any]] = {}
    for fam in WAF_FAMILIES:
        families[fam] = _effective_engine_for_family(
            nginx_root, fam, engine_overrides=engine_overrides
        )

    modes = {f["sec_rule_engine"] for f in families.values() if f.get("sec_rule_engine")}
    thresholds = {
        f["anomaly_threshold"]
        for f in families.values()
        if f.get("anomaly_threshold") is not None
    }
    aggregate_mode = modes.pop() if len(modes) == 1 else ("mixed" if modes else None)
    aggregate_threshold = (
        thresholds.pop() if len(thresholds) == 1 else ("mixed" if thresholds else None)
    )

    return {
        "present": True,
        "verifiable": False,
        "nginx_root": str(nginx_root),
        "source_kind": "repo_intent",
        "column_title": "Repo (intention)",
        "verified_in_container": False,
        "source_note": (
            "Lu depuis le checkout git (BASTION_NGINX_CONF_ROOT) — intention versionnée, "
            "pas l'état du conteneur nginx."
        ),
        "families": families,
        "aggregate_mode": aggregate_mode,
        "aggregate_threshold": aggregate_threshold,
        "engine_mode_generated_loaded": any(
            f.get("engine_mode_generated_loaded") for f in families.values()
        ),
        "crs_setup_generated_loaded": any(
            f.get("crs_setup_generated_loaded") for f in families.values()
        ),
        "freshness_minutes": None,
        "stale": False,
        "generated_at": None,
    }


def _snapshot_to_reality(data: dict[str, Any], *, path: Path) -> dict[str, Any]:
    families_raw = data.get("families") or {}
    families: dict[str, dict[str, Any]] = {}
    for fam in WAF_FAMILIES:
        entry = families_raw.get(fam)
        if isinstance(entry, dict):
            families[fam] = entry

    generated_at = _parse_generated_at(data.get("generated_at"))
    freshness = _freshness_minutes(generated_at)
    stale_threshold = snapshot_stale_minutes()
    stale = freshness is None or freshness > stale_threshold

    return {
        "present": True,
        "verifiable": True,
        "snapshot_path": str(path),
        "source_kind": "nginx_container_snapshot",
        "column_title": "Réellement actif (nginx)",
        "verified_in_container": True,
        "source_note": (
            "Instantané produit par bastion-nginx (nginx -T + fichiers chargés) "
            f"dans {path.name}."
        ),
        "families": families,
        "aggregate_mode": data.get("aggregate_mode"),
        "aggregate_threshold": data.get("aggregate_threshold"),
        "engine_mode_generated_loaded": bool(data.get("engine_mode_generated_loaded")),
        "crs_setup_generated_loaded": bool(data.get("crs_setup_generated_loaded")),
        "generated_at": data.get("generated_at"),
        "freshness_minutes": freshness,
        "stale": stale,
        "stale_threshold_minutes": stale_threshold,
        "nginx_version": data.get("nginx_version"),
        "image_tag": data.get("image_tag"),
        "nginx_t_ok": data.get("nginx_t_ok"),
        "schema_version": data.get("schema_version"),
    }


def read_nginx_waf_snapshot(
    *,
    snapshot_path: Path | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Read nginx-produced JSON snapshot; never falls back to repo."""
    path = snapshot_path or resolve_nginx_waf_snapshot_path(settings)
    if not path.is_file():
        return {
            "present": False,
            "verifiable": False,
            "source_kind": "missing_snapshot",
            "column_title": "Réellement actif (nginx)",
            "verified_in_container": False,
            "snapshot_path": str(path),
            "error": "snapshot nginx absent ou illisible",
        }

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "present": False,
            "verifiable": False,
            "source_kind": "missing_snapshot",
            "column_title": "Réellement actif (nginx)",
            "verified_in_container": False,
            "snapshot_path": str(path),
            "error": f"snapshot illisible ({exc})",
        }

    if not isinstance(raw, dict):
        return {
            "present": False,
            "verifiable": False,
            "source_kind": "missing_snapshot",
            "column_title": "Réellement actif (nginx)",
            "snapshot_path": str(path),
            "error": "snapshot JSON invalide",
        }

    schema = raw.get("schema_version")
    if schema != SNAPSHOT_SCHEMA_VERSION:
        return {
            "present": False,
            "verifiable": False,
            "source_kind": "missing_snapshot",
            "column_title": "Réellement actif (nginx)",
            "snapshot_path": str(path),
            "error": f"schema_version incompatible ({schema!r})",
        }

    return _snapshot_to_reality(raw, path=path)


def read_nginx_waf_reality(
    *,
    settings: Settings | None = None,
    snapshot_path: Path | None = None,
) -> dict[str, Any]:
    """Live nginx state via shared snapshot only (no repo fallback)."""
    return read_nginx_waf_snapshot(snapshot_path=snapshot_path, settings=settings)


def read_security_headers_from_snapshot(
    reality: dict[str, Any],
    raw_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not reality.get("verifiable"):
        return {
            "present": False,
            "verifiable": False,
            "source_kind": "missing_snapshot",
            "source_note": "En-têtes non vérifiables — snapshot nginx absent.",
        }

    sec = (raw_snapshot or {}).get("security_headers") or {}
    headers = sec.get("headers") or []
    if not isinstance(headers, list):
        headers = []

    return {
        "present": True,
        "verifiable": True,
        "path": sec.get("path") or "/etc/nginx/includes/security-headers.conf",
        "source_kind": "nginx_container_snapshot",
        "verified_in_container": True,
        "source_note": "Lu depuis le snapshot bastion-nginx (configuration effective).",
        "headers": headers,
        "included_on_443": bool(sec.get("included_on_443")),
        "portal_vhost_note": (
            "Inclus via sync-acme-tls.sh sur les vhosts :443 (snapshot nginx)."
            if sec.get("included_on_443")
            else "Inclusion :443 non détectée dans le snapshot."
        ),
        "no_duplicate_8080": bool(sec.get("no_duplicate_8080")),
        "undefined_headers": list(_UNDEFINED_HEADERS),
        "freshness_minutes": reality.get("freshness_minutes"),
        "stale": reality.get("stale"),
    }


def read_security_headers_from_repo(*, nginx_root: Path) -> dict[str, Any]:
    headers_path = nginx_root / "includes" / "security-headers.conf"
    headers: list[dict[str, str]] = []
    if headers_path.is_file():
        for line in _read_text(headers_path).splitlines():
            m = _ADD_HEADER_RE.search(line.strip())
            if m:
                headers.append({"name": m.group(1), "value": m.group(2)})

    portal_tpl = _read_text(nginx_root / "templates" / "vhost_sso_portal.conf.template")
    acme_sync = _read_text(nginx_root / "sync-acme-tls.sh")
    included_on_443 = "includes/security-headers.conf" in acme_sync
    portal_avoids_dup = "Do not re-add" in portal_tpl or "security-headers" in portal_tpl

    return {
        "present": True,
        "verifiable": False,
        "path": str(headers_path),
        "source_kind": "repo_intent",
        "verified_in_container": False,
        "source_note": "Lu depuis BASTION_NGINX_CONF_ROOT — intention repo, pas le conteneur.",
        "headers": headers,
        "included_on_443": included_on_443,
        "portal_vhost_note": (
            "Inclus via sync-acme-tls.sh sur les vhosts :443 uniquement."
            if included_on_443
            else "Inclusion :443 non détectée dans sync-acme-tls.sh."
        ),
        "no_duplicate_8080": portal_avoids_dup,
        "undefined_headers": list(_UNDEFINED_HEADERS),
    }


def _load_raw_snapshot(
    *,
    settings: Settings | None = None,
    snapshot_path: Path | None = None,
) -> dict[str, Any] | None:
    path = snapshot_path or resolve_nginx_waf_snapshot_path(settings)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _profile_db_snapshot(profile: WafProfile, exclusions: list[WafExclusion]) -> dict[str, Any]:
    active_ex = [e for e in exclusions if e.active]
    return {
        "profile_name": profile.name,
        "mode": profile.mode,
        "anomaly_threshold": clamp_anomaly_threshold(profile.anomaly_threshold),
        "ip_deny_min_occurrences": int(profile.ip_deny_min_occurrences or 3),
        "portal_login_rate": int(profile.portal_login_rate or 3),
        "portal_api_rate": int(profile.portal_api_rate or 30),
        "portal_login_burst": int(profile.portal_login_burst or 5),
        "portal_api_burst": int(profile.portal_api_burst or 60),
        "exclusion_count": len(active_ex),
        "exclusion_rule_ids": sorted(
            int(e.crs_rule_id) for e in active_ex if e.crs_rule_id is not None
        ),
    }


def diff_db_vs_export(
    profile: WafProfile,
    exclusions: list[WafExclusion],
    effective: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compare souhaité (DB) vs généré (export JSON)."""
    if not effective.get("present"):
        return [
            {
                "field": "export",
                "label": "Export",
                "export": "absent",
                "db": "enregistré",
            }
        ]

    db = _profile_db_snapshot(profile, exclusions)
    diffs: list[dict[str, Any]] = []

    scalar_fields = (
        ("mode", "Mode"),
        ("anomaly_threshold", "Seuil anomalie"),
        ("ip_deny_min_occurrences", "Promotion IP deny (min. occ.)"),
        ("portal_login_rate", "Rate login (r/s)"),
        ("portal_api_rate", "Rate API (r/s)"),
        ("portal_login_burst", "Burst login"),
        ("portal_api_burst", "Burst API"),
        ("exclusion_count", "Exclusions actives (nombre)"),
    )
    for key, label in scalar_fields:
        exp_val = effective.get(key)
        db_val = db.get(key)
        if exp_val != db_val:
            diffs.append(
                {
                    "field": key,
                    "label": label,
                    "export": exp_val,
                    "db": db_val,
                }
            )

    if "exclusion_rule_ids" in effective:
        exp_ids = effective.get("exclusion_rule_ids") or []
        if db["exclusion_rule_ids"] != exp_ids:
            if not any(d["field"] == "exclusion_count" for d in diffs):
                diffs.append(
                    {
                        "field": "exclusion_rule_ids",
                        "label": "Exclusions actives (IDs CRS)",
                        "export": exp_ids or "—",
                        "db": db["exclusion_rule_ids"] or "—",
                    }
                )

    return diffs


def _mode_label(mode: str | None) -> str:
    labels = {
        MODE_ON: "On (blocage)",
        MODE_DETECTION: "DetectionOnly",
        MODE_OFF: "Off",
        "mixed": "mixte",
    }
    if mode is None:
        return "—"
    return labels.get(mode, str(mode))


def build_waf_reality_warnings(
    profile: WafProfile,
    reality: dict[str, Any],
) -> list[str]:
    """Technical warnings (stale snapshot, threshold drift) — verdict covers mode."""
    if not reality.get("verifiable"):
        return []

    warnings: list[str] = []
    if reality.get("stale"):
        mins = reality.get("freshness_minutes")
        threshold = reality.get("stale_threshold_minutes", snapshot_stale_minutes())
        warnings.append(
            f"Snapshot nginx lu il y a {mins} min (seuil {threshold} min)."
        )

    desired_thr = clamp_anomaly_threshold(profile.anomaly_threshold)
    active_thr = reality.get("aggregate_threshold")
    if active_thr not in (None, "mixed") and desired_thr != active_thr:
        warnings.append(
            f"Seuil nginx effectif : {active_thr} — seuil enregistré {desired_thr} non appliqué."
        )

    return warnings


def portal_engine_mode(active: dict[str, Any]) -> str | None:
    """SecRuleEngine for the portal family — scope of the WAF admin UI.

    ``aggregate_mode`` mixes portal + subdomain + public; subdomain/public stay
    Off by design and must not trigger a false « configuration non appliquée ».
    """
    if not active.get("verifiable"):
        return None
    fam = (active.get("families") or {}).get("portal")
    if isinstance(fam, dict):
        mode = fam.get("sec_rule_engine")
        if mode:
            return str(mode)
    agg = active.get("aggregate_mode")
    if agg and agg != "mixed":
        return str(agg)
    return None


def nginx_control_effect(reality: dict[str, Any]) -> dict[str, bool]:
    """Which profile fields actually reach nginx today."""
    if not reality.get("verifiable"):
        return {"mode": False, "anomaly_threshold": False}
    return {
        "mode": bool(reality.get("engine_mode_generated_loaded")),
        "anomaly_threshold": bool(reality.get("crs_setup_generated_loaded")),
    }


def reload_confirmed_after_apply(
    generated: dict[str, Any],
    reality: dict[str, Any],
) -> bool | None:
    """True when snapshot is newer than last Apply; None if unknown."""
    apply_at = _parse_generated_at(generated.get("last_apply_at"))
    snap_at = _parse_generated_at(reality.get("generated_at"))
    if apply_at is None or snap_at is None or not reality.get("verifiable"):
        return None
    return snap_at >= apply_at


def build_waf_ui_context(
    db: Session,
    settings: Settings,
    profile: WafProfile,
    exclusions: list[WafExclusion],
    *,
    snapshot_path: Path | None = None,
    nginx_root: Path | None = None,
    page: str = "unified",
) -> dict[str, Any]:
    """Bundle desired / generated / active + pending diffs for admin template."""
    desired = _profile_db_snapshot(profile, exclusions)
    generated = read_effective_status(settings)
    active = read_nginx_waf_reality(settings=settings, snapshot_path=snapshot_path)
    if active.get("verifiable"):
        active = {**active, "portal_mode": portal_engine_mode(active)}
    raw_snapshot = _load_raw_snapshot(settings=settings, snapshot_path=snapshot_path)

    repo_root = nginx_root or resolve_nginx_conf_root()
    repo_intent = (
        read_nginx_waf_reality_from_repo(nginx_root=repo_root)
        if repo_root is not None
        else None
    )

    if active.get("verifiable") and raw_snapshot is not None:
        headers = read_security_headers_from_snapshot(active, raw_snapshot)
    elif repo_root is not None:
        headers = read_security_headers_from_repo(nginx_root=repo_root)
    else:
        headers = read_security_headers_from_snapshot(active, None)

    pending_diffs = diff_db_vs_export(profile, exclusions, generated)
    export_pending = bool(pending_diffs)
    warnings = build_waf_reality_warnings(profile, active)
    control_effect = nginx_control_effect(active)

    from app.bastion.nginx_waf_export import list_promoted_deny_ips
    from app.bastion.waf_readability import (
        build_waf_diagnostic_export,
        build_waf_readability_context,
        format_waf_diagnostic_export_json,
    )

    desired["ip_deny_count"] = len(
        list_promoted_deny_ips(
            db, min_occurrences=int(profile.ip_deny_min_occurrences or 3)
        )
    )

    reload_ok = reload_confirmed_after_apply(generated, active)
    readability = build_waf_readability_context(
        db,
        settings,
        profile,
        active,
        headers,
        export_pending=export_pending,
        page=page,
        generated=generated,
    )
    diagnostic_export = build_waf_diagnostic_export(
        desired=desired,
        generated=generated,
        active=active,
        pending_diffs=pending_diffs,
        export_pending=export_pending,
        control_effect=control_effect,
        security_headers_panel=headers,
        diagnostic=readability["diagnostic"],
        verdict=readability["verdict"],
        reality_warnings=warnings,
        reload_confirmed=reload_ok,
    )

    return {
        "desired": desired,
        "generated": generated,
        "active": active,
        "repo_intent": repo_intent,
        "pending_diffs": pending_diffs,
        "export_pending": export_pending,
        "reality_warnings": warnings,
        "control_effect": control_effect,
        "security_headers_panel": headers,
        "reload_confirmed": reload_ok,
        "readability": readability,
        "verdict": readability["verdict"],
        "protection_layers": readability["protection_layers"],
        "efficiency": readability["efficiency"],
        "efficiency_7d": readability["efficiency_7d"],
        "efficiency_visuals": readability["efficiency_visuals"],
        "attack_controls": readability["attack_controls"],
        "unknown_host_panel": readability.get("unknown_host_panel") or {},
        "executive_summary": readability.get("executive_summary") or {},
        "threat_intel": readability.get("threat_intel") or {},
        "quarantine_panel": readability.get("quarantine_panel") or {},
        "quick_controls": readability.get("quick_controls") or [],
        "ip_geolocation": readability.get("ip_geolocation") or {},
        "security_policy_enabled": readability.get("security_policy_enabled", True),
        "reactivation": readability["reactivation"],
        "apply_enabled": readability["apply_enabled"],
        "mode_pilotable": readability["mode_pilotable"],
        "diagnostic": readability["diagnostic"],
        "diagnostic_export": diagnostic_export,
        "diagnostic_export_json": format_waf_diagnostic_export_json(diagnostic_export),
    }
