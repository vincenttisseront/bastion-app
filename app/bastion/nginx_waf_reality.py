"""Read nginx ModSecurity / CRS files for WAF admin UI (Phase B lot 2).

Parses the **repo build context** ``docker/nginx/`` (COPY'd into the nginx image
at rebuild). There is **no bind mount** of that tree into ``bastion-nginx`` —
this is not a live ``docker exec`` read of the running container.

Never writes SecRuleEngine or include chains.
"""

from __future__ import annotations

import re
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

WAF_FAMILIES = ("portal", "subdomain", "public")

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
}

_UNDEFINED_HEADERS = (
    "Content-Security-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
)


def resolve_nginx_docker_root() -> Path | None:
    """Locate ``docker/nginx`` in the git checkout (image build context, not a live mount)."""
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "docker" / "nginx",
        Path.cwd() / "docker" / "nginx",
    ]
    for root in candidates:
        if (root / "modsecurity" / "main-portal.conf").is_file():
            return root
    return None


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


def _docker_path_to_local(nginx_root: Path, docker_path: str) -> Path | None:
    """Map ``/etc/nginx/modsecurity/...`` to files under ``docker/nginx``."""
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
    """Walk main-{family}.conf include chain; last SecRuleEngine wins."""
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
                stub = 'SecRuleEngine Off\n'
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
        "engine_file": str(
            nginx_root / "modsecurity" / f"engine-{family}.conf"
        ),
        "sec_rule_engine": mode,
        "sec_rule_engine_static": static_engine,
        "engine_source": engine_source,
        "anomaly_threshold": threshold,
        "anomaly_source": threshold_source,
        "engine_mode_generated_loaded": engine_mode_gen_loaded,
        "crs_setup_generated_loaded": crs_setup_gen_loaded,
    }


def read_nginx_waf_reality(
    *,
    nginx_root: Path | None = None,
    engine_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    root = nginx_root or resolve_nginx_docker_root()
    if root is None:
        return {"present": False, "error": "docker/nginx introuvable"}

    families: dict[str, dict[str, Any]] = {}
    for fam in WAF_FAMILIES:
        families[fam] = _effective_engine_for_family(
            root, fam, engine_overrides=engine_overrides
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

    any_engine_gen = any(
        f.get("engine_mode_generated_loaded") for f in families.values()
    )
    any_crs_gen = any(f.get("crs_setup_generated_loaded") for f in families.values())

    return {
        "present": True,
        "nginx_root": str(root),
        "source_kind": "repo_build_context",
        "verified_in_container": False,
        "source_note": (
            "Lu depuis docker/nginx du checkout (contexte de build de l'image), "
            "pas depuis le filesystem du conteneur bastion-nginx. "
            "Ces fichiers sont COPY au rebuild — pas de bind mount. "
            "Équivalent au runtime seulement si l'image en cours a été construite "
            "depuis ce même arbre."
        ),
        "families": families,
        "aggregate_mode": aggregate_mode,
        "aggregate_threshold": aggregate_threshold,
        "engine_mode_generated_loaded": any_engine_gen,
        "crs_setup_generated_loaded": any_crs_gen,
    }


def read_security_headers_panel(*, nginx_root: Path | None = None) -> dict[str, Any]:
    root = nginx_root or resolve_nginx_docker_root()
    if root is None:
        return {"present": False}

    headers_path = root / "includes" / "security-headers.conf"
    headers: list[dict[str, str]] = []
    if headers_path.is_file():
        for line in _read_text(headers_path).splitlines():
            m = _ADD_HEADER_RE.search(line.strip())
            if m:
                headers.append({"name": m.group(1), "value": m.group(2)})

    portal_tpl = _read_text(root / "templates" / "vhost_sso_portal.conf.template")
    acme_sync = _read_text(root / "sync-acme-tls.sh")
    included_on_443 = "includes/security-headers.conf" in acme_sync
    portal_avoids_dup = "Do not re-add" in portal_tpl or "security-headers" in portal_tpl

    return {
        "present": True,
        "path": str(headers_path),
        "source_kind": "repo_build_context",
        "verified_in_container": False,
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

    # Absent key = unknown (pre-lot-2 JSON). Do not treat as [] / divergent.
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
    """Banner lines when nginx reality diverges from DB intent."""
    if not reality.get("present"):
        return [
            "Configuration nginx introuvable — impossible de lire le moteur ModSecurity réel."
        ]

    warnings: list[str] = []
    desired_mode = profile.mode
    active_mode = reality.get("aggregate_mode")
    if active_mode and desired_mode != active_mode:
        warnings.append(
            f"ModSecurity : moteur {_mode_label(active_mode)} en nginx. "
            f"Le mode « {_mode_label(desired_mode)} » enregistré ici N'EST PAS appliqué. "
            "Aucun blocage CRS n'est actif tant que le moteur est Off. "
            "Voir docs/ops-modsecurity-crs.md."
        )

    desired_thr = clamp_anomaly_threshold(profile.anomaly_threshold)
    active_thr = reality.get("aggregate_threshold")
    if (
        active_thr not in (None, "mixed")
        and desired_thr != active_thr
    ):
        warnings.append(
            f"Seuil d'anomalie nginx : {active_thr} (statique). "
            f"Le seuil {desired_thr} enregistré en base N'EST PAS appliqué "
            "(overlay crs-setup-generated non chargé)."
        )

    return warnings


def nginx_control_effect(reality: dict[str, Any]) -> dict[str, bool]:
    """Which profile fields actually reach nginx today."""
    if not reality.get("present"):
        return {"mode": False, "anomaly_threshold": False}
    return {
        "mode": bool(reality.get("engine_mode_generated_loaded")),
        "anomaly_threshold": bool(reality.get("crs_setup_generated_loaded")),
    }


def build_waf_ui_context(
    db: Session,
    settings,
    profile: WafProfile,
    exclusions: list[WafExclusion],
    *,
    nginx_root: Path | None = None,
    engine_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Bundle desired / generated / active + pending diffs for admin template."""
    desired = _profile_db_snapshot(profile, exclusions)
    generated = read_effective_status(settings)
    active = read_nginx_waf_reality(
        nginx_root=nginx_root, engine_overrides=engine_overrides
    )
    pending_diffs = diff_db_vs_export(profile, exclusions, generated)
    warnings = build_waf_reality_warnings(profile, active)
    control_effect = nginx_control_effect(active)
    headers = read_security_headers_panel(nginx_root=nginx_root)

    return {
        "desired": desired,
        "generated": generated,
        "active": active,
        "pending_diffs": pending_diffs,
        "export_pending": bool(pending_diffs),
        "reality_warnings": warnings,
        "control_effect": control_effect,
        "security_headers_panel": headers,
    }
