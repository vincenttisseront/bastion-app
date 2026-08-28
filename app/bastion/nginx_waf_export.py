"""Export ModSecurity/CRS overlays (never overwrite static engine / crs-setup / waf-basic).

Writes under ``exports/modsecurity/`` and ``exports/nginx-waf-*.conf``:

* ``crs-setup-generated.conf`` — anomaly threshold overlay (paranoia stays in static crs-setup)
* ``bastion-exclusions-generated.conf`` — UI exclusions after ``waf-basic.conf``
* ``engine-mode-generated.conf`` — SecRuleEngine from active profile (included last)
* ``waf-ip-deny.conf`` — nginx ``deny`` for promoted IP bans
* ``nginx-portal-rate-limits.conf`` — existing ``portal_login`` / ``portal_api`` zones

IP promotion: a ``SecurityBan`` with ``target_type=ip`` is exported only when the ban is
currently active AND (``permanent`` OR historical ban count for that IP >=
``WafProfile.ip_deny_min_occurrences``, default 3). Isolated single login failures do not
regenerate nginx deny lists.
"""

from __future__ import annotations

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import SecurityBan, WafExclusion, WafProfile
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

ANOMALY_MIN = 3
ANOMALY_MAX = 10
DEFAULT_ANOMALY = 5
DEFAULT_IP_DENY_MIN = 3

MODE_OFF = "off"
MODE_DETECTION = "detection_only"
MODE_ON = "on"
VALID_MODES = frozenset({MODE_OFF, MODE_DETECTION, MODE_ON})

ENGINE_LINE = {
    MODE_OFF: "SecRuleEngine Off",
    MODE_DETECTION: "SecRuleEngine DetectionOnly",
    MODE_ON: "SecRuleEngine On",
}

WAF_EXPORT_SUBDIR = "modsecurity"
PREV_SUFFIX = ".prev"
_APPLY_METADATA_KEYS = (
    "last_apply_at",
    "last_apply_by",
    "last_apply_nginx_t_ok",
    "last_apply_nginx_t_detail",
    "last_apply_nginx_t_skipped",
)


def clamp_anomaly_threshold(value: int | None) -> int:
    try:
        n = int(value) if value is not None else DEFAULT_ANOMALY
    except (TypeError, ValueError):
        n = DEFAULT_ANOMALY
    return max(ANOMALY_MIN, min(ANOMALY_MAX, n))


def _status_json_path(settings: Settings) -> Path:
    return waf_exports_dir(settings) / "waf-effective-status.json"


def _read_status_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _merge_apply_metadata(status: dict[str, Any], settings: Settings) -> None:
    """Keep last successful Apply audit fields when regenerating export snapshots."""
    existing = _read_status_json(_status_json_path(settings))
    for key in _APPLY_METADATA_KEYS:
        if key in existing:
            status[key] = existing[key]


def record_waf_apply_metadata(
    settings: Settings,
    *,
    actor: str,
    nginx_t_ok: bool,
    nginx_t_detail: str,
    nginx_t_skipped: bool = False,
) -> None:
    """Stamp waf-effective-status.json after a successful Admin → Appliquer."""
    path = _status_json_path(settings)
    if not path.is_file():
        return
    data = _read_status_json(path)
    data["last_apply_at"] = datetime.now(timezone.utc).isoformat()
    data["last_apply_by"] = (actor or "admin").strip() or "admin"
    data["last_apply_nginx_t_skipped"] = bool(nginx_t_skipped)
    data["last_apply_nginx_t_ok"] = bool(nginx_t_ok) and not nginx_t_skipped
    detail = (nginx_t_detail or "").strip()
    data["last_apply_nginx_t_detail"] = detail[:500] if detail else ""
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def waf_exports_dir(settings: Settings) -> Path:
    path = Path(settings.exports_dir) / WAF_EXPORT_SUBDIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_active_profile(db: Session) -> WafProfile | None:
    return db.query(WafProfile).filter_by(is_active=True).order_by(WafProfile.id).first()


def ensure_active_profile(db: Session) -> WafProfile:
    """Return active profile or activate Production / create a default."""
    active = get_active_profile(db)
    if active:
        return active
    prod = db.query(WafProfile).filter_by(name="Production").first()
    if prod:
        prod.is_active = True
        db.commit()
        db.refresh(prod)
        return prod
    row = WafProfile(
        name="Production",
        mode=MODE_ON,
        anomaly_threshold=DEFAULT_ANOMALY,
        ip_deny_min_occurrences=DEFAULT_IP_DENY_MIN,
        is_active=True,
        created_by="system",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def ip_ban_occurrence_counts(db: Session) -> dict[str, int]:
    rows = (
        db.query(SecurityBan.target, func.count(SecurityBan.id))
        .filter(SecurityBan.target_type == "ip")
        .group_by(SecurityBan.target)
        .all()
    )
    return {str(target): int(count) for target, count in rows}


def list_promoted_deny_ips(
    db: Session,
    *,
    min_occurrences: int = DEFAULT_IP_DENY_MIN,
) -> list[str]:
    """Active IP bans eligible for nginx deny (permanent or repeated)."""
    min_n = max(1, int(min_occurrences or DEFAULT_IP_DENY_MIN))
    counts = ip_ban_occurrence_counts(db)
    active = (
        db.query(SecurityBan)
        .filter(
            SecurityBan.target_type == "ip",
            SecurityBan.lifted_at.is_(None),
        )
        .order_by(SecurityBan.banned_at.desc())
        .all()
    )
    out: list[str] = []
    seen: set[str] = set()
    for ban in active:
        ip = (ban.target or "").strip()
        if not ip or ip in seen:
            continue
        if ban.permanent or counts.get(ip, 0) >= min_n:
            seen.add(ip)
            out.append(ip)
    return out


def render_crs_setup_generated(profile: WafProfile) -> str:
    threshold = clamp_anomaly_threshold(profile.anomaly_threshold)
    # Custom rule id MUST be outside OWASP CRS ranges (900000–999999).
    # 901110 collided with REQUEST-901-INITIALIZATION → nginx 500 on every
    # ModSecurity-enabled request (favicon, /, /static, …). Health paths with
    # ``modsecurity off`` stayed 200.
    return (
        "# Generated by nginx_waf_export — do not edit\n"
        "# Paranoia level remains in static docker/nginx/modsecurity/crs-setup.conf (PL1).\n"
        "# This file only overlays anomaly thresholds from the active WafProfile.\n"
        "SecAction \\\n"
        '    "id:1000900110,\\\n'
        "    phase:1,\\\n"
        "    nolog,\\\n"
        "    pass,\\\n"
        "    t:none,\\\n"
        f"    setvar:tx.inbound_anomaly_score_threshold={threshold},\\\n"
        "    setvar:tx.outbound_anomaly_score_threshold=4\"\n"
    )


def render_engine_mode_generated(profile: WafProfile) -> str:
    mode = profile.mode if profile.mode in VALID_MODES else MODE_ON
    line = ENGINE_LINE[mode]
    return (
        "# Generated by nginx_waf_export — do not edit\n"
        "# Included LAST in main-*.conf so profile mode overrides static engine-*.conf.\n"
        f"{line}\n"
    )


def render_exclusions_generated(exclusions: list[WafExclusion]) -> str:
    lines = [
        "# Generated by nginx_waf_export — do not edit",
        "# Appended after includes/waf-basic.conf (manual exclusions stay intact).",
        "",
    ]
    for ex in exclusions:
        if not ex.active:
            continue
        rule_id = ex.crs_rule_id
        if rule_id is None:
            lines.append(
                f"# skip exclusion id={ex.id}: crs_rule_id required "
                f"(host={ex.host!r} uri={ex.uri_pattern!r})"
            )
            continue
        comment = f"# exclusion id={ex.id} reason={ex.reason!r}"
        lines.append(comment)
        # Targeted remove; optional host/uri documented for ops (CRS RemoveById is global
        # in this include — scope is enforced by only enabling for confirmed FPs).
        host = (ex.host or "").strip()
        uri = (ex.uri_pattern or "").strip()
        if host or uri:
            lines.append(f"# scope hint host={host!r} uri={uri!r}")
        lines.append(f"SecRuleRemoveById {int(rule_id)}")
        lines.append("")
    if len(lines) <= 3:
        lines.append("# (no active exclusions)")
        lines.append("")
    return "\n".join(lines)


def render_ip_deny_conf(ips: list[str], *, min_occurrences: int) -> str:
    lines = [
        "# Generated by nginx_waf_export — do not edit",
        f"# IP deny from SecurityBan (target_type=ip), promoted if permanent OR "
        f"ban history count >= {min_occurrences}.",
        "# Source of truth remains security_bans / security_ban_rules — no WAF-only IP table.",
        "",
    ]
    for ip in ips:
        # Basic sanitise: deny directives need a literal address/CIDR without spaces.
        safe = "".join(c for c in ip if c.isalnum() or c in ".:/")
        if safe != ip or not safe:
            lines.append(f"# skipped unsafe target: {ip!r}")
            continue
        lines.append(f"deny {safe};")
    if not ips:
        lines.append("# (no promoted IP bans)")
    lines.append("")
    return "\n".join(lines)


def render_rate_limits_conf(profile: WafProfile) -> str:
    login_rate = max(1, int(profile.portal_login_rate or 3))
    api_rate = max(1, int(profile.portal_api_rate or 30))
    return (
        "# Generated by nginx_waf_export — do not edit\n"
        "# Pilots EXISTING zone names portal_login / portal_api (no new zone names).\n"
        f"limit_req_zone $binary_remote_addr zone=portal_login:10m rate={login_rate}r/s;\n"
        f"limit_req_zone $binary_remote_addr zone=portal_api:10m rate={api_rate}r/s;\n"
        "limit_req_zone $binary_remote_addr zone=portal_unknown_host:10m rate=5r/s;\n"
    )


def _backup_file(path: Path) -> None:
    if path.is_file():
        shutil.copy2(path, path.with_suffix(path.suffix + PREV_SUFFIX))


def _restore_file(path: Path) -> bool:
    prev = path.with_suffix(path.suffix + PREV_SUFFIX)
    if not prev.is_file():
        return False
    shutil.copy2(prev, path)
    return True


def write_waf_exports(db: Session, settings: Settings) -> dict[str, str]:
    """Generate WAF overlay files. Safe to call on every catalogue export."""
    profile = ensure_active_profile(db)
    exclusions = (
        db.query(WafExclusion)
        .filter_by(active=True)
        .order_by(WafExclusion.id)
        .all()
    )
    min_occ = max(1, int(profile.ip_deny_min_occurrences or DEFAULT_IP_DENY_MIN))
    ips = list_promoted_deny_ips(db, min_occurrences=min_occ)

    mod_dir = waf_exports_dir(settings)
    exports = Path(settings.exports_dir)
    exports.mkdir(parents=True, exist_ok=True)

    files = {
        mod_dir / "crs-setup-generated.conf": render_crs_setup_generated(profile),
        mod_dir / "engine-mode-generated.conf": render_engine_mode_generated(profile),
        mod_dir / "bastion-exclusions-generated.conf": render_exclusions_generated(
            exclusions
        ),
        exports / "waf-ip-deny.conf": render_ip_deny_conf(ips, min_occurrences=min_occ),
        exports / "nginx-portal-rate-limits.conf": render_rate_limits_conf(profile),
    }

    paths: dict[str, str] = {}
    for path, content in files.items():
        _backup_file(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        paths[path.name] = str(path)

    # Status snapshot for the admin UI (effective generated config).
    active_exclusions = [e for e in exclusions if e.active]
    status = {
        "mode": profile.mode if profile.mode in VALID_MODES else MODE_ON,
        "anomaly_threshold": clamp_anomaly_threshold(profile.anomaly_threshold),
        "profile_name": profile.name,
        "ip_deny_count": len(ips),
        "ip_deny_min_occurrences": min_occ,
        "exclusion_count": len(active_exclusions),
        "exclusion_rule_ids": sorted(
            int(e.crs_rule_id) for e in active_exclusions if e.crs_rule_id is not None
        ),
        "portal_login_rate": int(profile.portal_login_rate or 3),
        "portal_api_rate": int(profile.portal_api_rate or 30),
        "portal_login_burst": int(profile.portal_login_burst or 5),
        "portal_api_burst": int(profile.portal_api_burst or 60),
    }
    _merge_apply_metadata(status, settings)

    status_path = mod_dir / "waf-effective-status.json"
    _backup_file(status_path)
    status_path.write_text(
        json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    paths["waf-effective-status.json"] = str(status_path)
    return paths


def restore_waf_exports_previous(settings: Settings) -> list[str]:
    """Restore ``*.prev`` copies after a failed nginx -t."""
    restored: list[str] = []
    mod_dir = waf_exports_dir(settings)
    exports = Path(settings.exports_dir)
    candidates = [
        mod_dir / "crs-setup-generated.conf",
        mod_dir / "engine-mode-generated.conf",
        mod_dir / "bastion-exclusions-generated.conf",
        mod_dir / "waf-effective-status.json",
        mod_dir / "waf-engine-arm.json",
        exports / "waf-ip-deny.conf",
        exports / "nginx-portal-rate-limits.conf",
        exports / "modsecurity-portal-switch.conf",
    ]
    for path in candidates:
        if _restore_file(path):
            restored.append(str(path))
    return restored


def read_effective_status(settings: Settings) -> dict[str, Any]:
    path = _status_json_path(settings)
    if not path.is_file():
        return {"present": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"present": False, "error": "unreadable"}
    data["present"] = True
    data["path"] = str(path)
    if "last_apply_at" not in data:
        try:
            mtime = path.stat().st_mtime
            data["export_file_mtime"] = datetime.fromtimestamp(
                mtime, tz=timezone.utc
            ).isoformat()
        except OSError:
            pass
    return data


def apply_waf_exports(
    db: Session,
    settings: Settings,
    *,
    validate: Callable[[Settings], tuple[bool, str]] | None = None,
) -> dict[str, Any]:
    """Write exports; on validation failure restore previous files (no reload of bad conf)."""
    paths = write_waf_exports(db, settings)
    validator = validate or default_nginx_validate
    result = validator(settings)
    if len(result) == 2:
        ok, detail = result
        skipped = detail.lower().startswith("nginx -t skipped")
    else:
        ok, detail, skipped = result
    if not ok:
        restored = restore_waf_exports_previous(settings)
        return {
            "ok": False,
            "paths": paths,
            "restored": restored,
            "error": detail or "nginx -t failed",
        }
    return {
        "ok": True,
        "paths": paths,
        "error": None,
        "validate_detail": detail,
        "validate_skipped": skipped,
    }


def default_nginx_validate(settings: Settings) -> tuple[bool, str, bool]:
    """Best-effort nginx -t via docker compose exec.

    Returns (ok, detail, skipped). Production reload + snapshot are handled by
    bastion-nginx ``watch-exports-reload`` (no docker.sock in bastion-app).
    """
    import subprocess

    compose_dir = Path(settings.compose_dir) if getattr(settings, "compose_dir", None) else None
    candidates = []
    if compose_dir:
        candidates.append(compose_dir)
    candidates.append(Path.cwd())
    for base in candidates:
        compose = base / "docker-compose.yml"
        if not compose.is_file():
            continue
        try:
            proc = subprocess.run(
                [
                    "docker",
                    "compose",
                    "exec",
                    "-T",
                    "nginx",
                    "sh",
                    "-c",
                    "/sync-exports-to-confd.sh && nginx -t && nginx -s reload && /export-waf-snapshot.sh",
                ],
                cwd=str(base),
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return True, f"nginx -t non exécuté depuis l'app ({exc}) — watcher nginx validera", True
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        if proc.returncode != 0:
            return False, out or f"nginx -t exit {proc.returncode}", False
        return True, out or "nginx -t ok", False
    return True, "nginx -t non exécuté depuis l'app (pas de docker-compose.yml) — watcher nginx validera", True
