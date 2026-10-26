"""UI target vs on-disk WAF export drift (unified diffs for Admin → Détails techniques)."""

from __future__ import annotations

import difflib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.bastion.nginx_waf_export import (
    DEFAULT_IP_DENY_MIN,
    ensure_active_profile,
    list_allowlist_ips,
    list_promoted_deny_ips,
    render_crs_setup_generated,
    render_engine_mode_generated,
    render_exclusions_generated,
    render_ip_allow_conf,
    render_ip_deny_conf,
    render_rate_limits_conf,
    render_virtual_patches_enabled,
    waf_exports_dir,
)
from app.models import WafExclusion
from app.sso_settings import Settings

STATUS_SYNCED = "synced"
STATUS_DIVERGED = "diverged"
STATUS_MISSING = "missing"

# Core ModSecurity overlays first; nginx rate/deny optional but useful for support.
_DRIFT_SPECS: tuple[dict[str, str], ...] = (
    {
        "id": "crs-setup-generated",
        "name": "crs-setup-generated.conf",
        "label": "CRS setup (seuil / PL)",
        "location": "modsecurity",
    },
    {
        "id": "engine-mode-generated",
        "name": "engine-mode-generated.conf",
        "label": "Engine mode (SecRuleEngine)",
        "location": "modsecurity",
    },
    {
        "id": "bastion-exclusions-generated",
        "name": "bastion-exclusions-generated.conf",
        "label": "Exclusions CRS",
        "location": "modsecurity",
    },
    {
        "id": "bastion-virtual-patches-enabled",
        "name": "bastion-virtual-patches-enabled.conf",
        "label": "Packs virtual-patch",
        "location": "modsecurity",
    },
    {
        "id": "nginx-portal-rate-limits",
        "name": "nginx-portal-rate-limits.conf",
        "label": "Rate limits portail",
        "location": "exports",
    },
    {
        "id": "waf-ip-allow",
        "name": "waf-ip-allow.conf",
        "label": "IP allow nginx (trust)",
        "location": "exports",
    },
    {
        "id": "waf-ip-deny",
        "name": "waf-ip-deny.conf",
        "label": "IP deny nginx",
        "location": "exports",
    },
)


def _normalize_text(text: str) -> str:
    """LF endings, ensure trailing newline for stable diffs."""
    normalized = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    return normalized


def _read_disk(path: Path) -> tuple[str | None, str]:
    """Return (content_or_None, status_hint)."""
    if not path.exists():
        return None, STATUS_MISSING
    try:
        return path.read_text(encoding="utf-8"), STATUS_SYNCED
    except OSError:
        return None, STATUS_MISSING


def _unified(
    *,
    name: str,
    disk: str | None,
    desired: str,
) -> tuple[str, list[str], str]:
    """Return (status, unified_lines, unified_text)."""
    desired_n = _normalize_text(desired)
    if disk is None:
        # Treat as empty on disk → entire desired is additions.
        disk_n = ""
        status = STATUS_MISSING
    else:
        disk_n = _normalize_text(disk)
        status = STATUS_SYNCED if disk_n == desired_n else STATUS_DIVERGED

    if status == STATUS_SYNCED:
        return status, [], ""

    from_lines = disk_n.splitlines(keepends=True)
    to_lines = desired_n.splitlines(keepends=True)
    lines = list(
        difflib.unified_diff(
            from_lines,
            to_lines,
            fromfile=f"disk/{name}",
            tofile=f"ui/{name}",
            n=3,
        )
    )
    text = "".join(lines)
    if status == STATUS_MISSING and not text and desired_n:
        text = f"--- disk/{name}\n+++ ui/{name}\n@@ -0,0 +1,{desired_n.count(chr(10))} @@\n"
        text += "".join(f"+{ln}" for ln in to_lines)
    return status, lines, text


def _desired_contents(
    db: Session, settings: Settings
) -> dict[str, tuple[Path, str]]:
    """Map file id → (absolute path, desired text)."""
    profile = ensure_active_profile(db)
    exclusions = (
        db.query(WafExclusion)
        .filter_by(active=True)
        .order_by(WafExclusion.id)
        .all()
    )
    min_occ = max(1, int(profile.ip_deny_min_occurrences or DEFAULT_IP_DENY_MIN))
    ips = list_promoted_deny_ips(db, min_occurrences=min_occ)
    allow_ips = list_allowlist_ips(db)
    mod_dir = waf_exports_dir(settings)
    exports = Path(settings.exports_dir)

    return {
        "crs-setup-generated": (
            mod_dir / "crs-setup-generated.conf",
            render_crs_setup_generated(profile),
        ),
        "engine-mode-generated": (
            mod_dir / "engine-mode-generated.conf",
            render_engine_mode_generated(profile),
        ),
        "bastion-exclusions-generated": (
            mod_dir / "bastion-exclusions-generated.conf",
            render_exclusions_generated(exclusions),
        ),
        "bastion-virtual-patches-enabled": (
            mod_dir / "bastion-virtual-patches-enabled.conf",
            render_virtual_patches_enabled(profile),
        ),
        "nginx-portal-rate-limits": (
            exports / "nginx-portal-rate-limits.conf",
            render_rate_limits_conf(profile),
        ),
        "waf-ip-allow": (
            exports / "waf-ip-allow.conf",
            render_ip_allow_conf(allow_ips),
        ),
        "waf-ip-deny": (
            exports / "waf-ip-deny.conf",
            render_ip_deny_conf(ips, min_occurrences=min_occ),
        ),
    }


def build_waf_config_drift(db: Session, settings: Settings) -> dict[str, Any]:
    """Compare in-memory UI target renders vs files under exports/."""
    desired_map = _desired_contents(db, settings)
    files: list[dict[str, Any]] = []
    any_drift = False

    for spec in _DRIFT_SPECS:
        fid = spec["id"]
        path, desired = desired_map[fid]
        disk, _ = _read_disk(path)
        status, _lines, unified = _unified(
            name=spec["name"], disk=disk, desired=desired
        )
        if status != STATUS_SYNCED:
            any_drift = True
        css = {
            STATUS_SYNCED: "badge-ok",
            STATUS_DIVERGED: "badge-err",
            STATUS_MISSING: "badge-warn",
        }.get(status, "badge-muted")
        files.append(
            {
                "id": fid,
                "name": spec["name"],
                "label": spec["label"],
                "path": str(path),
                "status": status,
                "css": css,
                "unified": unified,
                "desired_bytes": len(_normalize_text(desired).encode("utf-8")),
                "disk_bytes": (
                    len(_normalize_text(disk).encode("utf-8")) if disk is not None else 0
                ),
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "synced": not any_drift,
        "files": files,
        "file_count": len(files),
        "diverged_count": sum(1 for f in files if f["status"] != STATUS_SYNCED),
    }
