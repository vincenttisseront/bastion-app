"""Phase F — extended virtual-patch catalog (WP / API JSON / RCE)."""

from __future__ import annotations

from pathlib import Path

from app.bastion.packs.catalog import (
    PACK_API_JSON_STRICT,
    PACK_CATALOG,
    PACK_PHP2SHELL,
    PACK_RCE_EXTENDED,
    PACK_WORDPRESS_CMS,
)
from app.bastion.waf_virtual_patches import (
    PACK_MODE_DETECTION,
    PACK_MODE_OFF,
    PACK_MODE_ON,
    _audit_hints_for_pack,
    render_virtual_patches_enabled_conf_from_modes,
)
from app.models import WafProfile

ROOT = Path(__file__).resolve().parents[1]
MODSEC = ROOT / "docker" / "nginx" / "modsecurity"


def test_catalog_id_bands_are_disjoint():
    bands = []
    for pack_id, meta in PACK_CATALOG.items():
        lo, hi = meta["id_range"]
        for rid in (r["id"] for r in meta["rules"]):
            n = int(rid)
            assert lo <= n <= hi, f"{pack_id} rule {rid} outside band"
        bands.append((pack_id, lo, hi))
    for i, (a, alo, ahi) in enumerate(bands):
        for b, blo, bhi in bands[i + 1 :]:
            assert ahi < blo or bhi < alo, f"overlap {a}/{b}"


def test_pack_conf_files_exist_and_smoke():
    for pack_id, meta in PACK_CATALOG.items():
        path = MODSEC / meta["conf_basename"]
        assert path.is_file(), path
        text = path.read_text(encoding="utf-8")
        live = [
            ln
            for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        assert live
        blob = "\n".join(live)
        assert "%" not in blob
        for rule in meta["rules"]:
            assert f"id:{rule['id']}," in blob
        for i, ln in enumerate(live):
            if ',chain"' in ln or ln.rstrip().endswith(",chain"):
                assert i + 1 < len(live)
                assert live[i + 1].lstrip().startswith("SecRule ")


def test_detection_export_updates_new_pack_ids():
    text = render_virtual_patches_enabled_conf_from_modes(
        {
            PACK_PHP2SHELL: PACK_MODE_OFF,
            PACK_WORDPRESS_CMS: PACK_MODE_DETECTION,
            PACK_API_JSON_STRICT: PACK_MODE_ON,
            PACK_RCE_EXTENDED: PACK_MODE_OFF,
        }
    )
    assert "bastion-pack-wordpress-cms.conf" in text
    assert "SecRuleUpdateActionById 100096200" in text
    assert "SecRuleUpdateActionById 100096202" in text
    assert "bastion-pack-api-json-strict.conf" in text
    assert "SecRuleUpdateActionById 100096300" not in text  # on = Include only
    assert "bastion-pack-rce-extended.conf" not in text


def test_audit_hints_wordpress_and_json():
    summary = {
        "present": True,
        "windows": {"24h": {"families": {}, "top_rules": []}},
        "recent_events": [
            {"uri": "/wp-login.php", "message": "scanner"},
            {"uri": "/wp-json/wp/v2/users", "message": "recon"},
            {"uri": "/api/v1/items", "message": "Content-Type: application/json"},
            {"uri": "/api/v1/search", "message": "application/json body"},
        ],
    }
    wp = _audit_hints_for_pack(PACK_WORDPRESS_CMS, summary)
    assert wp["signal"] is True
    api = _audit_hints_for_pack(PACK_API_JSON_STRICT, summary)
    assert api["signal"] is True


def test_profile_defaults_new_packs_off():
    profile = WafProfile(name="P", mode="on")
    # SQLAlchemy defaults apply on flush; attributes may be None until then —
    # catalog default_mode is the source of truth for profile_pack_mode.
    from app.bastion.waf_virtual_patches import profile_pack_mode

    assert profile_pack_mode(profile, PACK_WORDPRESS_CMS) == PACK_MODE_OFF
    assert profile_pack_mode(profile, PACK_API_JSON_STRICT) == PACK_MODE_OFF
    assert profile_pack_mode(profile, PACK_RCE_EXTENDED) == PACK_MODE_OFF
