"""Bilan v1.1 analytics KPIs."""

from __future__ import annotations

from app.bastion.waf_analytics import (
    build_waf_analytics_summary,
    event_block_intent,
)
from app.bastion.waf_virtual_patches import PACK_MODE_DETECTION, PACK_MODE_OFF
from app.models import WafProfile
from app.sso_settings import Settings


def test_event_block_intent_disruptive_primary():
    assert event_block_intent(
        {"blocked": False, "score": 0, "message": "Access denied with code 403", "rule_ids": ["942100"]}
    )
    assert event_block_intent(
        {"blocked": False, "score": 1, "message": "ok", "rule_ids": ["949110"]}
    )
    assert event_block_intent(
        {"blocked": False, "score": 0, "message": "vp", "rule_ids": ["100096200"]}
    )


def test_event_block_intent_anomaly_threshold_fallback():
    assert event_block_intent(
        {"blocked": False, "score": 5, "message": "anomaly", "rule_ids": ["913100"]},
        anomaly_threshold=5,
    )
    assert not event_block_intent(
        {"blocked": False, "score": 2, "message": "notice", "rule_ids": ["913100"]},
        anomaly_threshold=5,
    )


def test_build_waf_analytics_summary(db_session, tmp_path):
    settings = Settings(
        environment="test",
        portal_domain="portal.example.com",
        exports_dir=str(tmp_path / "exports"),
        portal_data_dir=str(tmp_path / "data"),
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    profile = WafProfile(
        name="Analytics",
        mode="on",
        anomaly_threshold=5,
        patch_php2shell_mode="on",
        patch_wordpress_cms_mode=PACK_MODE_DETECTION,
        patch_api_json_strict_mode=PACK_MODE_OFF,
        patch_rce_extended_mode=PACK_MODE_OFF,
        is_active=True,
    )
    db_session.add(profile)
    db_session.commit()

    summary = {
        "present": True,
        "windows": {
            "24h": {
                "inspected": 100,
                "detections": 80,
                "blocks": 10,
                "blocked_intents": 40,
                "critical": 5,
                "top_rules": [
                    {"rule_id": "942100", "label": "SQLi", "count": 12},
                    {"rule_id": "100096200", "label": "WP", "count": 3},
                ],
                "top_hosts": [
                    {"host": "portal.example.com", "count": 20},
                    {"host": "app.example.com", "count": 5},
                ],
                "rule_families": [
                    {"family": "sqli", "label": "SQLi", "count": 12},
                    {"family": "xss", "label": "XSS", "count": 4},
                ],
            }
        },
        "recent_events": [],
    }
    analytics = build_waf_analytics_summary(
        db_session, settings, profile, summary=summary, active={"verifiable": False}
    )
    assert analytics["kpis"]["requests_evaluated"] == 100
    assert analytics["kpis"]["blocked_intents"] == 40
    assert analytics["kpis"]["blocks_executed"] == 10
    assert analytics["kpis"]["efficiency_pct"] == 25.0
    assert analytics["kpis"]["detection_gap"] == 30
    assert analytics["packs_status"]["armed"] >= 2
    assert analytics["packs_status"]["total"] == 4
    assert analytics["top_rules"]["crs"][0]["rule_id"] == "942100"
    assert analytics["top_rules"]["bastion"][0]["rule_id"] == "100096200"
    assert analytics["attack_surfaces"][0]["id"] == "sqli"
    assert analytics["telemetry"]["health_status"] in ("red", "orange", "green")
