"""UI target vs on-disk WAF export drift."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.bastion.nginx_waf_export import (
    render_crs_setup_generated,
    write_waf_exports,
)
from app.bastion.waf_config_drift import (
    STATUS_DIVERGED,
    STATUS_MISSING,
    STATUS_SYNCED,
    build_waf_config_drift,
)
from app.models import WafProfile
from app.sso_settings import Settings, get_settings


ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        portal_domain="portal.example.com",
        exports_dir=str(tmp_path / "exports"),
        environment="test",
        vault_portal_internal_token="test-secret",
        breakglass_jwt_secret="test-bg-jwt-secret",
        breakglass_jwt_secret_fallback_enabled=True,
        session_hop_secret="test-session-hop-secret-for-pytest",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )  # type: ignore[call-arg]


def _seed(db: Session) -> WafProfile:
    profile = WafProfile(
        name="Production",
        mode="on",
        anomaly_threshold=5,
        paranoia_level=1,
        patch_php2shell_mode="on",
        patch_php2shell_enabled=True,
        is_active=True,
        created_by="test",
    )
    db.add(profile)
    db.commit()
    return profile


def test_drift_synced_after_export(db_session: Session, tmp_path: Path):
    settings = _settings(tmp_path)
    _seed(db_session)
    write_waf_exports(db_session, settings)
    payload = build_waf_config_drift(db_session, settings)
    assert payload["synced"] is True
    assert payload["diverged_count"] == 0
    assert all(f["status"] == STATUS_SYNCED for f in payload["files"])


def test_drift_missing_before_export(db_session: Session, tmp_path: Path):
    settings = _settings(tmp_path)
    _seed(db_session)
    payload = build_waf_config_drift(db_session, settings)
    assert payload["synced"] is False
    crs = next(f for f in payload["files"] if f["id"] == "crs-setup-generated")
    assert crs["status"] == STATUS_MISSING
    assert crs["unified"]
    assert "inbound_anomaly_score_threshold=5" in crs["unified"]


def test_drift_diverged_when_paranoia_changed(db_session: Session, tmp_path: Path):
    settings = _settings(tmp_path)
    profile = _seed(db_session)
    write_waf_exports(db_session, settings)
    profile.paranoia_level = 3
    db_session.commit()
    payload = build_waf_config_drift(db_session, settings)
    assert payload["synced"] is False
    crs = next(f for f in payload["files"] if f["id"] == "crs-setup-generated")
    assert crs["status"] == STATUS_DIVERGED
    assert "blocking_paranoia_level=3" in crs["unified"]
    assert "-" in crs["unified"] and "+" in crs["unified"]
    engine = next(f for f in payload["files"] if f["id"] == "engine-mode-generated")
    assert engine["status"] == STATUS_SYNCED


def test_drift_json_endpoint(
    client: TestClient, db_session: Session, tmp_path: Path
):
    settings = _settings(tmp_path)
    client.app.dependency_overrides[get_settings] = lambda: settings
    try:
        _seed(db_session)
        write_waf_exports(db_session, settings)
        resp = client.get("/admin/security/waf/drift.json", headers=ADMIN_HEADERS)
        assert resp.status_code == 200
        assert resp.headers.get("cache-control") == "no-store"
        data = resp.json()
        assert data["synced"] is True
        assert len(data["files"]) >= 4
        assert "generated_at" in data
    finally:
        # Restore fixture override
        from tests.conftest import TEST_PORTAL_INTERNAL_TOKEN

        client.app.dependency_overrides[get_settings] = lambda: Settings(
            environment="test",
            vault_portal_internal_token=TEST_PORTAL_INTERNAL_TOKEN,
            breakglass_jwt_secret="test-bg-jwt-secret",
            breakglass_jwt_secret_fallback_enabled=True,
            session_hop_secret="test-session-hop-secret-for-pytest",
            portal_secret_encryption_key="test-encryption-key-for-pytest-only",
            database_url="sqlite://",
        )


def test_desired_render_matches_write(db_session: Session, tmp_path: Path):
    settings = _settings(tmp_path)
    profile = _seed(db_session)
    write_waf_exports(db_session, settings)
    path = tmp_path / "exports" / "modsecurity" / "crs-setup-generated.conf"
    assert path.read_text(encoding="utf-8") == render_crs_setup_generated(profile)
