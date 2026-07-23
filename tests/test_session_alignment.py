"""Unit tests for SSO session alignment (oauth2 cookie vs Keycloak)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.orm import Session

from app.admin.session_alignment import (
    TARGET_COOKIE_EXPIRE,
    _evaluate_coherent,
    build_session_alignment_report,
    parse_oauth2_cookie_settings,
)
from app.models import RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings


def test_parse_oauth2_cookie_settings():
    cfg = '''
cookie_expire = "12h"
cookie_refresh = "1h"
user_id_claim = "sub"
'''
    parsed = parse_oauth2_cookie_settings(cfg)
    assert parsed["cookie_expire"] == "12h"
    assert parsed["cookie_refresh"] == "1h"


def test_evaluate_coherent_ok():
    ok, notes = _evaluate_coherent(
        cookie_expire="12h",
        cookie_refresh="1h",
        max_lifespan_s=43200,
        export_matches=True,
        keycloak_error=None,
    )
    assert ok is True
    assert any("conforme" in n for n in notes)


def test_evaluate_coherent_keycloak_too_long():
    ok, notes = _evaluate_coherent(
        cookie_expire="12h",
        cookie_refresh="1h",
        max_lifespan_s=86400,
        export_matches=True,
        keycloak_error=None,
    )
    assert ok is False
    assert any("86400" in n for n in notes)


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        exports_dir="/tmp/bastion-exports-test-alignment",
        sso_portal_default_realm_slug="ar-systems",
    )


@pytest.mark.asyncio
async def test_build_report_uses_keycloak_timeouts(db_session: Session, tmp_path):
    settings = _settings()
    settings = settings.model_copy(update={"exports_dir": str(tmp_path)})
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url="https://kc.example.com/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", settings),
        redirect_uri="https://portal.test/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        is_default=True,
        enabled=True,
        groups_sync_enabled=True,
        keycloak_admin_client_id="admin-cli",
        keycloak_admin_client_secret_encrypted=encrypt_secret("admin-secret", settings),
        last_test_status="ok",
    )
    db_session.add(realm)
    db_session.commit()

    export_dir = tmp_path / "oauth2" / "ar-systems"
    export_dir.mkdir(parents=True)
    (export_dir / "oauth2-proxy.cfg").write_text(
        'cookie_expire = "12h"\n'
        'cookie_refresh = "1h"\n'
        "cookie_secure = true\n"
        "cookie_httponly = true\n"
        'cookie_samesite = "lax"\n',
        encoding="utf-8",
    )

    with patch(
        "app.admin.session_alignment.fetch_realm_session_timeouts",
        new=AsyncMock(
            return_value={
                "ssoSessionMaxLifespan": 43200,
                "ssoSessionIdleTimeout": 1800,
                "clientSessionMaxLifespan": 0,
            }
        ),
    ):
        rows = await build_session_alignment_report(db_session, settings)

    assert len(rows) == 1
    assert rows[0].cookie_expire_export == TARGET_COOKIE_EXPIRE
    assert rows[0].sso_session_max_lifespan_s == 43200
    assert rows[0].coherent is True
