"""Public surfaces must not fingerprint product/stack in HTML or app headers."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]


def test_login_headers_no_stack_fingerprint(client: TestClient, db_session: Session):
    from app.breakglass_store import set_breakglass_password
    from app.models import RealmConfig
    from app.secret_crypto import encrypt_secret
    from app.sso_settings import Settings

    settings = Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        database_url="sqlite://",
    )
    db_session.add(
        RealmConfig(
            slug="ar-systems",
            name="AR-SYSTEMS",
            issuer_url="https://keycloak.example/realms/ar-systems",
            client_id="portal",
            client_secret_encrypted=encrypt_secret("secret", settings),
            redirect_uri="https://portal.example/oauth2/ar-systems/callback",
            oauth2_proxy_port=4180,
            is_default=True,
            enabled=True,
            last_test_status="ok",
        )
    )
    db_session.commit()
    set_breakglass_password(db_session, "admin", "super-secret-password")

    r = client.get("/auth/login")
    assert r.status_code == 200
    headers = {k.lower(): v for k, v in r.headers.items()}
    assert "x-powered-by" not in headers
    # Application layer should not advertise framework in custom headers
    blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    assert "uvicorn" not in blob
    assert "fastapi" not in blob
    assert 'name="generator"' not in r.text.lower()
    assert "Bastion Pro" not in r.text


def test_portal_nginx_server_tokens_off():
    for rel in (
        "nginx/vhosts/vhost_sso_portal.conf.j2",
        "docker/nginx/templates/vhost_sso_portal.conf.template",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "server_tokens off;" in text
        assert "generic-shield.svg" in text
        assert "/media/branding/" in text
        # Product icon must not be the public favicon fallback
        assert "bastion-icon.svg" not in text.split("location = /favicon.ico")[1][
            :400
        ]


def test_authenticated_chrome_keeps_product_brand(
    client: TestClient, db_session: Session
):
    """Post-login UI still shows Bastion Pro (non-regression)."""
    r = client.get(
        "/admin/dashboard",
        headers={
            "X-Email": "admin@example.com",
            "X-Preferred-Username": "admin",
            "X-Groups": "portal-admins",
        },
    )
    assert r.status_code == 200
    assert "Bastion" in r.text
    assert "bastion.css" in r.text
    assert "/static/css/portal.css" not in r.text
    assert "/static/portal.css" not in r.text
