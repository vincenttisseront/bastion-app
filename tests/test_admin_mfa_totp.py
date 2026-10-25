"""Admin MFA Phase A — TOTP Fernet + signed mfa_ok cookie + gate."""

from __future__ import annotations

import time
from pathlib import Path
import pyotp
import pytest
from cryptography.fernet import Fernet
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response

from app.auth.mfa_cookie import (
    MFA_COOKIE_NAME,
    clear_mfa_ok_cookie,
    generate_mfa_signature,
    is_mfa_cookie_valid,
    set_mfa_ok_cookie,
)
from app.auth.mfa_gate import MfaChallengeRequired, enforce_admin_mfa, path_is_mfa_exempt
from app.auth.totp_service import (
    confirm_totp_enrollment,
    generate_new_totp_setup,
    totp_enabled_for,
    verify_login_totp,
    verify_totp_token,
)
from app.secret_crypto import decrypt_secret
from app.sso_settings import Settings
from app.web.user_context import UserContext


def _settings() -> Settings:
    key = Fernet.generate_key().decode("ascii")
    return Settings(
        portal_domain="portal.example.com",
        sso_portal_default_realm_slug="default",
        vault_portal_internal_token="test-signing-secret",
        portal_secret_encryption_key=key,
    )  # type: ignore[call-arg]


def _admin(email: str = "admin@example.com") -> UserContext:
    return UserContext(
        email=email,
        username="admin",
        groups=["admins"],
        realm_slug="default",
        auth_source="sso",
        is_admin=True,
        keycloak_user_id=None,
        given_name=None,
        family_name=None,
    )


def _request(path: str = "/admin/apps", cookies: dict | None = None) -> StarletteRequest:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("test", 443),
    }
    if cookies:
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        scope["headers"] = [(b"cookie", cookie_header.encode("latin-1"))]
    return StarletteRequest(scope)


def test_totp_encrypt_roundtrip_and_verify(db_session):
    settings = _settings()
    setup = generate_new_totp_setup(db_session, settings, "admin@example.com")
    assert setup["secret_display"]
    assert setup["qr_data_url"].startswith("data:image/png;base64,")
    assert "otpauth://totp/" in setup["provisioning_url"]
    assert totp_enabled_for(db_session, "admin@example.com") is False

    from app.models import AdminMfaCredential

    row = (
        db_session.query(AdminMfaCredential)
        .filter_by(user_email="admin@example.com")
        .one()
    )
    # Secret at rest is not plaintext base32
    assert row.totp_secret != setup["secret_display"]
    plain = decrypt_secret(row.totp_secret, settings)
    assert plain == setup["secret_display"]

    code = pyotp.TOTP(setup["secret_display"]).now()
    assert verify_totp_token(settings, row.totp_secret, code) is True
    assert confirm_totp_enrollment(
        db_session, settings, "admin@example.com", code
    )
    assert totp_enabled_for(db_session, "admin@example.com") is True
    assert verify_login_totp(
        db_session, settings, "admin@example.com", code
    )


def test_totp_rejects_bad_code(db_session):
    settings = _settings()
    setup = generate_new_totp_setup(db_session, settings, "a@example.com")
    assert (
        confirm_totp_enrollment(db_session, settings, "a@example.com", "000000")
        is False
    )
    assert setup["secret_display"]


def test_mfa_cookie_hmac_valid_and_tamper(settings_override=None):
    settings = _settings()
    response = Response()
    set_mfa_ok_cookie(response, settings, "Admin@Example.com")
    # Extract Set-Cookie
    set_cookie = response.headers.get("set-cookie", "")
    assert MFA_COOKIE_NAME in set_cookie
    # Parse value
    value = None
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith(f"{MFA_COOKIE_NAME}="):
            value = part.split("=", 1)[1]
            break
    assert value
    req = _request(cookies={MFA_COOKIE_NAME: value})
    assert is_mfa_cookie_valid(req, settings, "admin@example.com") is True

    # Tamper signature
    email, exp, sig = value.split("|", 2)
    bad = f"{email}|{exp}|{'0' * len(sig)}"
    req_bad = _request(cookies={MFA_COOKIE_NAME: bad})
    assert is_mfa_cookie_valid(req_bad, settings, "admin@example.com") is False

    # Email mismatch
    assert is_mfa_cookie_valid(req, settings, "other@example.com") is False


def test_mfa_cookie_expired():
    settings = _settings()
    email = "admin@example.com"
    expires_at = int(time.time()) - 10
    sig = generate_mfa_signature(
        "test-signing-secret", email, expires_at
    )
    # portal_signing_secret uses vault_portal_internal_token
    settings = _settings()
    secret = settings.vault_portal_internal_token
    sig = generate_mfa_signature(secret, email, expires_at)
    cookie = f"{email}|{expires_at}|{sig}"
    req = _request(cookies={MFA_COOKIE_NAME: cookie})
    assert is_mfa_cookie_valid(req, settings, email) is False


def test_path_is_mfa_exempt():
    assert path_is_mfa_exempt("/admin/auth/mfa/challenge") is True
    assert path_is_mfa_exempt("/admin/profile") is True
    assert path_is_mfa_exempt("/admin/profile/mfa/totp/start") is True
    assert path_is_mfa_exempt("/admin/apps") is False


def test_enforce_admin_mfa_redirects_when_enabled(db_session):
    settings = _settings()
    setup = generate_new_totp_setup(db_session, settings, "admin@example.com")
    code = pyotp.TOTP(setup["secret_display"]).now()
    confirm_totp_enrollment(db_session, settings, "admin@example.com", code)

    req = _request("/admin/apps")
    with pytest.raises(MfaChallengeRequired) as exc:
        enforce_admin_mfa(req, _admin(), db_session, settings)
    assert "/admin/auth/mfa/challenge" in exc.value.redirect_url
    assert "next=" in exc.value.redirect_url


def test_enforce_admin_mfa_ok_with_cookie(db_session):
    settings = _settings()
    setup = generate_new_totp_setup(db_session, settings, "admin@example.com")
    code = pyotp.TOTP(setup["secret_display"]).now()
    confirm_totp_enrollment(db_session, settings, "admin@example.com", code)

    response = Response()
    set_mfa_ok_cookie(response, settings, "admin@example.com")
    value = None
    for part in response.headers.get("set-cookie", "").split(";"):
        part = part.strip()
        if part.startswith(f"{MFA_COOKIE_NAME}="):
            value = part.split("=", 1)[1]
            break
    req = _request("/admin/apps", cookies={MFA_COOKIE_NAME: value})
    enforce_admin_mfa(req, _admin(), db_session, settings)  # no raise


def test_enforce_skips_breakglass(db_session):
    settings = _settings()
    setup = generate_new_totp_setup(db_session, settings, "admin@example.com")
    code = pyotp.TOTP(setup["secret_display"]).now()
    confirm_totp_enrollment(db_session, settings, "admin@example.com", code)
    bg = _admin()
    bg.auth_source = "breakglass"
    enforce_admin_mfa(_request("/admin/apps"), bg, db_session, settings)


def test_clear_mfa_cookie():
    response = Response()
    clear_mfa_ok_cookie(response)
    assert MFA_COOKIE_NAME in (response.headers.get("set-cookie") or "")


def test_migration_and_templates_exist():
    root = Path(__file__).resolve().parents[1]
    assert (
        root / "migrations/versions/093_auth_mfa_credentials.py"
    ).is_file()
    assert (root / "app/templates/admin/mfa_challenge.html").is_file()
    assert (root / "app/templates/admin/profile.html").is_file()
    html = (root / "app/templates/admin/profile.html").read_text(
        encoding="utf-8"
    )
    assert 'id="mfa"' in html
