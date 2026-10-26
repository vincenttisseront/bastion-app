"""Admin MFA Phase B — WebAuthn (Base64URL COSE) + grace / enforcement."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response
from webauthn.helpers import bytes_to_base64url

from app.auth.mfa_gate import (
    MfaEnrollmentRequired,
    apply_grace_banner,
    enforce_admin_mfa,
    enforcement_deadline,
    grace_days_left,
)
from app.auth.webauthn_service import (
    CHALLENGE_COOKIE,
    WebAuthnError,
    build_authentication_options,
    build_registration_options,
    disable_webauthn,
    pop_challenge,
    rp_id_and_origin,
    stash_challenge,
    verify_and_store_registration,
    verify_authentication,
)
from app.models import AdminMfaCredential
from app.sso_settings import Settings
from app.web.user_context import UserContext


def _settings(**extra) -> Settings:
    key = Fernet.generate_key().decode("ascii")
    kwargs = dict(
        portal_domain="portal.example.com",
        sso_portal_default_realm_slug="default",
        vault_portal_internal_token="test-signing-secret",
        portal_secret_encryption_key=key,
        mfa_enforcement_required=False,
        mfa_enforcement_pivot_date=None,
        mfa_enforcement_grace_days=7,
    )
    kwargs.update(extra)
    return Settings(**kwargs)  # type: ignore[call-arg]


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
    req = StarletteRequest(scope)
    # Attach mutable state for banner injection
    req.state.mfa_grace_warning = None
    if cookies:
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        scope["headers"] = [(b"cookie", cookie_header.encode("latin-1"))]
        req = StarletteRequest(scope)
        req.state.mfa_grace_warning = None
    return req


def test_rp_id_and_origin_from_portal_fqdn():
    settings = _settings(portal_domain="portal.example.com")
    rp_id, origin = rp_id_and_origin(settings)
    assert rp_id == "portal.example.com"
    assert origin == "https://portal.example.com"


def test_rp_id_localhost_uses_http():
    settings = _settings(portal_domain="localhost")
    rp_id, origin = rp_id_and_origin(settings)
    assert rp_id == "localhost"
    assert origin == "http://localhost"


def test_registration_options_prefer_es256():
    settings = _settings()
    options, challenge = build_registration_options(settings, "admin@example.com")
    assert isinstance(challenge, bytes) and len(challenge) >= 16
    assert options["rp"]["id"] == "portal.example.com"
    assert options["user"]["name"] == "admin@example.com"
    algs = [p["alg"] for p in options["pubKeyCredParams"]]
    assert -7 in algs  # ES256


def test_challenge_cookie_roundtrip():
    settings = _settings()
    response = Response()
    challenge = b"\x01\x02\x03\x04" * 8
    stash_challenge(
        response,
        settings,
        user_email="Admin@Example.com",
        purpose="register",
        challenge=challenge,
    )
    set_cookie = response.headers.get("set-cookie", "")
    assert CHALLENGE_COOKIE in set_cookie
    value = None
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith(f"{CHALLENGE_COOKIE}="):
            value = part.split("=", 1)[1]
            break
    assert value
    req = _request(cookies={CHALLENGE_COOKIE: value})
    got = pop_challenge(
        req, settings, user_email="admin@example.com", purpose="register"
    )
    assert got == challenge
    # Wrong purpose
    assert (
        pop_challenge(req, settings, user_email="admin@example.com", purpose="assert")
        is None
    )


def test_verify_registration_stores_cose_base64url(db_session):
    settings = _settings()
    cred_id = b"\xaa" * 16
    # Minimal fake COSE key bytes (content opaque to persistence layer)
    cose_key = b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" + b"\x11" * 32
    verified = SimpleNamespace(
        credential_id=cred_id,
        credential_public_key=cose_key,
        sign_count=0,
    )
    with patch(
        "app.auth.webauthn_service.verify_registration_response",
        return_value=verified,
    ):
        row = verify_and_store_registration(
            db_session,
            settings,
            user_email="admin@example.com",
            credential={"id": "x", "response": {"transports": ["internal"]}},
            expected_challenge=b"chal",
        )
    assert row.webauthn_enabled is True
    assert row.webauthn_credential_id == bytes_to_base64url(cred_id)
    assert row.webauthn_public_key == bytes_to_base64url(cose_key)
    # No PEM / ASN.1 wrapping
    assert "BEGIN" not in (row.webauthn_public_key or "")
    assert row.webauthn_transports == ["internal"]


def test_authentication_options_require_enrolled_passkey(db_session):
    settings = _settings()
    with pytest.raises(WebAuthnError):
        build_authentication_options(db_session, settings, "nobody@example.com")


def test_authentication_options_and_verify_mocked(db_session):
    settings = _settings()
    cred_id = b"\xbb" * 16
    cose_key = b"\xcc" * 40
    row = AdminMfaCredential(
        user_email="admin@example.com",
        totp_enabled=False,
        webauthn_enabled=True,
        webauthn_credential_id=bytes_to_base64url(cred_id),
        webauthn_public_key=bytes_to_base64url(cose_key),
        webauthn_sign_count=1,
    )
    db_session.add(row)
    db_session.commit()

    options, challenge = build_authentication_options(
        db_session, settings, "admin@example.com"
    )
    assert options["rpId"] == "portal.example.com"
    assert options["allowCredentials"][0]["id"] == bytes_to_base64url(cred_id)
    assert isinstance(challenge, bytes)

    verified = SimpleNamespace(new_sign_count=2)
    with patch(
        "app.auth.webauthn_service.verify_authentication_response",
        return_value=verified,
    ):
        out = verify_authentication(
            db_session,
            settings,
            user_email="admin@example.com",
            credential={"id": "x"},
            expected_challenge=challenge,
        )
    assert out.webauthn_sign_count == 2


def test_disable_webauthn(db_session):
    settings = _settings()
    row = AdminMfaCredential(
        user_email="admin@example.com",
        totp_enabled=False,
        webauthn_enabled=True,
        webauthn_credential_id=bytes_to_base64url(b"\x01" * 16),
        webauthn_public_key=bytes_to_base64url(b"\x02" * 40),
        webauthn_sign_count=3,
    )
    db_session.add(row)
    db_session.commit()
    disable_webauthn(db_session, "admin@example.com")
    db_session.refresh(row)
    assert row.webauthn_enabled is False
    assert row.webauthn_credential_id is None
    assert row.webauthn_public_key is None


def test_grace_days_left_and_deadline():
    pivot = datetime(2026, 10, 1, tzinfo=timezone.utc)
    settings = _settings(
        mfa_enforcement_required=True,
        mfa_enforcement_pivot_date=pivot,
        mfa_enforcement_grace_days=7,
    )
    deadline = enforcement_deadline(settings)
    assert deadline == pivot + timedelta(days=7)

    now = pivot + timedelta(days=3, hours=1)
    left = grace_days_left(settings, now=now)
    assert left == 4  # days 3→7 inclusive-ish


def test_grace_banner_during_window(db_session):
    pivot = datetime.now(timezone.utc) - timedelta(days=1)
    settings = _settings(
        mfa_enforcement_required=True,
        mfa_enforcement_pivot_date=pivot,
        mfa_enforcement_grace_days=10,
    )
    req = _request("/admin/apps")
    apply_grace_banner(req, settings, enrolled=False)
    assert req.state.mfa_grace_warning
    assert "jour" in req.state.mfa_grace_warning


def test_enforce_enrollment_after_grace(db_session):
    pivot = datetime.now(timezone.utc) - timedelta(days=30)
    settings = _settings(
        mfa_enforcement_required=True,
        mfa_enforcement_pivot_date=pivot,
        mfa_enforcement_grace_days=7,
    )
    with pytest.raises(MfaEnrollmentRequired) as exc:
        enforce_admin_mfa(_request("/admin/apps"), _admin(), db_session, settings)
    assert "force_mfa=1" in exc.value.redirect_url


def test_enforce_allows_during_grace_with_banner(db_session):
    pivot = datetime.now(timezone.utc) - timedelta(days=1)
    settings = _settings(
        mfa_enforcement_required=True,
        mfa_enforcement_pivot_date=pivot,
        mfa_enforcement_grace_days=14,
    )
    req = _request("/admin/apps")
    enforce_admin_mfa(req, _admin(), db_session, settings)  # no raise
    assert req.state.mfa_grace_warning


def test_enforce_skips_when_webauthn_enrolled_with_cookie(db_session):
    from app.auth.mfa_cookie import MFA_COOKIE_NAME, set_mfa_ok_cookie

    settings = _settings(
        mfa_enforcement_required=True,
        mfa_enforcement_pivot_date=datetime(2020, 1, 1, tzinfo=timezone.utc),
        mfa_enforcement_grace_days=0,
    )
    row = AdminMfaCredential(
        user_email="admin@example.com",
        totp_enabled=False,
        webauthn_enabled=True,
        webauthn_credential_id=bytes_to_base64url(b"\x01" * 16),
        webauthn_public_key=bytes_to_base64url(b"\x02" * 40),
        webauthn_sign_count=0,
    )
    db_session.add(row)
    db_session.commit()

    response = Response()
    set_mfa_ok_cookie(response, settings, "admin@example.com")
    value = None
    for part in response.headers.get("set-cookie", "").split(";"):
        part = part.strip()
        if part.startswith(f"{MFA_COOKIE_NAME}="):
            value = part.split("=", 1)[1]
            break
    req = _request("/admin/apps", cookies={MFA_COOKIE_NAME: value})
    enforce_admin_mfa(req, _admin(), db_session, settings)


def test_templates_hybrid_challenge_and_passkey():
    root = Path(__file__).resolve().parents[1]
    challenge = (
        root / "app/templates/admin/mfa_challenge.html"
    ).read_text(encoding="utf-8")
    assert "mfa-webauthn-btn" in challenge
    assert "webauthn/options" in challenge
    assert "totp-fallback" in challenge
    profile = (root / "app/templates/admin/profile.html").read_text(
        encoding="utf-8"
    )
    assert "mfa-webauthn-register" in profile
    assert "force_mfa" in profile
