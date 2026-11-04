"""Regression tests — review findings S1 (break-glass identity), S3 (admin MFA
bypass outside /admin) and S5 (permissive admin group check)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.admin.throttling import reset_test_rate_limits
from app.auth.breakglass import COOKIE_NAME, issue_breakglass_token
from app.models import AdminMfaCredential, App
from app.sso_settings import Settings
from app.web.user_context import UserContext, get_user_context

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "test-secret"
BG_SECRET = "test-breakglass-secret-for-pytest-32b"


def _settings(**extra) -> Settings:
    base = dict(
        vault_portal_internal_token=TOKEN,
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
        breakglass_jwt_secret=BG_SECRET,
        sso_portal_default_realm_slug="example-corp",
        portal_admin_groups=["portal-admins"],
    )
    base.update(extra)
    return Settings(**base)


def _request(headers: dict[str, str], *, cookies: str = "", path: str = "/") -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    raw.append((b"x-portal-internal-token", TOKEN.encode()))
    if cookies:
        raw.append((b"cookie", cookies.encode()))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "query_string": b"",
            "headers": raw,
            "client": ("10.0.0.8", 1234),
            "server": ("portal.test", 443),
            "scheme": "https",
        }
    )


# --- S1 : break-glass only from a validated bg_session cookie ----------------


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Email": "admin@breakglass.local", "X-Groups": ""},
        {"X-Email": "", "X-Preferred-Username": "admin@BreakGlass.Local"},
        {"X-User": "root@breakglass.local"},
        {
            "X-Email": "admin@breakglass.local",
            "X-Portal-Auth-Source": "breakglass",
            "X-Groups": "portal-admins",
        },
    ],
)
def test_s1_reserved_breakglass_domain_from_idp_is_rejected(headers):
    assert get_user_context(_request(headers), settings=_settings(), db=None) is None


@pytest.mark.parametrize("source", ["breakglass", "break-glass"])
def test_s1_x_portal_auth_source_header_is_ignored(source):
    user = get_user_context(
        _request({"X-Email": "eve@example.com", "X-Portal-Auth-Source": source}),
        settings=_settings(),
        db=None,
    )
    assert user is not None
    assert user.auth_source == "sso"
    assert not user.is_breakglass
    assert not user.is_admin


def test_s1_forged_breakglass_email_cannot_reach_admin(client: TestClient):
    resp = client.get(
        "/admin/files",
        headers={"X-Email": "eve@breakglass.local", "X-Groups": ""},
        follow_redirects=False,
    )
    assert resp.status_code != 200


def test_s1_validated_bg_cookie_still_grants_breakglass(db_session: Session):
    token, _jti = issue_breakglass_token(db_session, "admin", BG_SECRET)
    db_session.commit()
    user = get_user_context(
        _request(
            {"X-Portal-Realm-Slug": "example-corp"}, cookies=f"{COOKIE_NAME}={token}"
        ),
        settings=_settings(),
        db=db_session,
    )
    assert user is not None
    assert user.is_breakglass and user.is_admin
    assert user.realm_slug == ""


def test_s1_nginx_no_longer_derives_auth_source_from_cookie():
    for rel in (
        "docker/nginx/nginx.conf",
        "docker/nginx/templates/vhost_sso_portal.conf.template",
        "nginx/vhosts/vhost_sso_portal.conf.j2",
        "nginx/snippets/proxy_portal_admin_location.conf.j2",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "portal_x_auth_source" not in text, rel
        assert "nginx-portal-breakglass.map" not in text, rel
    assert not (ROOT / "docker/nginx/includes/nginx-portal-breakglass.map.conf").exists()
    assert not (ROOT / "nginx/maps/nginx-portal-breakglass.map.conf").exists()
    # The anti-spoofing snippet keeps blanking any client-sent value.
    strip = (ROOT / "docker/nginx/snippets/proxy_portal_strip_identity.conf").read_text(
        encoding="utf-8"
    )
    assert 'proxy_set_header X-Portal-Auth-Source "";' in strip


# --- S5 : admin groups — exact full path, default realm, no generic "admins" --


@pytest.mark.parametrize(
    ("groups", "expected"),
    [
        ("portal-admins", True),
        ("/portal-admins", True),
        ("/portal-admins/", True),
        ("/client-a/portal-admins", False),
        ("client-a/portal-admins", False),
        ("admins", False),
        ("portal-admins-x", False),
    ],
)
def test_s5_admin_group_requires_exact_full_path(groups, expected):
    user = get_user_context(
        _request({"X-Email": "u@example.com", "X-Groups": groups}),
        settings=_settings(),
        db=None,
    )
    assert user is not None
    assert user.is_admin is expected


def test_s5_admin_group_only_in_portal_default_realm():
    user = get_user_context(
        _request(
            {
                "X-Email": "u@example.com",
                "X-Groups": "/portal-admins",
                "X-Portal-Realm-Slug": "client-a",
            }
        ),
        settings=_settings(),
        db=None,
    )
    assert user is not None
    assert not user.is_admin


def test_s5_generic_admins_group_not_in_defaults():
    assert "admins" not in Settings().portal_admin_groups
    assert "admins" not in Settings(portal_admin_groups="").portal_admin_groups


@pytest.mark.asyncio
async def test_s5_auth_request_ignores_client_x_realm_slug(db_session: Session):
    from app.auth import auth_request as ar

    default = SimpleNamespace(slug="example-corp")
    seen: dict[str, str] = {}

    def fake_proxy_url(slug, _settings, _db):
        seen["slug"] = slug
        return "http://oauth2-proxy:4180"

    fake_resp = SimpleNamespace(status_code=202, headers={})
    with (
        patch.object(ar, "get_default_idp_realm", return_value=default),
        patch.object(ar, "get_realm_proxy_url", side_effect=fake_proxy_url),
        patch.object(ar, "_get_oauth2_auth", new=AsyncMock(return_value=fake_resp)),
        patch.object(ar, "_forward_auth_request_headers", return_value={}),
    ):
        resp = await ar._oauth2_proxy_auth_response(
            _request({"X-Realm-Slug": "attacker-realm"}), _settings(), db_session
        )
    assert seen["slug"] == "example-corp"
    assert resp.headers["X-Auth-Request-Realm"] == "example-corp"


# --- S3 : admin bypass outside /admin requires the admin MFA gate -------------


def _enrolled_admin(db: Session, email: str = "admin@example.com") -> UserContext:
    db.add(AdminMfaCredential(user_email=email, totp_enabled=True))
    db.commit()
    return UserContext(
        email=email,
        username="admin",
        groups=["portal-admins"],
        realm_slug="example-corp",
        auth_source="sso",
        is_admin=True,
        keycloak_user_id="kc-admin",
    )


def test_s3_robotic_admin_bypass_needs_mfa(db_session: Session):
    from app.robotic.client_open_action import _check_app_rbac

    db_session.add(
        App(slug="transfer", label="T", upstream_url="https://t.example/", enabled=True)
    )
    db_session.commit()
    admin = _enrolled_admin(db_session)
    settings = _settings()
    req = _request({}, path="/api/internal/impersonate/transfer")

    denied = _check_app_rbac(db_session, "transfer", admin, request=req, settings=settings)
    assert denied is not None and denied.status_code == 403

    with patch("app.auth.mfa_gate.is_mfa_cookie_valid", return_value=True):
        assert (
            _check_app_rbac(db_session, "transfer", admin, request=req, settings=settings)
            is None
        )


def test_s3_files_portal_admin_needs_mfa(db_session: Session):
    from app.files.routes import _portal_admin

    admin = _enrolled_admin(db_session)
    settings = _settings()
    req = _request({}, path="/files")
    assert _portal_admin(req, admin, db_session, settings) is False
    with patch("app.auth.mfa_gate.is_mfa_cookie_valid", return_value=True):
        assert _portal_admin(req, admin, db_session, settings) is True


def test_s3_sessions_admin_view_needs_mfa(db_session: Session):
    from app.auth.mfa_gate import elevate_portal_admin_mfa

    admin = _enrolled_admin(db_session)
    req = _request({}, path="/api/sessions")
    assert elevate_portal_admin_mfa(req, admin, db_session, _settings()).is_admin is False
    with patch("app.auth.mfa_gate.is_mfa_cookie_valid", return_value=True):
        assert elevate_portal_admin_mfa(req, admin, db_session, _settings()).is_admin


def test_s3_robotic_open_route_denies_admin_without_mfa(
    client: TestClient, db_session: Session
):
    """End-to-end: the impersonate route no longer lets an un-challenged admin in."""
    reset_test_rate_limits()
    db_session.add(
        App(
            slug="transfer",
            label="Transfer",
            upstream_url="https://crush.example/",
            robotic_driver="crushftp",
            access_mode="legacy_path_proxy",
            enabled=True,
        )
    )
    db_session.add(AdminMfaCredential(user_email="admin@example.com", totp_enabled=True))
    db_session.commit()
    resp = client.get(
        "/api/internal/impersonate/transfer",
        headers={"X-Email": "admin@example.com", "X-Groups": "portal-admins"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_s5_admin_group_accepted_in_db_default_idp_realm():
    """The realm stamped by /internal/oauth2-auth is the DB default IdP realm."""
    from unittest.mock import MagicMock

    db = MagicMock()
    with (
        patch(
            "app.auth.flow.get_default_idp_realm",
            return_value=SimpleNamespace(slug="corp-idp"),
        ),
        patch("app.web.user_context.user_has_portal_admin_role", return_value=False),
        patch("app.web.user_context.enrich_user_identity"),
    ):
        user = get_user_context(
            _request(
                {
                    "X-Email": "u@example.com",
                    "X-Groups": "/portal-admins",
                    "X-Portal-Realm-Slug": "corp-idp",
                }
            ),
            settings=_settings(),
            db=db,
        )
    assert user is not None and user.is_admin
