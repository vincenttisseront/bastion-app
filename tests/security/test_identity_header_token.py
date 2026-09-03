"""SDD-001: identity headers require a valid X-Portal-Internal-Token."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tests.conftest import TEST_PORTAL_INTERNAL_TOKEN

ADMIN_SPOOF = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def test_forged_admin_headers_without_token_rejected(client: TestClient):
    """Direct FastAPI access with spoofed X-Email/X-Groups and no token → unauthenticated."""
    resp = client.get(
        "/admin",
        headers={
            **ADMIN_SPOOF,
            "X-Test-Omit-Internal-Token": "1",
        },
        follow_redirects=False,
    )
    # Unauthenticated HTML → redirect to login (or 401 JSON depending on Accept).
    assert resp.status_code in (302, 401, 403)
    if resp.status_code == 302:
        loc = resp.headers.get("location") or ""
        assert "/admin" not in loc.rstrip("/")
        assert "login" in loc.lower() or "/auth" in loc.lower() or loc.startswith("/")


def test_forged_admin_headers_with_wrong_token_rejected(client: TestClient):
    resp = client.get(
        "/admin",
        headers={
            **ADMIN_SPOOF,
            "X-Portal-Internal-Token": "not-the-real-token",
        },
        follow_redirects=False,
    )
    assert resp.status_code in (302, 401, 403)


def test_admin_headers_with_valid_token_accepted(client: TestClient):
    resp = client.get(
        "/admin",
        headers={
            **ADMIN_SPOOF,
            "X-Portal-Internal-Token": TEST_PORTAL_INTERNAL_TOKEN,
        },
        follow_redirects=False,
    )
    # Authenticated admin reaches admin hub (200) or redirect within admin.
    assert resp.status_code in (200, 302)
    if resp.status_code == 302:
        loc = resp.headers.get("location") or ""
        assert "/login" not in loc.lower()


def test_get_user_context_ignores_headers_without_token(db_session: Session):
    from starlette.requests import Request

    from app.models import AuditLog
    from app.sso_settings import Settings
    from app.web.user_context import get_user_context

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/admin",
        "raw_path": b"/admin",
        "query_string": b"",
        "headers": [
            (b"x-email", b"admin@example.com"),
            (b"x-groups", b"portal-admins"),
        ],
        "client": ("10.5.0.99", 12345),
        "server": ("test", 80),
    }
    request = Request(scope)
    settings = Settings(
        environment="test",
        vault_portal_internal_token=TEST_PORTAL_INTERNAL_TOKEN,
    )
    assert get_user_context(request, settings, db=db_session) is None
    row = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "security.identity_header_spoof")
        .order_by(AuditLog.id.desc())
        .first()
    )
    assert row is not None
    assert row.event_code == "BST-AUTH-4001"
    assert row.target == "ip:10.5.0.99"


def test_get_user_context_trusts_headers_with_token(db_session: Session):
    from starlette.requests import Request

    from app.sso_settings import Settings
    from app.web.user_context import get_user_context

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/admin",
        "raw_path": b"/admin",
        "query_string": b"",
        "headers": [
            (b"x-email", b"admin@example.com"),
            (b"x-groups", b"portal-admins"),
            (b"x-portal-internal-token", TEST_PORTAL_INTERNAL_TOKEN.encode()),
        ],
        "client": ("10.5.0.2", 12345),
        "server": ("test", 80),
    }
    request = Request(scope)
    settings = Settings(
        environment="test",
        vault_portal_internal_token=TEST_PORTAL_INTERNAL_TOKEN,
    )
    user = get_user_context(request, settings, db=db_session)
    assert user is not None
    assert user.email == "admin@example.com"
    assert user.is_admin is True
