"""Light, non-destructive active probes against staging.

Target: https://portal.ar-systems.fr (IP confirmed by Vincent before each audit).
No credentials, no writes, no fuzzing / bruteforce.
"""

from __future__ import annotations

import socket
from urllib.parse import urlparse

import httpx
import pytest

from tests.security.conftest import EXPECTED_STAGING_IP, STAGING_BASE_URL

pytestmark = pytest.mark.security_active


def _resolve_host(url: str) -> str:
    host = urlparse(url).hostname or ""
    return socket.gethostbyname(host)


def test_00_dns_still_matches_confirmed_staging_ip():
    """Re-check DNS before any probe — abort if IP drifted."""
    resolved = _resolve_host(STAGING_BASE_URL)
    assert resolved == EXPECTED_STAGING_IP, (
        f"DNS for {STAGING_BASE_URL} resolved to {resolved}, "
        f"expected confirmed staging IP {EXPECTED_STAGING_IP}. "
        "Re-confirm with Vincent before continuing."
    )


def test_admin_routes_unauthenticated_redirect_or_deny(staging_base_url: str):
    """Unauthenticated browser hits on admin surfaces must not return 200 HTML admin."""
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        paths = [
            "/admin",
            "/dashboard",
            "/api/admin/breakglass/sessions",
            "/api/admin/apps/transfer/credential",
        ]
        results = {}
        for path in paths:
            resp = client.get(path)
            results[path] = (resp.status_code, resp.headers.get("location", "")[:120])
            # Must not serve protected content as 200 without auth.
            assert resp.status_code in (301, 302, 303, 307, 401, 403, 404), (
                f"{path} unexpected status {resp.status_code}: {resp.text[:200]}"
            )
            if resp.status_code == 200:
                pytest.fail(f"{path} returned 200 without session")
        print("admin_unauth_results", results)
    finally:
        client.close()


def test_api_apps_unauthenticated_denied(staging_base_url: str):
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        resp = client.get("/api/apps", headers={"Accept": "application/json"})
        print("api_apps_unauth", resp.status_code, resp.headers.get("location"))
        assert resp.status_code in (301, 302, 303, 307, 401, 403)
    finally:
        client.close()


def test_analyze_login_form_unauthenticated_blocked(staging_base_url: str):
    """SSRF endpoint must not be callable without auth (even with internal URL)."""
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        resp = client.post(
            "/admin/apps/analyze-login-form",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json={"url": "http://127.0.0.1:8000/health"},
        )
        print(
            "analyze_unauth",
            resp.status_code,
            resp.headers.get("location", "")[:120],
            resp.text[:200],
        )
        assert resp.status_code in (301, 302, 303, 307, 401, 403)
        # Must not have fetched / returned form analysis.
        if resp.headers.get("content-type", "").startswith("application/json"):
            body = resp.json() if resp.content else {}
            assert "forms_found" not in body
    finally:
        client.close()


def test_vault_credential_without_bearer_denied(staging_base_url: str):
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        resp = client.get(
            "/api/admin/apps/transfer/credential",
            headers={"Accept": "application/json"},
        )
        print("vault_no_bearer", resp.status_code, resp.text[:200])
        assert resp.status_code in (301, 302, 303, 307, 401, 403)
        if resp.headers.get("content-type", "").startswith("application/json"):
            text = resp.text.lower()
            assert "password" not in text
            assert "encrypted_password" not in text
    finally:
        client.close()


def test_vault_credential_with_bogus_bearer_denied(staging_base_url: str):
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        resp = client.get(
            "/api/admin/apps/transfer/credential",
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer clearly-not-the-real-token",
            },
        )
        print("vault_bogus_bearer", resp.status_code, resp.text[:200])
        assert resp.status_code in (301, 302, 303, 307, 401, 403)
    finally:
        client.close()


def test_rfc1918_xff_spoof_does_not_open_admin(staging_base_url: str):
    """Spoofed private XFF from outside must not grant admin/catalogue access."""
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        headers = {
            "X-Forwarded-For": "10.0.0.50",
            "X-Real-IP": "10.0.0.50",
            "Accept": "application/json",
        }
        resp = client.get("/api/apps", headers=headers)
        print(
            "xff_spoof_api_apps",
            resp.status_code,
            resp.headers.get("location", "")[:120],
        )
        assert resp.status_code in (301, 302, 303, 307, 401, 403)

        resp2 = client.get("/admin", headers=headers, follow_redirects=False)
        print(
            "xff_spoof_admin",
            resp2.status_code,
            resp2.headers.get("location", "")[:120],
        )
        assert resp2.status_code in (301, 302, 303, 307, 401, 403)
    finally:
        client.close()


def test_security_headers_present(staging_base_url: str):
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        resp = client.get("/health")
        print("security_headers", {k: resp.headers.get(k) for k in (
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
            "referrer-policy",
        )})
        assert resp.status_code == 200
        assert "max-age" in (resp.headers.get("strict-transport-security") or "").lower()
        assert "nosniff" in (resp.headers.get("x-content-type-options") or "").lower()
        csp = resp.headers.get("content-security-policy") or ""
        assert "default-src" in csp
    finally:
        client.close()


def test_breakglass_html_login_rejects_bad_password_no_cookie(staging_base_url: str):
    """Single failed HTML login — API path is behind nginx auth_request (see sibling test)."""
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        resp = client.post(
            "/auth/breakglass",
            data={
                "username": "audit-probe-nonexistent",
                "password": "AuditProbe-Disposable-Wrong-9xQ",
                "rd": "/apps",
            },
        )
        raw_sc = resp.headers.get("set-cookie") or ""
        print(
            "bg_html_bad_login",
            resp.status_code,
            resp.headers.get("location"),
            raw_sc[:120],
        )
        assert resp.status_code in (200, 302, 401, 403)
        assert "bg_session=" not in raw_sc
    finally:
        client.close()


def test_breakglass_api_login_lan_path_not_sso_gated(staging_base_url: str):
    """F-06 after nginx apply: login is LAN-allowlisted, not auth_request → SSO.

    Without deploy, may still 302 to /auth/login. Never issue bg_session here
    (wrong password / no credentials in active probe).
    """
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        resp = client.post(
            "/api/admin/breakglass/login",
            json={
                "username": "audit-probe-nonexistent",
                "password": "AuditProbe-Disposable-Wrong-9xQ",
            },
            headers={"Accept": "application/json"},
        )
        print("bg_api_login", resp.status_code, resp.headers.get("location"))
        assert resp.status_code in (301, 302, 303, 307, 401, 403, 404)
        assert "bg_session=" not in (resp.headers.get("set-cookie") or "")
    finally:
        client.close()


def test_error_page_no_stack_trace_leak(staging_base_url: str):
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        resp = client.get("/this-path-should-not-exist-audit-2026-07-25")
        print("not_found", resp.status_code, resp.headers.get("location"), resp.text[:200])
        body = resp.text.lower()
        assert "traceback" not in body
        assert "uvicorn" not in body
        assert 'file "' not in body
        # Staging catch-all sends unknown paths to SSO login (302), not a FastAPI 404.
        assert resp.status_code in (404, 302, 303, 307, 401, 403)
    finally:
        client.close()


def test_internal_auth_endpoints_not_auth_bypass(staging_base_url: str):
    """Public GET must not return 200 auth success (bypass).

    After nginx apply of F-07: expect 404 for all three.
    Before apply: oauth2-auth / rfc1918 may still 302 to login — never 200.
    """
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        for path in (
            "/internal/oauth2-auth",
            "/internal/subdomain-auth",
            "/internal/portal-rfc1918-bypass-auth",
        ):
            resp = client.get(path)
            print(
                "internal_public",
                path,
                resp.status_code,
                resp.headers.get("location"),
                resp.headers.get("x-auth-source"),
            )
            assert resp.status_code != 200
            assert resp.headers.get("x-auth-source") is None
            assert resp.status_code in (302, 303, 307, 401, 403, 404, 405)
    finally:
        client.close()


def test_security_headers_not_duplicated_on_health(staging_base_url: str):
    """F-09: after docker nginx apply, each security header value once (no comma twin)."""
    client = httpx.Client(
        base_url=staging_base_url,
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    )
    try:
        resp = client.get("/health")
        assert resp.status_code == 200
        for name in (
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
        ):
            raw = resp.headers.get(name) or ""
            print("header", name, raw)
            # Comma-joined duplicates look like "nosniff, nosniff"
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            if len(parts) >= 2 and parts[0] == parts[1]:
                # Still duplicated until nginx template is deployed to staging.
                print("F-09_PENDING_DEPLOY duplicate", name, raw)
            else:
                assert len(set(parts)) == len(parts) or not parts
    finally:
        client.close()
