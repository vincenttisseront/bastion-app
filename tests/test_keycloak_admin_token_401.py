"""Keycloak Admin API: a 401 evicts the rejected service-account token and retries once."""

from __future__ import annotations

import time
from types import SimpleNamespace

import httpx
import respx

from app.rbac import keycloak_admin as kc

ISSUER = "https://kc.example.test/realms/acme"
USER_URL = "https://kc.example.test/admin/realms/acme/users/abc"
REALM = SimpleNamespace(issuer_url=ISSUER)


def _seed_cache(token: str) -> None:
    kc._TOKEN_CACHE[("endpoint", "client", "secret")] = (token, time.monotonic() + 60)


def _fake_tokens(monkeypatch, *tokens: str) -> list[str]:
    issued = iter(tokens)
    calls: list[str] = []

    async def fake_get_admin_token(realm, settings):  # noqa: ANN001
        token = next(issued)
        calls.append(token)
        return token

    monkeypatch.setattr(kc, "get_admin_token", fake_get_admin_token)
    return calls


def _reply_by_bearer(good: str):
    def _reply(request: httpx.Request) -> httpx.Response:
        ok = request.headers["authorization"] == f"Bearer {good}"
        return httpx.Response(200 if ok else 401, json={"id": "abc"})

    return _reply


async def test_get_retries_once_with_fresh_token_after_401(monkeypatch):
    _seed_cache("stale")
    calls = _fake_tokens(monkeypatch, "stale", "fresh")
    with respx.mock(assert_all_called=True) as router:
        route = router.get(USER_URL).mock(side_effect=_reply_by_bearer("fresh"))
        resp = await kc._admin_get(REALM, None, "/users/abc")
    assert resp.status_code == 200
    assert route.call_count == 2
    assert calls == ["stale", "fresh"]
    assert kc._TOKEN_CACHE == {}


async def test_get_retries_only_once(monkeypatch):
    _fake_tokens(monkeypatch, "t1", "t2", "t3")
    with respx.mock() as router:
        route = router.get(USER_URL).mock(return_value=httpx.Response(401))
        resp = await kc._admin_get(REALM, None, "/users/abc")
    assert resp.status_code == 401
    assert route.call_count == 2


async def test_get_with_caller_token_is_not_retried_but_evicted(monkeypatch):
    _seed_cache("provision")
    calls = _fake_tokens(monkeypatch)
    with respx.mock() as router:
        route = router.get(USER_URL).mock(return_value=httpx.Response(401))
        resp = await kc._admin_get(REALM, None, "/users/abc", token="provision")
    assert resp.status_code == 401
    assert route.call_count == 1
    assert calls == []
    assert kc._TOKEN_CACHE == {}


async def test_get_403_is_not_retried(monkeypatch):
    calls = _fake_tokens(monkeypatch, "t1")
    with respx.mock() as router:
        route = router.get(USER_URL).mock(return_value=httpx.Response(403))
        resp = await kc._admin_get(REALM, None, "/users/abc")
    assert resp.status_code == 403
    assert route.call_count == 1
    assert calls == ["t1"]


async def test_post_retries_once_with_fresh_token_after_401(monkeypatch):
    _seed_cache("stale")
    _fake_tokens(monkeypatch, "stale", "fresh")
    with respx.mock(assert_all_called=True) as router:
        route = router.post(f"{USER_URL}/logout").mock(
            side_effect=lambda request: httpx.Response(
                204 if request.headers["authorization"] == "Bearer fresh" else 401
            )
        )
        resp = await kc._admin_post(REALM, None, "/users/abc/logout")
    assert resp.status_code == 204
    assert route.call_count == 2
    assert kc._TOKEN_CACHE == {}
