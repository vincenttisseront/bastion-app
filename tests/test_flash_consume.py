"""Flash cookie must display once then clear (not on every navigation)."""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import Response

from app.web.flash import (
    FLASH_COOKIE,
    clear_flash,
    get_flash_messages,
    set_flash,
)
from app.web.templates import render


SECRET = "test-flash-secret"


def _request_with_flash_cookie(cookie_val: str) -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/apps",
        "raw_path": b"/apps",
        "query_string": b"",
        "headers": [(b"cookie", f"{FLASH_COOKIE}={cookie_val}".encode())],
        "client": ("127.0.0.1", 123),
        "server": ("test", 80),
    }
    return Request(scope)


def test_get_flash_marks_consume_flag():
    seed = Response()
    set_flash(
        seed,
        [{"message": "Connexion break-glass réussie.", "category": "success"}],
        SECRET,
    )
    cookie_val = seed.headers.get("set-cookie", "").split(";", 1)[0].split("=", 1)[1]
    request = _request_with_flash_cookie(cookie_val)

    msgs = get_flash_messages(request, SECRET)
    assert len(msgs) == 1
    assert msgs[0]["message"] == "Connexion break-glass réussie."
    assert getattr(request.state, "flash_consume", False) is True


def test_clear_flash_deletes_cookie():
    resp = Response()
    clear_flash(resp)
    set_cookie = " ".join(resp.headers.getlist("set-cookie")).lower()
    assert FLASH_COOKIE in set_cookie
    assert "max-age=0" in set_cookie or "expires=" in set_cookie


def test_render_clears_consumed_flash_cookie():
    seed = Response()
    set_flash(
        seed,
        [{"message": "Connexion break-glass réussie.", "category": "success"}],
        SECRET,
    )
    cookie_val = seed.headers.get("set-cookie", "").split(";", 1)[0].split("=", 1)[1]
    request = _request_with_flash_cookie(cookie_val)
    assert get_flash_messages(request, SECRET)

    response = render(
        "errors/404.html",
        request=request,
        messages=[{"message": "Connexion break-glass réussie.", "category": "success"}],
        current_user=None,
        is_admin=False,
        is_portal_admin=False,
        csrf_token="x",
        hide_chrome=True,
        app_version="test",
        realm_slug="ar-systems",
        status_code=404,
    )
    set_cookies = " ".join(response.headers.getlist("set-cookie")).lower()
    assert FLASH_COOKIE in set_cookies
    assert "max-age=0" in set_cookies or "expires=" in set_cookies


def test_flash_cookie_is_base64_encoded_for_waf():
    seed = Response()
    set_flash(
        seed,
        [{"message": "Mot de passe incorrect ou compte verrouillé.", "category": "error"}],
        SECRET,
    )
    cookie_val = seed.headers.get("set-cookie", "").split(";", 1)[0].split("=", 1)[1]
    assert cookie_val.startswith("b64.")
    assert "[" not in cookie_val
    assert "{" not in cookie_val
    request = _request_with_flash_cookie(cookie_val)
    msgs = get_flash_messages(request, SECRET)
    assert msgs[0]["message"] == "Mot de passe incorrect ou compte verrouillé."


def test_flash_cookie_reads_legacy_signed_json():
    seed = Response()
    set_flash(
        seed,
        [{"message": "Legacy flash", "category": "info"}],
        SECRET,
    )
    # Simulate pre-base64 cookie: signed JSON payload in clear.
    from app.web.flash import _sign
    import json

    legacy = _sign(json.dumps([{"message": "Legacy flash", "category": "info"}]), SECRET)
    request = _request_with_flash_cookie(legacy)
    msgs = get_flash_messages(request, SECRET)
    assert msgs[0]["message"] == "Legacy flash"
