"""Every error the bastion serves is a branded page — never a bare nginx / JSON one.

Static pages (docker/nginx/errors) are generated from app/web/static_error_pages.py
and served by bastion-nginx itself, so they keep working while bastion-app or an
app upstream is down. Non-HTML clients (ActiveSync, M2M, /api/*) get text / JSON.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.bastion.nginx_error_pages import (
    ERROR_PAGE_CODES,
    error_page_lines,
    error_pages_location_lines,
)
from app.bastion.nginx_public_proxy_export import generate_public_proxy_server_block
from app.bastion.nginx_subdomain_export import generate_subdomain_server_block
from app.bastion.unknown_host_routes import render_unknown_host_page
from app.models import App
from app.sso_settings import Settings
from app.web.static_error_pages import (
    STATIC_ERROR_PAGES,
    build_static_error_files,
    wants_html_error,
)

ROOT = Path(__file__).resolve().parents[1]
NGINX = ROOT / "docker" / "nginx"
ERRORS = NGINX / "errors"
BROWSER_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _settings() -> Settings:
    return Settings(  # type: ignore[call-arg]
        portal_domain="portal.example.com",
        sso_portal_default_realm_slug="example-corp",
        exports_dir="data/test-exports",
    )


def _app(**kwargs) -> App:
    base = {
        "slug": "mail",
        "label": "Mail",
        "upstream_url": "https://10.0.0.20/",
        "access_mode": "subdomain_proxy",
        "public_fqdn": "mail.example.com",
        "enabled": True,
    }
    base.update(kwargs)
    return App(**base)


def _blocks(conf: str) -> dict[str, str]:
    """``location …`` header → body (single nesting level, as generated)."""
    out: dict[str, str] = {}
    for match in re.finditer(r"^\s*location ([^{]+)\{\n(.*?)^    \}", conf, re.MULTILINE | re.DOTALL):
        out[match.group(1).strip()] = match.group(2)
    return out


def _covered_codes(body: str) -> set[int]:
    codes: set[int] = set()
    for line in re.findall(r"error_page ([^;]+);", body):
        for token in line.split():
            if token.isdigit():
                codes.add(int(token))
    return codes


# --- static files ------------------------------------------------------------


def test_committed_nginx_error_pages_match_generator():
    expected = build_static_error_files()
    on_disk = {p.name for p in ERRORS.iterdir() if p.is_file()}
    assert on_disk == set(expected), "run scripts/generate_nginx_error_pages.py"
    for name, content in expected.items():
        assert _read(ERRORS / name) == content, (
            f"{name} drifted — run scripts/generate_nginx_error_pages.py"
        )


@pytest.mark.parametrize("key", sorted(STATIC_ERROR_PAGES))
def test_static_html_page_is_self_contained_and_bilingual(key: str):
    page = STATIC_ERROR_PAGES[key]
    html = _read(ERRORS / f"{key}.html")
    assert f'data-bastion-error="{key}"' in html
    assert '<meta charset="utf-8">' in html
    assert 'name="viewport"' in html
    assert page.fr_title in html.replace("&#39;", "'")
    assert page.en_title in html
    assert f'<p class="code">{page.status}</p>' in html
    # Portal palette (bastion-tokens.css), inline only — bastion-app may be down.
    assert "#7b93ff" in html
    assert "#10b981" not in html
    assert "<style>" in html
    assert not re.search(r"""(?:src|href)=["'](?:https?:)?//""", html)
    assert "/static/" not in html
    assert "<script" not in html
    # Unknown Hosts can reach these pages: no product / company identity.
    assert "Bastion" not in html
    assert "AR-SYSTEMS" not in html
    assert "nginx" not in html.lower()


@pytest.mark.parametrize("key", sorted(STATIC_ERROR_PAGES))
def test_static_json_and_text_variants(key: str):
    page = STATIC_ERROR_PAGES[key]
    body = json.loads(_read(ERRORS / f"{key}.json"))
    assert body == {"code": page.slug, "message": page.fr_message}
    text = _read(ERRORS / f"{key}.txt")
    assert text.startswith(f"{page.status} ")
    assert "<" not in text


def test_bad_request_aliases_are_sent_as_400():
    for key in ("494", "495", "496"):
        assert STATIC_ERROR_PAGES[key].status == 400


def test_unknown_host_page_stays_neutral():
    html = _read(ERRORS / "unknown-host.html")
    assert html == render_unknown_host_page()
    assert "#10b981" not in html
    assert "#7b93ff" not in html
    assert "Accès" not in html


def test_every_nginx_error_code_has_its_files():
    for code in ERROR_PAGE_CODES:
        for ext in ("html", "json", "txt"):
            assert (ERRORS / f"{code}.{ext}").is_file(), f"{code}.{ext}"


# --- docker/nginx config (portal, edge, snippets) ------------------------------


def _referenced_error_files(text: str) -> set[str]:
    files: set[str] = set()
    for codes, target in re.findall(r"error_page ([0-9 =]+) (/__bastion_errors/\S+);", text):
        name = target.removeprefix("/__bastion_errors/")
        if "$status" in name:
            for token in codes.split():
                if token.isdigit():
                    files.add(name.replace("$status", token))
        else:
            files.add(name)
    return files


def test_every_referenced_static_page_exists():
    sources = [
        *NGINX.joinpath("snippets").glob("*.conf"),
        NGINX / "templates" / "vhost_sso_portal.conf.template",
        NGINX / "sync-acme-tls.sh",
        ROOT / "ansible/roles/bastion_app_docker/templates/nginx-infra-proxy-apps.conf.j2",
    ]
    referenced: set[str] = set()
    for path in sources:
        referenced |= _referenced_error_files(_read(path))
    generated = "\n".join(
        [
            generate_subdomain_server_block(
                _app(allow_activesync=True, m2m_bypass_paths="/dav/"), _settings()
            ),
            generate_public_proxy_server_block(_app(access_mode="public_proxy")),
        ]
    )
    referenced |= _referenced_error_files(generated)
    assert referenced, "no error_page found"
    missing = sorted(name for name in referenced if not (ERRORS / name).is_file())
    assert not missing, missing


def test_status_pages_never_use_status_variable_for_400_aliases():
    """nginx rewrites 494–496 to 400 before $status is read → explicit files."""
    for path in NGINX.joinpath("snippets").glob("*.conf"):
        for codes in re.findall(r"error_page ([0-9 ]+) /__bastion_errors/\$status", _read(path)):
            assert not {"494", "495", "496", "497"} & set(codes.split()), path.name


def test_location_snippet_matches_python_helper():
    snippet = _read(NGINX / "snippets" / "bastion_error_pages_location.conf")
    for line in error_pages_location_lines(indent="")[1:]:
        assert line in snippet, line
    html = _read(NGINX / "snippets" / "bastion_error_pages_html.conf")
    for line in error_page_lines("html", indent=""):
        assert line in html, line


def test_portal_server_level_wiring():
    pages = _read(NGINX / "snippets" / "error_pages.conf")
    assert "proxy_intercept_errors off;" in pages
    assert "recursive_error_pages on;" in pages
    assert "include /etc/nginx/snippets/error_pages_portal_html.conf;" in pages
    assert "include /etc/nginx/snippets/bastion_error_pages_location.conf;" in pages
    portal = _read(NGINX / "snippets" / "error_pages_portal_html.conf")
    assert _covered_codes(portal) >= {400, 403, 404, 405, 408, 413, 414, 429, 494, 495, 496,
                                       500, 502, 503, 504}
    assert 401 not in _covered_codes(portal)
    location = _read(NGINX / "snippets" / "bastion_error_pages_location.conf")
    assert "internal;" in location
    assert "alias /var/www/nginx-errors/;" in location
    assert "modsecurity off;" in location
    assert "auth_request off;" in location


def test_portal_locations_with_own_error_page_repeat_the_list():
    """A location error_page replaces the inherited list: 502 / 429 / WAF 403 / 500
    in location / were bare nginx pages."""
    text = _read(NGINX / "templates" / "vhost_sso_portal.conf.template")
    headers = re.findall(r"^    location ([^{]+)\{", text, re.MULTILINE)
    bodies = re.split(r"^    location [^{]+\{", text, flags=re.MULTILINE)[1:]
    gated = 0
    for header, body in zip(headers, bodies):
        body = body.split("\n    }\n", 1)[0]
        if "error_page 401 = @portal_oauth2_signin;" not in body:
            continue
        gated += 1
        if "/api/" in header:
            assert "bastion_error_pages_json.conf" in body, header
        else:
            assert "error_pages_portal_html.conf" in body, header
    assert gated == 6


def test_portal_error_locations_fall_back_to_static_when_app_is_down():
    text = _read(NGINX / "templates" / "vhost_sso_portal.conf.template")
    referenced = set(re.findall(r"= (/__portal_err/\d+);", _read(
        NGINX / "snippets" / "error_pages_portal_html.conf"
    )))
    assert referenced == {"/__portal_err/403", "/__portal_err/404",
                          "/__portal_err/429", "/__portal_err/503"}
    for uri in referenced:
        code = uri.rsplit("/", 1)[1]
        body = text.split(f"location = {uri} {{", 1)[1].split("\n    }\n", 1)[0]
        assert "proxy_intercept_errors off;" in body, uri
        assert "recursive_error_pages off;" in body, uri
        assert f"error_page 500 502 503 504 ={code} /__bastion_errors/{code}.html;" in body


def test_portal_unknown_host_stays_neutral_and_never_loops():
    text = _read(NGINX / "templates" / "vhost_sso_portal.conf.template")
    # error_page redirects re-run the server rewrite: exempt the static pages.
    assert '"^/(_portal_|__waf_sandbox|__bastion_errors/)"' in text
    unknown = text.split("location = /__bastion_unknown_host {", 1)[1].split("\n    }\n", 1)[0]
    assert "error_page 429 500 502 503 504 =403 /__bastion_errors/unknown-host.html;" in unknown
    assert "proxy_intercept_errors off;" in unknown


def test_portal_json_endpoints_get_json_errors():
    text = _read(NGINX / "templates" / "vhost_sso_portal.conf.template")
    for header in ("location = /health {", "location = /api/health {",
                   "location = /api/admin/breakglass/login {",
                   "location = /api/admin/breakglass/logout {"):
        body = text.split(header, 1)[1].split("\n    }\n", 1)[0]
        assert "bastion_error_pages_json.conf" in body, header


def test_oauth2_proxy_errors_are_intercepted():
    for path in (NGINX / "templates" / "nginx-portal-core-realm-oauth2.conf.template",
                 NGINX / "snippets" / "nginx-portal-core-realm-oauth2.conf"):
        assert "proxy_intercept_errors on;" in _read(path), path.name


def test_tls_edge_servers_include_error_pages():
    script = _read(NGINX / "sync-acme-tls.sh")
    assert script.count("bastion_error_pages_edge.conf") == 3  # :80, default :443, per FQDN
    edge = _read(NGINX / "snippets" / "bastion_error_pages_edge.conf")
    assert "error_page 497 =301 https://$host$request_uri;" in edge
    assert "bastion_error_pages_html.conf" in edge
    # Own location: its add_header must not drop HSTS / nosniff / XFO.
    location = edge.split("location ^~ /__bastion_errors/ {", 1)[1]
    assert "include /etc/nginx/includes/security-headers.conf;" in location
    assert "alias /var/www/nginx-errors/;" in location
    assert "internal;" in location


def test_nginx_hides_version():
    assert "server_tokens off;" in _read(NGINX / "nginx.conf")


def test_dockerfile_ships_error_pages():
    assert "COPY errors/ /var/www/nginx-errors/" in _read(NGINX / "Dockerfile")


# --- generated exports ---------------------------------------------------------


def test_subdomain_server_level_pages_and_location():
    conf = generate_subdomain_server_block(_app(), _settings())
    server = conf.split("location ", 1)[0]
    assert "proxy_intercept_errors off;" in server
    assert _covered_codes(server) == set(ERROR_PAGE_CODES)
    assert "location ^~ /__bastion_errors/ {" in conf
    assert "alias /var/www/nginx-errors/;" in conf
    # Self-contained export: no new snippet an older nginx image would lack.
    assert "bastion_error_pages" not in conf


def test_subdomain_gated_location_keeps_portal_redirect_and_adds_pages():
    blocks = _blocks(generate_subdomain_server_block(_app(), _settings()))
    body = blocks["/"]
    assert "error_page 401 403 503 = @portal_redirect_mail;" in body
    assert "/__bastion_errors/$status.html;" in body
    assert _covered_codes(body) >= {400, 413, 429, 494, 500, 502, 504}
    assert "proxy_intercept_errors off;" in body  # upstream 404/502 pages untouched


def test_subdomain_activesync_and_m2m_never_get_html():
    conf = generate_subdomain_server_block(
        _app(allow_activesync=True, m2m_bypass_paths="/dav/"), _settings()
    )
    blocks = _blocks(conf)
    for header in ("~* ^/Microsoft-Server-ActiveSync", "~* ^/(AutoDiscover|autodiscover)/",
                   "^~ /dav/"):
        body = blocks[header]
        assert ".html" not in body, header
        assert "/__bastion_errors/$status.txt;" in body, header
        assert _covered_codes(body) >= {413, 429, 500, 502, 503, 504}, header
    eas = blocks["~* ^/Microsoft-Server-ActiveSync"]
    assert "error_page 401 = @activesync_unauthorized_mail;" in eas
    assert 401 not in _covered_codes(eas.replace("error_page 401 =", ""))
    unauthorized = blocks["@activesync_unauthorized_mail"]
    assert "WWW-Authenticate" in unauthorized


def test_subdomain_fetch_401_is_json_not_nginx_html():
    blocks = _blocks(generate_subdomain_server_block(_app(), _settings()))
    redirect = blocks["@portal_redirect_mail"]
    assert "default_type application/json;" in redirect
    assert re.search(r"return 401 '\{\"code\":\"unauthorized\",[^']*\}';", redirect)
    assert "return 401;" not in redirect


def test_subdomain_crushftp_locations_get_pages():
    conf = generate_subdomain_server_block(
        _app(slug="crush", public_fqdn="transfer.example.com", robotic_driver="crushftp"),
        _settings(),
    )
    blocks = _blocks(conf)
    for header in ("/", "^~ /WebInterface/function"):
        assert _covered_codes(blocks[header]) >= {413, 500, 502, 504}, header
    # Named upstream locations inherit the server list (WAF 403, 502…).
    assert "error_page" not in blocks["@app_upstream_crush"]


def test_every_generated_location_with_error_page_covers_gateway_errors():
    conf = generate_subdomain_server_block(
        _app(allow_activesync=True, m2m_bypass_paths="/dav/\n/api/v1"), _settings()
    )
    checked = 0
    for header, body in _blocks(conf).items():
        if re.search(r"^\s*error_page ", body, re.MULTILINE):
            checked += 1
            assert {500, 502, 504} <= _covered_codes(body), header
    assert checked >= 5  # EAS, Autodiscover, 2 M2M, location /


def test_public_proxy_server_level_pages():
    conf = generate_public_proxy_server_block(_app(access_mode="public_proxy"))
    server = conf.split("location ", 1)[0]
    assert _covered_codes(server) == set(ERROR_PAGE_CODES)
    assert "location ^~ /__bastion_errors/ {" in conf
    assert conf.count("{") == conf.count("}")


def test_mta_sts_vhost_has_pages():
    from app.mail.mta_sts_service import generate_nginx_mta_sts_conf

    conf = generate_nginx_mta_sts_conf(
        enabled=True,
        mail_domain="example.com",
        mode="testing",
        mx_hosts=["mx.example.com"],
        max_age=86400,
    )
    assert "location ^~ /__bastion_errors/ {" in conf
    assert "/__bastion_errors/$status.html;" in conf
    assert conf.count("{") == conf.count("}")


def test_realm_oauth2_locations_intercept_errors(db_session):
    from app.admin.export import generate_nginx_realms_conf
    from app.models import RealmConfig
    from app.secret_crypto import encrypt_secret

    settings = Settings(  # type: ignore[call-arg]
        portal_domain="portal.example.com",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        oauth2_proxy_network_mode="docker",
    )
    db_session.add(
        RealmConfig(
            slug="clients",
            name="Clients",
            issuer_url="https://kc.example.com/realms/clients",
            client_id="portal",
            client_secret_encrypted=encrypt_secret("s", settings),
            redirect_uri="https://portal.example.com/oauth2/clients/callback",
            oauth2_proxy_port=4181,
            enabled=True,
        )
    )
    db_session.commit()
    conf = generate_nginx_realms_conf(db_session, settings)
    block = conf.split("location ^~ /oauth2/clients/ {", 1)[1].split("}", 1)[0]
    assert "proxy_intercept_errors on;" in block


def test_infra_proxy_template_has_inline_pages():
    text = _read(ROOT / "ansible/roles/bastion_app_docker/templates/nginx-infra-proxy-apps.conf.j2")
    assert "location ^~ /__bastion_errors/ {" in text
    assert "/__bastion_errors/$status.html;" in text
    assert "include /etc/nginx/snippets/bastion_error_pages" not in text


# --- FastAPI side --------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"path": "/admin/x", "accept": BROWSER_ACCEPT}, True),
        ({"path": "/auth/login", "accept": "*/*", "sec_fetch_mode": "navigate"}, True),
        ({"path": "/admin/x", "accept": "*/*", "sec_fetch_dest": "document"}, True),
        ({"path": "/api/admin/x", "accept": BROWSER_ACCEPT}, False),
        ({"path": "/internal/oauth2-auth", "accept": BROWSER_ACCEPT}, False),
        ({"path": "/Microsoft-Server-ActiveSync", "accept": BROWSER_ACCEPT}, False),
        ({"path": "/admin/x", "accept": "application/json"}, False),
        ({"path": "/admin/x", "accept": "*/*"}, False),
        ({"path": "/admin/x", "accept": BROWSER_ACCEPT, "sec_fetch_mode": "cors"}, False),
        ({"path": "/admin/x", "accept": BROWSER_ACCEPT, "x_requested_with": "XMLHttpRequest"},
         False),
    ],
)
def test_wants_html_error(kwargs, expected):
    assert wants_html_error(**kwargs) is expected


def test_cross_origin_form_post_gets_branded_403_page(client: TestClient):
    resp = client.post(
        "/auth/logout",
        headers={
            "Cookie": "bastion_session=x",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "Accept": BROWSER_ACCEPT,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 403
    assert resp.headers["content-type"].startswith("text/html")
    assert 'data-bastion-error="403"' in resp.text
    assert "Accès refusé" in resp.text


def test_cross_origin_fetch_keeps_json_403(client: TestClient):
    resp = client.post(
        "/admin/apps",
        headers={
            "Cookie": "bastion_session=x",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "cors",
            "Accept": "application/json",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 403
    assert resp.json() == {"detail": "Cross-origin request blocked"}


def test_ban_middleware_serves_page_to_browsers_json_to_api(
    client: TestClient, db_session
):
    from app.security.banning.engine import (
        RULE_RATE_LIMIT,
        clear_counters_for_tests,
        ensure_security_defaults,
    )
    from app.security.banning.service import update_ban_rules

    clear_counters_for_tests(db_session)
    ensure_security_defaults(db_session)
    update_ban_rules(
        db_session,
        rules={RULE_RATE_LIMIT: {"enabled": True, "threshold": 1, "window_seconds": 30}},
        actor="test",
    )
    base = {"X-Email": "admin@example.com", "X-Groups": "portal-admins",
            "X-Real-IP": "203.0.113.150"}
    try:
        assert client.get("/admin/security", headers=base).status_code == 200
        page = client.get("/admin/security", headers={**base, "Accept": BROWSER_ACCEPT})
        assert page.status_code == 429
        assert page.headers["content-type"].startswith("text/html")
        assert 'data-bastion-error="429"' in page.text
        assert page.headers.get("Retry-After") == "30"
        api = client.get("/admin/security", headers={**base, "Accept": "application/json"})
        assert api.status_code == 429
        assert api.json()["code"] == "too_many_requests"
    finally:
        clear_counters_for_tests(db_session)


def test_client_error_page_shows_real_status_code(client: TestClient):
    """405 / 413 … reuse errors/400.html but must not display « 400 »."""
    resp = client.put("/errors/403", headers={"Accept": BROWSER_ACCEPT}, follow_redirects=False)
    assert resp.status_code == 405
    assert resp.headers["content-type"].startswith("text/html")
    assert '<div class="error-code error-code--warn">405</div>' in resp.text
