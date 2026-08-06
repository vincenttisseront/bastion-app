"""ModSecurity CRS — docker nginx wiring (emergency Off 2026-08-06)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_docker_portal_keeps_modsecurity_wiring_but_off():
    text = (ROOT / "docker/nginx/templates/vhost_sso_portal.conf.template").read_text(
        encoding="utf-8"
    )
    # Emergency Off — connector still wired for a safe re-enable later.
    assert "modsecurity off;" in text
    assert "modsecurity on;" not in [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert (
        "modsecurity_rules_file /etc/nginx/modsecurity/main-portal.conf;" in text
    )
    # Former nginx include of waf-basic would break if that file holds SecRule syntax.
    assert "include /etc/nginx/includes/waf-basic.conf;" not in text
    health = text.split("location = /health {", 1)[1].split("}", 1)[0]
    assert "modsecurity off;" in health
    hop = text.split("location = /api/internal/session-cookie-hop {", 1)[1].split(
        "}", 1
    )[0]
    assert "modsecurity off;" in hop


def test_docker_nginx_loads_modsecurity_module_after_real_ip_order():
    conf = (ROOT / "docker/nginx/nginx.conf").read_text(encoding="utf-8")
    assert "load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;" in conf
    # Activation must not be a live directive in http{} — only per-server in conf.d.
    http_body = conf.split("http {", 1)[1]
    live = [
        ln
        for ln in http_body.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    live_blob = "\n".join(live)
    assert "modsecurity on;" not in live_blob
    assert "modsecurity_rules_file" not in live_blob
    assert "set_real_ip_from" in conf
    assert conf.index("set_real_ip_from") < conf.index("include /etc/nginx/conf.d/*.conf;")


def test_modsecurity_engine_files_off_emergency():
    for name in ("engine-portal.conf", "engine-subdomain.conf", "engine-public.conf"):
        text = (ROOT / "docker/nginx/modsecurity" / name).read_text(encoding="utf-8")
        live = [
            ln.strip()
            for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        assert live == ["SecRuleEngine Off"]


def test_modsecurity_audit_engine_off_emergency():
    text = (ROOT / "docker/nginx/modsecurity/modsecurity.conf").read_text(
        encoding="utf-8"
    )
    assert "SecAuditEngine Off" in text
    assert "SecResponseBodyAccess Off" in text
    assert "SecRequestBodyAccess On" in text
    live = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert not any(ln.startswith("SecRuleEngine") for ln in live)
    assert any(ln == "SecAuditEngine Off" for ln in live)


def test_modsecurity_main_includes_generated_overlays_not_replacing_static():
    for name in ("main-portal.conf", "main-subdomain.conf", "main-public.conf"):
        text = (ROOT / "docker/nginx/modsecurity" / name).read_text(encoding="utf-8")
        assert "Include /etc/nginx/modsecurity/crs-setup.conf" in text
        # Hotfix: do not load crs-setup-generated (stale id:901110 → HTTP 500).
        assert (
            "Include /etc/nginx/modsecurity/generated/crs-setup-generated.conf"
            not in text
        )
        # Emergency: do not load engine-mode-generated (DB mode=on forced On → 500).
        assert (
            "Include /etc/nginx/modsecurity/generated/engine-mode-generated.conf"
            not in text
        )
        assert "Include /etc/nginx/includes/waf-basic.conf" in text
        assert (
            "Include /etc/nginx/modsecurity/generated/bastion-exclusions-generated.conf"
            in text
        )


def test_auth_snippets_disable_modsecurity():
    sub = (ROOT / "docker/nginx/snippets/subdomain_auth_common.conf").read_text(
        encoding="utf-8"
    )
    assert "modsecurity off;" in sub.split("location = /internal/subdomain-auth", 1)[1][
        :200
    ]
    eas = (ROOT / "docker/nginx/snippets/activesync_auth_common.conf").read_text(
        encoding="utf-8"
    )
    assert "modsecurity off;" in eas.split("location = /internal/activesync-auth", 1)[
        1
    ][:200]


def test_family_snippets_modsecurity_off_emergency():
    for name in ("modsecurity-subdomain.conf", "modsecurity-public.conf"):
        text = (ROOT / "docker/nginx/snippets" / name).read_text(encoding="utf-8")
        live = [
            ln.strip()
            for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        assert "modsecurity off;" in live
        assert "modsecurity on;" not in live
