"""ModSecurity CRS — docker nginx wiring."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_docker_portal_keeps_modsecurity_wiring_but_off():
    text = (ROOT / "docker/nginx/templates/vhost_sso_portal.conf.template").read_text(
        encoding="utf-8"
    )
    # Server-level switch is an include (default off); locations keep explicit off.
    assert "include /etc/nginx/includes/modsecurity-portal-switch.conf;" in text
    # Server switch stays off by default; only the admin sandbox location may set on.
    on_lines = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#") and "modsecurity on;" in ln
    ]
    assert on_lines == ["modsecurity on;"]
    assert "location ^~ /__waf_sandbox/" in text
    sandbox = text.split("location ^~ /__waf_sandbox/ {", 1)[1].split(
        "location = /health {", 1
    )[0]
    assert "allow 10.0.0.0/8;" in sandbox
    assert "allow 172.16.0.0/12;" in sandbox
    assert "deny all;" in sandbox
    assert "SecRuleEngine DetectionOnly" in sandbox
    # Sandbox must inherit server-level rules_file (re-include → duplicate id:200000).
    sandbox_live = "\n".join(
        ln for ln in sandbox.splitlines() if ln.strip() and not ln.strip().startswith("#")
    )
    assert "modsecurity_rules_file" not in sandbox_live
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
    favicon = text.split("location = /favicon.ico {", 1)[1].split("}", 1)[0]
    assert "modsecurity off;" in favicon
    static = text.split("location ^~ /static/ {", 1)[1].split("}", 1)[0]
    assert "modsecurity off;" in static
    admin = text.split("location ^~ /admin {", 1)[1].split("location = /dashboard", 1)[
        0
    ]
    assert "modsecurity off;" in admin
    dashboard = text.split("location = /dashboard {", 1)[1].split(
        "location = /api/internal/session-cookie-hop", 1
    )[0]
    assert "modsecurity off;" in dashboard
    assert "auth_request /portal_auth_check;" in dashboard
    modsec_ok = text.split("location = /_portal_modsec_ok {", 1)[1].split(
        "location @portal_modsec_ok_fail", 1
    )[0]
    assert "modsecurity off;" not in modsec_ok
    assert "return 200" in modsec_ok
    nginx_ok = text.split("location = /_portal_nginx_ok {", 1)[1].split("}", 1)[0]
    assert "modsecurity off;" in nginx_ok
    api_admin = text.split("location ^~ /api/admin {", 1)[1].split(
        "location ^~ /admin {", 1
    )[0]
    assert "modsecurity off;" in api_admin
    api_apps = text.split("location ^~ /api/apps/ {", 1)[1].split(
        "location ^~ /api/admin {", 1
    )[0]
    assert "modsecurity off;" in api_apps
    assert "if ($uri ~ ^/(admin|dashboard))" in text


def test_main_portal_includes_engine_mode_generated_for_ihm_arm():
    text = (ROOT / "docker/nginx/modsecurity/main-portal.conf").read_text(encoding="utf-8")
    assert (
        "Include /etc/nginx/modsecurity/generated/engine-mode-generated.conf" in text
    )
    sub = (ROOT / "docker/nginx/modsecurity/main-subdomain.conf").read_text(encoding="utf-8")
    assert (
        "Include /etc/nginx/modsecurity/generated/engine-subdomain-mode-generated.conf"
        in sub
    )
    public = (ROOT / "docker/nginx/modsecurity/main-public.conf").read_text(encoding="utf-8")
    assert (
        "Include /etc/nginx/modsecurity/generated/engine-mode-generated.conf"
        not in public
    )
    assert "Include /etc/nginx/modsecurity/generated/engine-public-mode-generated.conf" not in public
    assert "no public_armed path yet" in public
    assert "INTENTIONAL" in public

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


def test_modsecurity_audit_engine_relevant_only_for_waf_bilan():
    """Audit must hit the shared volume so the WAF bilan aggregator can chart CRS hits."""
    text = (ROOT / "docker/nginx/modsecurity/modsecurity.conf").read_text(
        encoding="utf-8"
    )
    assert "SecResponseBodyAccess Off" in text
    assert "SecRequestBodyAccess On" in text
    live = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert not any(ln.startswith("SecRuleEngine") for ln in live)
    assert any(ln == "SecAuditEngine RelevantOnly" for ln in live)
    assert any(
        ln == "SecAuditLog /var/log/nginx/apps/modsec_audit.log" for ln in live
    )
    assert not any(ln == "SecAuditEngine Off" for ln in live)
    assert not any(ln.endswith("/dev/null") and "SecAuditLog" in ln for ln in live)


def test_crs_setup_declares_crs_setup_version_for_blocking_mode():
    """CRS 901001 returns HTTP 500 in On mode when crs_setup_version is missing."""
    text = (ROOT / "docker/nginx/modsecurity/crs-setup.conf").read_text(encoding="utf-8")
    assert "crs_setup_version=4280" in text
    assert 'SecDefaultAction "phase:1,log,auditlog,pass"' in text


def test_modsecurity_main_includes_generated_overlays_not_replacing_static():
    for name in ("main-portal.conf", "main-subdomain.conf", "main-public.conf"):
        text = (ROOT / "docker/nginx/modsecurity" / name).read_text(encoding="utf-8")
        assert "Include /etc/nginx/modsecurity/crs-setup.conf" in text
        assert (
            "Include /etc/nginx/modsecurity/generated/crs-setup-generated.conf"
            in text
        )
        assert (
            "Include /etc/nginx/modsecurity/generated/bastion-virtual-patches-enabled.conf"
            in text
        )
        setup_idx = text.index("Include /etc/nginx/modsecurity/crs-setup.conf")
        gen_idx = text.index(
            "Include /etc/nginx/modsecurity/generated/crs-setup-generated.conf"
        )
        vp_idx = text.index(
            "Include /etc/nginx/modsecurity/generated/bastion-virtual-patches-enabled.conf"
        )
        rules_idx = text.index("Include /etc/modsecurity.d/owasp-crs/rules/*.conf")
        assert setup_idx < gen_idx < vp_idx < rules_idx
        assert "Include /etc/nginx/includes/waf-basic.conf" in text
        assert (
            "Include /etc/nginx/modsecurity/generated/bastion-exclusions-generated.conf"
            in text
        )
        # Portal only: engine-mode-generated Included (gated by waf-engine-arm.json in sync).
        if name == "main-portal.conf":
            assert (
                "Include /etc/nginx/modsecurity/generated/engine-mode-generated.conf"
                in text
            )
        else:
            assert (
                "Include /etc/nginx/modsecurity/generated/engine-mode-generated.conf"
                not in text
            )


def test_bastion_virtual_patches_syntax_smoke():
    """Static guardrails: valid Include target, no CRS-clash ids, no bare % macros."""
    path = ROOT / "docker/nginx/modsecurity/bastion-virtual-patches.conf"
    text = path.read_text(encoding="utf-8")
    live = [
        ln
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert live, "expected at least one live SecRule"
    blob = "\n".join(live)
    assert "%" not in blob
    assert "id:901" not in blob
    for rule_id in (
        "100096180",
        "100096181",
        "100096182",
        "100096183",
        "100096184",
    ):
        assert f"id:{rule_id}," in blob
    assert "PHPSESSID" in blob
    assert "PHP_SESSION_UPLOAD_PROGRESS" in blob
    assert "php2shell" in blob
    assert "CVE-2026-109618" in blob
    assert "CVE-2026-109619" in blob
    # Chains must not leave a dangling SecRule without a following rule line.
    for i, ln in enumerate(live):
        if ",chain\"" in ln or ln.rstrip().endswith(",chain"):
            assert i + 1 < len(live), f"dangling chain at line: {ln}"
            assert live[i + 1].lstrip().startswith("SecRule "), (
                f"chain follower must be SecRule: {live[i + 1]}"
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


def test_eas_locations_disable_modsecurity_in_subdomain_export():
    from app.bastion.nginx_subdomain_export import generate_subdomain_server_block
    from app.models import App
    from app.sso_settings import Settings

    app = App(
        slug="grommunio",
        label="Mail",
        upstream_url="https://10.0.0.9/",
        access_mode="subdomain_proxy",
        public_fqdn="webmail.example.fr",
        allow_activesync=True,
        enabled=True,
    )
    block = generate_subdomain_server_block(
        app,
        Settings(
            portal_domain="portal.example.com",
            vault_portal_internal_token="test-secret",
        ),
    )
    eas = block.split("location ~* ^/Microsoft-Server-ActiveSync {", 1)[1].split(
        "}", 1
    )[0]
    assert "modsecurity off;" in eas
    ad = block.split("location ~* ^/(AutoDiscover|autodiscover)/ {", 1)[1].split(
        "}", 1
    )[0]
    assert "modsecurity off;" in ad


def test_family_snippets_use_exportable_switch():
    for family, switch in (
        ("modsecurity-subdomain.conf", "modsecurity-subdomain-switch.conf"),
        ("modsecurity-public.conf", "modsecurity-public-switch.conf"),
    ):
        text = (ROOT / "docker/nginx/snippets" / family).read_text(encoding="utf-8")
        assert f"include /etc/nginx/includes/{switch};" in text
        assert "modsecurity_rules_file" in text
        live = [
            ln.strip()
            for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        assert "modsecurity on;" not in live


def test_family_switch_includes_default_off():
    for name in ("modsecurity-subdomain-switch.conf", "modsecurity-public-switch.conf"):
        text = (ROOT / "docker/nginx/includes" / name).read_text(encoding="utf-8")
        live = [
            ln.strip()
            for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        assert live == ["modsecurity off;"]
