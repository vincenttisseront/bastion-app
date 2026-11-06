"""CRS parsed once in http{} — never per vhost (bastion-nginx memcg OOM on reload).

ModSecurity-nginx parses a rules file for every server{} that declares it. With
the CRS reachable from each vhost, ~25 vhosts held ~25 CRS copies (~900 MB) and
every ``nginx -t`` / reload added another full copy. The CRS now lives in
``modsecurity/main-common.conf``, loaded once from nginx.conf http{}; per-server
files may only set SecRuleEngine, and inline rules must not reuse a shared id
(ModSecurity rejects duplicated ids at merge time → ``nginx -t`` fails).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.bastion.nginx_public_proxy_export import generate_public_proxy_server_block
from app.bastion.nginx_subdomain_export import generate_subdomain_server_block
from app.bastion.nginx_waf_export import MODE_DETECTION, MODE_OFF, MODE_ON
from app.bastion.waf_reactivation import render_engine_mode_line
from app.models import App
from app.sso_settings import Settings

ROOT = Path(__file__).resolve().parents[2]
NGINX = ROOT / "docker" / "nginx"
MODSEC = NGINX / "modsecurity"
COMMON = "/etc/nginx/modsecurity/main-common.conf"
FAMILY_FILES = {
    "/etc/nginx/modsecurity/main-portal.conf",
    "/etc/nginx/modsecurity/main-subdomain.conf",
    "/etc/nginx/modsecurity/main-public.conf",
}

_RULES_FILE_RE = re.compile(r"^\s*modsecurity_rules_file\s+(\S+?)\s*;", re.MULTILINE)
_INLINE_RULES_RE = re.compile(r"modsecurity_rules\s+'(.*?)'\s*;", re.DOTALL)
_RULE_ID_RE = re.compile(r"\bid:(\d+)")
_ENGINE_LINE_RE = re.compile(r"^SecRuleEngine\s+(Off|On|DetectionOnly)$")


def _live_lines(text: str) -> list[str]:
    return [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]


def _local(docker_path: str) -> Path:
    for prefix, base in (
        ("/etc/nginx/modsecurity/", MODSEC),
        ("/etc/nginx/includes/", NGINX / "includes"),
    ):
        if docker_path.startswith(prefix):
            return base / docker_path[len(prefix) :]
    raise AssertionError(f"Include outside the repo nginx tree: {docker_path}")


def _resolved_live_lines(docker_path: str, seen: set[str] | None = None) -> list[str]:
    """Live lines of a ModSecurity file with repo-local Includes expanded."""
    seen = set() if seen is None else seen
    assert docker_path not in seen, f"Include loop through {docker_path}"
    seen.add(docker_path)
    out: list[str] = []
    for ln in _live_lines(_local(docker_path).read_text(encoding="utf-8")):
        target = ln.split(None, 1)[1] if ln.startswith("Include ") else ""
        if target and not target.startswith("/etc/modsecurity.d/"):
            out.extend(_resolved_live_lines(target, seen))
        else:
            out.append(ln)
    return out


def _settings() -> Settings:
    return Settings(portal_domain="portal.example.com", vault_portal_internal_token="t")


def _generated_vhosts() -> dict[str, str]:
    """One vhost per export flavour that wires ModSecurity differently."""
    sub = {
        "subdomain": {},
        "subdomain_crushftp": {"robotic_driver": "crushftp"},
        "subdomain_activesync": {"allow_activesync": True},
        "subdomain_m2m": {
            "m2m_bypass_paths": "/api/v1/\n/hooks/",
            "m2m_bypass_long_timeout": True,
        },
    }
    out: dict[str, str] = {}
    for i, (name, extra) in enumerate(sub.items()):
        app = App(
            slug=f"app{i}",
            label=name,
            upstream_url=f"https://10.0.0.{10 + i}/",
            access_mode="subdomain_proxy",
            public_fqdn=f"app{i}.example.com",
            enabled=True,
            **extra,
        )
        out[name] = generate_subdomain_server_block(app, _settings())
    public = App(
        slug="pub0",
        label="public",
        upstream_url="https://10.0.1.10/",
        access_mode="public_proxy",
        public_fqdn="pub0.example.com",
        enabled=True,
    )
    out["public"] = generate_public_proxy_server_block(public)
    return out


def _server_level_sources() -> dict[str, str]:
    """Every nginx file rendered inside a server{} (image side)."""
    files = [
        *sorted((NGINX / "snippets").glob("*.conf")),
        *sorted((NGINX / "templates").glob("*.template")),
        *sorted((NGINX / "conf.d").glob("*.conf")),
        *sorted((NGINX / "includes").glob("*.conf")),
    ]
    return {p.relative_to(NGINX).as_posix(): p.read_text(encoding="utf-8") for p in files}


def test_nginx_conf_parses_shared_rules_once_in_http():
    conf = (NGINX / "nginx.conf").read_text(encoding="utf-8")
    http_body = conf.split("http {", 1)[1]
    assert _RULES_FILE_RE.findall("\n".join(_live_lines(http_body))) == [COMMON]
    common = _resolved_live_lines(COMMON)
    assert "Include /etc/modsecurity.d/owasp-crs/rules/*.conf" in common
    # Default for a server{} with the connector on but no family overlay.
    assert common[0] == "SecRuleEngine Off"


@pytest.mark.parametrize("family_file", sorted(FAMILY_FILES))
def test_family_overlay_only_sets_engine_mode(family_file: str):
    lines = _resolved_live_lines(family_file)
    assert lines, family_file
    for ln in lines:
        assert _ENGINE_LINE_RE.match(ln), f"{family_file}: per-server line {ln!r}"


def test_engine_overlays_rendered_by_app_only_set_engine_mode():
    from app.bastion.nginx_waf_export import render_engine_mode_generated
    from app.models import WafProfile

    for mode in (MODE_OFF, MODE_DETECTION, MODE_ON):
        for text in (
            render_engine_mode_line(mode),
            render_engine_mode_generated(WafProfile(name="p", mode=mode)),
        ):
            assert all(_ENGINE_LINE_RE.match(ln) for ln in _live_lines(text)), text


def test_server_level_files_never_load_the_shared_rules():
    for name, text in _server_level_sources().items():
        for target in _RULES_FILE_RE.findall("\n".join(_live_lines(text))):
            assert target in FAMILY_FILES, f"{name}: modsecurity_rules_file {target}"


def test_generated_vhosts_have_no_modsecurity_rules_file():
    for name, block in _generated_vhosts().items():
        assert "modsecurity_rules_file" not in block, name
        family = "public" if name == "public" else "subdomain"
        assert block.count(f"include /etc/nginx/snippets/modsecurity-{family}.conf;") == 1


def test_inline_rule_ids_do_not_collide_with_shared_chain():
    shared_ids: set[str] = set()
    for path in [
        MODSEC / "modsecurity.conf",
        MODSEC / "crs-setup.conf",
        *sorted(MODSEC.glob("bastion-*.conf")),
        *sorted((MODSEC / "generated").glob("*.conf")),
        NGINX / "includes" / "waf-basic.conf",
    ]:
        shared_ids.update(
            _RULE_ID_RE.findall("\n".join(_live_lines(path.read_text(encoding="utf-8"))))
        )
    assert "200000" in shared_ids  # sanity: the parser sees modsecurity.conf ids
    sources = dict(_generated_vhosts())
    sources.update(_server_level_sources())
    inline_seen = 0
    for name, text in sources.items():
        for rules in _INLINE_RULES_RE.findall("\n".join(_live_lines(text))):
            inline_seen += 1
            clash = set(_RULE_ID_RE.findall(rules)) & shared_ids
            assert not clash, f"{name}: inline rule ids {sorted(clash)} also in http{{}} chain"
    assert inline_seen >= 2  # CrushFTP location + portal sandbox
