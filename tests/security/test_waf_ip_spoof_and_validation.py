"""WAF hardening: edge client-IP overwrite, exclusion / ACL validation."""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

import pytest

from app.bastion.nginx_waf_export import (
    is_excludable_rule_id,
    list_promoted_deny_ips,
    render_exclusions_generated,
    render_ip_allow_conf,
    render_ip_deny_conf,
)
from app.ip_cidrs import canonical_ip_or_network, waf_acl_entry_problem
from app.models import SecurityAllowlistEntry, SecurityBan, WafExclusion, utcnow
from app.security.banning.service import add_allowlist_entry, apply_manual_ban
from app.security.waf.service import SCOPE_RULE, _validate_exclusion_fields

ROOT = Path(__file__).resolve().parents[2]

# Line separators str.splitlines() honours — each one would end a generated rule.
_LINE_BREAKS = ["\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x85", "\u2028", "\u2029"]


# --- :443 edge must own CF-Connecting-IP -------------------------------------


def test_every_edge_proxy_block_overwrites_cf_connecting_ip():
    """:8080 trusts CF-Connecting-IP from 127.0.0.0/8 (the :443 hop).

    Each ``proxy_pass http://127.0.0.1:8080`` body must overwrite it with the
    client resolved on :443, else a direct-to-origin client chooses its own
    ``$remote_addr`` on :8080 (allow 10/8 on /breakglass, limit_req, bans).
    """
    text = (ROOT / "docker/nginx/sync-acme-tls.sh").read_text(encoding="utf-8")
    blocks = text.split("proxy_pass http://127.0.0.1:8080;")[1:]
    assert len(blocks) >= 2  # default_server + per-FQDN PROXY_EOF body
    for body in blocks:
        head = body.split("}", 1)[0].split("PROXY_EOF", 1)[0]
        assert re.search(
            r"proxy_set_header CF-Connecting-IP \\?\$remote_addr;", head
        ), head
    nginx_conf = (ROOT / "docker/nginx/nginx.conf").read_text(encoding="utf-8")
    assert "set_real_ip_from 127.0.0.0/8;" in nginx_conf
    assert "real_ip_header CF-Connecting-IP;" in nginx_conf


# --- exclusions: no directive injection, no disguised global disable ---------


def _validate(**overrides):
    kwargs = {
        "reason": "FP",
        "crs_rule_id": 942100,
        "uri_pattern": "/api/x",
        "host": None,
        "scope_kind": SCOPE_RULE,
        "target_name": None,
        "uri_match": "exact",
        "allow_global": False,
    }
    kwargs.update(overrides)
    return _validate_exclusion_fields(**kwargs)


@pytest.mark.parametrize("sep", _LINE_BREAKS)
@pytest.mark.parametrize("uri_match", ["exact", "prefix", "regex"])
def test_exclusion_uri_with_line_break_is_refused(sep, uri_match):
    with pytest.raises(ValueError, match="URI refusée"):
        _validate(uri_pattern=f"/x{sep}SecRuleEngine Off", uri_match=uri_match)


@pytest.mark.parametrize(
    "host",
    [
        "app.example.com\nInclude /etc/passwd",
        "app.example.com\u2028SecRuleEngine Off",
        "app example.com",
        'app.example.com"',
        "app_example.com",
        "-app.example.com",
    ],
)
def test_exclusion_invalid_host_is_refused(host):
    with pytest.raises(ValueError, match="host invalide"):
        _validate(host=host)


def test_exclusion_valid_host_and_port_accepted():
    out = _validate(host="App.Example.com:8443")
    assert out[2] == "app.example.com:8443"


@pytest.mark.parametrize(
    "rule_id",
    [949110, 949111, 959100, 980170, 901001, 900990, 200002, 1000900110, 0, -1, 1],
)
def test_exclusion_non_detection_rule_ids_are_refused(rule_id):
    assert not is_excludable_rule_id(rule_id)
    with pytest.raises(ValueError, match="non excluable"):
        _validate(crs_rule_id=rule_id)


@pytest.mark.parametrize("rule_id", [911100, 920350, 942100, 944130, 951110, 100096180])
def test_exclusion_detection_rule_ids_are_accepted(rule_id):
    assert is_excludable_rule_id(rule_id)
    assert _validate(crs_rule_id=rule_id)[0] == "FP"


def _directive_lines(text: str) -> list[str]:
    return [ln for ln in text.split("\n") if ln.strip() and not ln.lstrip().startswith("#")]


@pytest.mark.parametrize("sep", _LINE_BREAKS)
def test_render_skips_legacy_rows_with_line_breaks(sep):
    """Rows stored before validation must never reach the shared rules file."""
    rows = [
        WafExclusion(
            id=10,
            crs_rule_id=942100,
            reason="legacy",
            uri_pattern=f"/x{sep}Include /etc/nginx/evil.conf",
            active=True,
            scope_kind="rule",
            uri_match="exact",
        ),
        WafExclusion(
            id=11,
            crs_rule_id=942100,
            reason="legacy host",
            host=f"app.example.com{sep}SecRuleRemoveById 900000-999999",
            uri_pattern="/x",
            active=True,
            scope_kind="rule",
            uri_match="exact",
        ),
    ]
    out = render_exclusions_generated(rows)
    assert _directive_lines(out) == []
    assert "skip exclusion id=10" in out
    assert "skip exclusion id=11" in out


def test_render_skips_blocking_rule_exclusion():
    row = WafExclusion(
        id=12,
        crs_rule_id=949110,
        reason="disable blocking",
        host=None,
        uri_pattern=None,
        active=True,
        scope_kind="rule",
    )
    out = render_exclusions_generated([row])
    assert "SecRuleRemoveById 949110" not in out
    assert _directive_lines(out) == []


# --- nginx allow / deny entries ----------------------------------------------


@pytest.mark.parametrize("value", ["all", "unknown", "", "0.0.0.0/0", "::/0", "1.0.0.0/7", "10.1.2.3/33"])
@pytest.mark.parametrize("deny", [True, False])
def test_acl_refuses_non_addresses_and_huge_ranges(value, deny):
    assert waf_acl_entry_problem(value, deny=deny) is not None


@pytest.mark.parametrize("value", ["127.0.0.1", "10.5.0.3", "10.0.0.0/8", "172.17.0.1", "::1"])
def test_acl_deny_refuses_infrastructure_hops(value):
    assert waf_acl_entry_problem(value, deny=True) is not None
    assert waf_acl_entry_problem(value, deny=False) is None


@pytest.mark.parametrize(
    "raw,canonical",
    [
        ("203.0.113.7", "203.0.113.7"),
        ("203.0.113.7/32", "203.0.113.7"),
        ("192.168.1.5/24", "192.168.1.0/24"),
        ("2001:DB8::1", "2001:db8::1"),
    ],
)
def test_acl_accepts_and_canonicalizes(raw, canonical):
    assert waf_acl_entry_problem(raw, deny=True) is None
    assert canonical_ip_or_network(raw) == canonical


def test_render_deny_never_emits_unsafe_targets():
    out = render_ip_deny_conf(
        ["all", "0.0.0.0/0", "127.0.0.1", "10.5.0.0/16", "203.0.113.7", "x\nallow all"],
        min_occurrences=3,
    )
    assert _directive_lines(out) == ["deny 203.0.113.7;"]


def test_render_allow_never_emits_unsafe_targets():
    out = render_ip_allow_conf(["all", "0.0.0.0/0", "::/0", "198.51.100.0/24"])
    assert _directive_lines(out) == ["allow 198.51.100.0/24;"]


@pytest.mark.parametrize("value", ["all", "0.0.0.0/0", "not-an-ip"])
def test_allowlist_entry_refuses_bypass_values(db_session, value):
    with pytest.raises(ValueError, match="IP refusée"):
        add_allowlist_entry(
            db_session, entry_type="ip", value=value, comment="x", actor="test"
        )
    assert db_session.query(SecurityAllowlistEntry).count() == 0


def test_allowlist_entry_stores_canonical_network(db_session):
    row = add_allowlist_entry(
        db_session, entry_type="ip", value=" 192.168.10.7/24 ", comment="vpn", actor="test"
    )
    assert row.value == "192.168.10.0/24"


@pytest.mark.parametrize("value", ["all", "0.0.0.0/0", "127.0.0.1", "10.5.0.9"])
def test_manual_ip_ban_refuses_unsafe_targets(db_session, value):
    with pytest.raises(ValueError, match="IP refusée"):
        apply_manual_ban(
            db_session,
            target_type="ip",
            target=value,
            reason="x",
            permanent=True,
            ban_minutes=60,
            confirm_permanent=True,
            actor="test",
        )
    assert db_session.query(SecurityBan).count() == 0


def test_expired_unlifted_temp_ban_is_not_promoted(db_session):
    now = utcnow()
    for target, expires in (
        ("203.0.113.20", now - timedelta(minutes=5)),  # expired, never lifted
        ("203.0.113.21", now + timedelta(hours=1)),  # still active
    ):
        for _ in range(3):
            db_session.add(
                SecurityBan(
                    target_type="ip",
                    target=target,
                    reason="repeat",
                    permanent=False,
                    expires_at=expires,
                    created_by="test",
                )
            )
    db_session.add(
        SecurityBan(
            target_type="ip",
            target="203.0.113.22",
            reason="perm",
            permanent=True,
            created_by="test",
        )
    )
    db_session.commit()

    promoted = list_promoted_deny_ips(db_session, min_occurrences=3)
    assert "203.0.113.20" not in promoted
    assert "203.0.113.21" in promoted
    assert "203.0.113.22" in promoted
