"""Portal Mes liens — pin managed-domain public_proxy apps on profile."""

from __future__ import annotations

import pytest

from app.models import App, PortalSettings, UserPublicAppLink
from app.sso_settings import Settings
from app.web.portal_public_links import (
    PublicLinkError,
    add_public_link,
    is_linkable_public_proxy,
    list_eligible_public_proxy_apps,
    list_linked_app_ids,
    profile_public_link_tiles,
    remove_public_link,
)


def _settings(**kwargs) -> Settings:
    base = {
        "portal_domain": "portal.example.org",
        "sso_portal_default_realm_slug": "default",
        "vault_portal_internal_token": "test-secret",
    }
    base.update(kwargs)
    return Settings(**base)  # type: ignore[call-arg]


def _seed_portal_domain(db_session, domain: str = "portal.example.org") -> None:
    row = db_session.query(PortalSettings).filter_by(id=1).first()
    if row is None:
        row = PortalSettings(id=1, portal_domain=domain)
        db_session.add(row)
    else:
        row.portal_domain = domain
    db_session.commit()


def _make_public_proxy(
    db_session,
    *,
    slug: str,
    fqdn: str,
    enabled: bool = True,
) -> App:
    app = App(
        slug=slug,
        label=slug.title(),
        upstream_url=f"http://10.0.0.10/{slug}/",
        access_mode="public_proxy",
        public_fqdn=fqdn,
        enabled=enabled,
    )
    db_session.add(app)
    db_session.commit()
    return app


def test_is_linkable_requires_managed_public_proxy():
    from app.bastion.pending_host_service import managed_domain_suffixes

    suffixes = managed_domain_suffixes(portal_domain="portal.example.org")
    ok = App(
        slug="zabbix",
        label="Zabbix",
        upstream_url="http://10.0.0.10/",
        access_mode="public_proxy",
        public_fqdn="zabbix.example.org",
        enabled=True,
    )
    noise = App(
        slug="noise",
        label="Noise",
        upstream_url="http://10.0.0.11/",
        access_mode="public_proxy",
        public_fqdn="www.other.example.net",
        enabled=True,
    )
    sso = App(
        slug="wiki",
        label="Wiki",
        upstream_url="https://wiki.example.org/",
        access_mode="sso_gate",
        enabled=True,
    )
    assert is_linkable_public_proxy(ok, suffixes=suffixes)
    assert not is_linkable_public_proxy(noise, suffixes=suffixes)
    assert not is_linkable_public_proxy(sso, suffixes=suffixes)


def test_list_eligible_filters_unmanaged_and_disabled(db_session):
    _seed_portal_domain(db_session)
    settings = _settings()
    zabbix = _make_public_proxy(
        db_session, slug="zabbix", fqdn="zabbix.example.org"
    )
    _make_public_proxy(db_session, slug="noise", fqdn="www.other.example.net")
    _make_public_proxy(
        db_session, slug="off", fqdn="off.example.org", enabled=False
    )

    eligible = list_eligible_public_proxy_apps(db_session, settings)
    assert [a.slug for a in eligible] == ["zabbix"]
    assert eligible[0].id == zabbix.id


def test_add_remove_public_link(db_session):
    _seed_portal_domain(db_session)
    settings = _settings()
    app = _make_public_proxy(db_session, slug="zabbix", fqdn="zabbix.example.org")

    assert list_linked_app_ids(db_session, "kc-alice") == []
    assert add_public_link(
        db_session,
        settings,
        keycloak_user_id="kc-alice",
        application_id=app.id,
        actor="alice@example.com",
    )
    assert list_linked_app_ids(db_session, "kc-alice") == [app.id]
    assert (
        add_public_link(
            db_session,
            settings,
            keycloak_user_id="kc-alice",
            application_id=app.id,
            actor="alice@example.com",
        )
        is False
    )
    assert remove_public_link(
        db_session,
        keycloak_user_id="kc-alice",
        application_id=app.id,
        actor="alice@example.com",
    )
    assert list_linked_app_ids(db_session, "kc-alice") == []
    assert db_session.query(UserPublicAppLink).count() == 0


def test_add_rejects_unmanaged_fqdn(db_session):
    _seed_portal_domain(db_session)
    settings = _settings()
    noise = _make_public_proxy(
        db_session, slug="noise", fqdn="www.other.example.net"
    )
    with pytest.raises(PublicLinkError):
        add_public_link(
            db_session,
            settings,
            keycloak_user_id="kc-alice",
            application_id=noise.id,
            actor="alice@example.com",
        )


def test_profile_tiles_split_linked_and_available(db_session):
    _seed_portal_domain(db_session)
    settings = _settings()
    zabbix = _make_public_proxy(
        db_session, slug="zabbix", fqdn="zabbix.example.org"
    )
    grafana = _make_public_proxy(
        db_session, slug="grafana", fqdn="grafana.example.org"
    )
    add_public_link(
        db_session,
        settings,
        keycloak_user_id="kc-alice",
        application_id=zabbix.id,
        actor="alice@example.com",
    )

    linked, available = profile_public_link_tiles(
        db_session, settings, keycloak_user_id="kc-alice"
    )
    assert [t["slug"] for t in linked] == ["zabbix"]
    assert linked[0]["launch_url"].startswith("https://zabbix.example.org")
    assert [t["slug"] for t in available] == ["grafana"]
    assert available[0]["id"] == grafana.id


def test_audit_catalog_has_public_link_events():
    from app.audit.event_catalog import resolve_event

    added = resolve_event(action="portal.public_link_add")
    removed = resolve_event(action="portal.public_link_remove")
    assert added.code == "BST-ADM-0009"
    assert removed.code == "BST-ADM-0010"
