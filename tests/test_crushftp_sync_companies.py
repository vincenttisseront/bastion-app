"""CrushFTP company-folder listing / société sync helpers."""

from unittest.mock import patch

import pytest
import respx
from httpx import Response

from app.bastion.drivers.crushftp import (
    CrushFTPProvisioningDriver,
    normalize_crushftp_listing_path,
    parse_crushftp_directory_names,
)
from app.models import App, RBACGroup, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def test_parse_crushftp_directory_names_jsonobj():
    body = (
        '[{"name":"SDIS74","type":"DIR"},'
        '{"name":"readme.txt","type":"FILE"},'
        '{"name":"SDIS999","type":"DIR"}]'
    )
    assert parse_crushftp_directory_names(body) == ["SDIS74", "SDIS999"]


def test_parse_crushftp_directory_names_xml():
    body = """
    <listing type="vector">
      <listing_subitem type="properties">
        <name>SDIS74</name><type>DIR</type>
      </listing_subitem>
      <listing_subitem type="properties">
        <name>note.txt</name><type>FILE</type>
      </listing_subitem>
    </listing>
    """
    assert parse_crushftp_directory_names(body) == ["SDIS74"]


def test_normalize_crushftp_listing_path():
    assert normalize_crushftp_listing_path("crush_data/AR-SYSTEMS") == "/crush_data/AR-SYSTEMS/"
    assert normalize_crushftp_listing_path("/crush_data/AR-SYSTEMS/") == "/crush_data/AR-SYSTEMS/"


@pytest.mark.asyncio
@respx.mock
async def test_list_company_folders_calls_get_xml_listing(db_session):
    s = _settings()
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://transfer.example/",
        enabled=True,
        provisioning_driver="crushftp",
        crushftp_admin_base_url="https://crush.internal/",
        crushftp_admin_username="crushadmin",
        crushftp_admin_password_encrypted=encrypt_secret("secret", s),
        crushftp_vfs_base_path="/crush_data/AR-SYSTEMS",
    )
    db_session.add(app)
    db_session.commit()

    route = respx.post("https://crush.internal/").mock(
        return_value=Response(
            200,
            text='[{"name":"SDIS74","type":"DIR"},{"name":"SDIS999","type":"DIR"}]',
        )
    )
    folders, err = await CrushFTPProvisioningDriver().list_company_folders(
        app=app, settings=s
    )
    assert err is None
    assert folders == ["SDIS74", "SDIS999"]
    assert route.called
    sent = route.calls.last.request
    assert b"getXMLListing" in sent.content
    assert b"crush_data%2FAR-SYSTEMS" in sent.content or b"/crush_data/AR-SYSTEMS/" in sent.content


@respx.mock
def test_sync_companies_endpoint_creates_groups(client, db_session):
    s = _settings()
    realm = RealmConfig(
        slug="clients",
        name="clients",
        issuer_url="https://kc.example.com/realms/clients",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/oauth2/clients/callback",
        oauth2_proxy_port=4180,
        enabled=True,
        groups_sync_enabled=True,
        keycloak_admin_client_id="sync",
        keycloak_admin_client_secret_encrypted=encrypt_secret("admin", s),
        keycloak_provision_client_id="prov",
        keycloak_provision_client_secret_encrypted=encrypt_secret("prov", s),
    )
    app = App(
        slug="transfer",
        label="Transfer",
        upstream_url="https://transfer.example/",
        enabled=True,
        provisioning_driver="crushftp",
        crushftp_admin_base_url="https://crush.internal/",
        crushftp_admin_username="crushadmin",
        crushftp_admin_password_encrypted=encrypt_secret("secret", s),
        crushftp_vfs_base_path="/crush_data/AR-SYSTEMS",
    )
    db_session.add_all([realm, app])
    db_session.commit()

    respx.post("https://crush.internal/").mock(
        return_value=Response(
            200,
            text='[{"name":"SDIS74","type":"DIR"},{"name":"SDIS999","type":"DIR"}]',
        )
    )

    async def fake_token(*_a, **_k):
        return "token"

    async def fake_create_group(realm, settings, *, name, token=None):
        return f"kc-{name}"

    with (
        patch("app.rbac.account_service.get_provision_token", fake_token),
        patch("app.rbac.account_service.create_keycloak_group", fake_create_group),
    ):
        resp = client.post(
            f"/admin/apps/{app.slug}/crushftp/sync-companies",
            headers={**ADMIN_HEADERS, "Accept": "application/json"},
            data={"realm_id": str(realm.id)},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert set(body["created"]) == {"SDIS74", "SDIS999"}
    groups = db_session.query(RBACGroup).filter_by(realm_id=realm.id).all()
    assert {g.name for g in groups} == {"SDIS74", "SDIS999"}
