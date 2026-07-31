"""Post-grant provisioning hook — POST /admin/rbac/grants (spec §5.3)."""

import respx
from httpx import Response

from app.models import (
    App,
    BastionAccount,
    BastionAccountProvisioning,
    RealmConfig,
)
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}
JSON_HEADERS = {
    **ADMIN_HEADERS,
    "Accept": "application/json",
    "Content-Type": "application/json",
}

CRUSH_ADMIN_URL = "https://crush-admin.internal:8080/"

CRUSH_SET_USER_OK = Response(200, text="<response>success</response>")


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _seed(db, *, with_account: bool = True):
    s = _settings()
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url="https://kc.example.com/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/cb",
        oauth2_proxy_port=4180,
        enabled=True,
        keycloak_provision_client_id="bastion-admin-provision",
        keycloak_provision_client_secret_encrypted=encrypt_secret("prov-secret", s),
        provisioning_enabled=True,
    )
    app = App(
        slug="crushftp",
        label="CrushFTP",
        upstream_url="https://crush.public/",
        enabled=True,
        provisioning_driver="crushftp",
        crushftp_admin_base_url=CRUSH_ADMIN_URL,
        crushftp_admin_server_group="MainUsers",
        crushftp_admin_username="crushadmin",
        crushftp_admin_password_encrypted=encrypt_secret("admin-pass", s),
        crushftp_vfs_base_path="/crush_data/AR-SYSTEMS",
    )
    db.add_all([realm, app])
    db.commit()
    db.refresh(realm)
    db.refresh(app)
    account = None
    if with_account:
        account = BastionAccount(
            realm_id=realm.id,
            username="jdoe",
            email="jdoe@example.com",
            organization="SDIS999",
            status="keycloak_created",
            keycloak_user_id="kc-user-1",
            origin="bastion",
            created_by="admin@example.com",
        )
        db.add(account)
    db.commit()
    return realm, app, account


@respx.mock
def test_bastion_account_grant_hook_triggers_provisioning(client, db_session):
    realm, app, account = _seed(db_session)

    respx.post(CRUSH_ADMIN_URL).mock(
        side_effect=[
            Response(200, text="<response>failure</response>"),
            CRUSH_SET_USER_OK,
            CRUSH_SET_USER_OK,
            Response(
                200,
                text='<?xml version="1.0"?><user type="properties"><username>jdoe</username><root_dir>/</root_dir></user>',
            ),
            CRUSH_SET_USER_OK,
        ]
    )

    resp = client.post(
        "/admin/rbac/grants",
        headers=JSON_HEADERS,
        json={
            "subject_type": "user",
            "keycloak_user_id": "kc-user-1",
            "user_display_cache": "jdoe",
            "resource_type": "application",
            "application_id": app.id,
            "access_level": "launch",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["provisioning"]["status"] == "success"
    assert body["provisioning"]["app_slug"] == "crushftp"

    row = (
        db_session.query(BastionAccountProvisioning)
        .filter_by(bastion_account_id=account.id, application_id=app.id)
        .first()
    )
    assert row is not None
    assert row.status == "success"


@respx.mock
def test_bastion_account_grant_hook_no_bastion_account_is_explicit(client, db_session):
    """User created outside bastion → explicit 'skipped', never silent."""
    realm, app, _ = _seed(db_session, with_account=False)

    resp = client.post(
        "/admin/rbac/grants",
        headers=JSON_HEADERS,
        json={
            "subject_type": "user",
            "keycloak_user_id": "kc-unknown",
            "user_display_cache": "outsider",
            "resource_type": "application",
            "application_id": app.id,
            "access_level": "launch",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True  # the grant itself succeeded
    assert body["provisioning"]["status"] == "skipped"
    assert "hors bastion" in body["provisioning"]["detail"]
    assert db_session.query(BastionAccountProvisioning).count() == 0


def test_bastion_account_grant_hook_ignores_apps_without_driver(client, db_session):
    realm, _, account = _seed(db_session)
    sso_app = App(
        slug="wikijs",
        label="Wiki.js",
        upstream_url="https://wiki.internal/",
        enabled=True,
        provisioning_driver=None,
    )
    db_session.add(sso_app)
    db_session.commit()

    resp = client.post(
        "/admin/rbac/grants",
        headers=JSON_HEADERS,
        json={
            "subject_type": "user",
            "keycloak_user_id": "kc-user-1",
            "user_display_cache": "jdoe",
            "resource_type": "application",
            "application_id": sso_app.id,
            "access_level": "launch",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert "provisioning" not in body  # out of hook scope — no driver configured


def test_bastion_account_grant_hook_ignores_group_grants(client, db_session):
    """V1: only user-subject grants trigger the hook (audit §4)."""
    from app.models import RBACGroup

    realm, app, account = _seed(db_session)
    group = RBACGroup(
        realm_id=realm.id,
        keycloak_group_id="g1",
        name="ARSYSTEMS-Users",
        path="/ARSYSTEMS-Users",
    )
    db_session.add(group)
    db_session.commit()

    resp = client.post(
        "/admin/rbac/grants",
        headers=JSON_HEADERS,
        json={
            "subject_type": "group",
            "rbac_group_id": group.id,
            "resource_type": "application",
            "application_id": app.id,
            "access_level": "launch",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert "provisioning" not in body
    assert db_session.query(BastionAccountProvisioning).count() == 0
