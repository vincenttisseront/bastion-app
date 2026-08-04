"""Bastion account creation flow — internal row + Keycloak push (spec §1/§4)."""

import respx
from httpx import Response

from app.models import BastionAccount, RBACGroup, RealmConfig
from app.secret_crypto import encrypt_secret
from app.sso_settings import Settings

ADMIN_HEADERS = {
    "X-Email": "admin@example.com",
    "X-Groups": "portal-admins",
}
JSON_HEADERS = {**ADMIN_HEADERS, "Accept": "application/json"}

KC_BASE = "https://kc.example.com"
KC_ADMIN = f"{KC_BASE}/admin/realms/AR-SYSTEMS"
TOKEN_URL = f"{KC_BASE}/realms/AR-SYSTEMS/protocol/openid-connect/token"


def _settings() -> Settings:
    return Settings(
        vault_portal_internal_token="test-secret",
        portal_secret_encryption_key="test-encryption-key-for-pytest-only",
        portal_domain="portal.test",
        database_url="sqlite://",
    )


def _realm(db, *, provisioning_enabled: bool = True) -> RealmConfig:
    s = _settings()
    realm = RealmConfig(
        slug="ar-systems",
        name="AR-SYSTEMS",
        issuer_url=f"{KC_BASE}/realms/AR-SYSTEMS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", s),
        redirect_uri="https://portal.test/oauth2/ar-systems/callback",
        oauth2_proxy_port=4180,
        enabled=True,
        groups_sync_enabled=True,
        keycloak_admin_client_id="bastion-admin-sync",
        keycloak_admin_client_secret_encrypted=encrypt_secret("sync-secret", s),
        keycloak_provision_client_id="bastion-admin-provision",
        keycloak_provision_client_secret_encrypted=encrypt_secret("prov-secret", s),
        provisioning_enabled=provisioning_enabled,
    )
    db.add(realm)
    db.commit()
    db.refresh(realm)
    return realm


def _group(db, realm: RealmConfig, *, name: str = "ARSYSTEMS-Users", kc_id: str = "g1") -> RBACGroup:
    group = RBACGroup(
        realm_id=realm.id,
        keycloak_group_id=kc_id,
        name=name,
        path=f"/{name}",
    )
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


ORG = "ARSYSTEMS-Users"  # reuse fixture group name → ensure_company_group is idempotent


def _create_payload(realm_id: int, **extra) -> dict:
    data = {
        "realm_id": str(realm_id),
        "username": "jdoe",
        "email": "jdoe@example.com",
        "organization": ORG,
    }
    data.update(extra)
    return data


def _mock_no_duplicate(username: str = "jdoe", email: str = "jdoe@example.com"):
    respx.get(
        f"{KC_ADMIN}/users",
        params={"username": username, "exact": "true", "max": "2"},
    ).respond(200, json=[])
    respx.get(
        f"{KC_ADMIN}/users",
        params={"email": email, "exact": "true", "max": "2"},
    ).respond(200, json=[])


@respx.mock
def test_bastion_account_creation_success_with_group(client, db_session):
    realm = _realm(db_session)
    group = _group(db_session, realm)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    _mock_no_duplicate()
    create_route = respx.post(f"{KC_ADMIN}/users").respond(
        201, headers={"Location": f"{KC_ADMIN}/users/kc-new-1"}
    )
    group_route = respx.put(f"{KC_ADMIN}/users/kc-new-1/groups/g1").respond(204)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data=_create_payload(
            realm.id,
            first_name="John",
            last_name="Doe",
            group_ids=str(group.id),
        ),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["status"] == "keycloak_created"
    assert body["keycloak_user_id"] == "kc-new-1"
    assert body["errors"] == []

    account = db_session.query(BastionAccount).filter_by(username="jdoe").first()
    assert account is not None
    assert account.status == "keycloak_created"
    assert account.keycloak_user_id == "kc-new-1"
    assert account.organization == ORG
    assert account.last_error is None
    assert group_route.called

    # Password policy: generated + UPDATE_PASSWORD temporary, never echoed.
    import json as _json

    sent = _json.loads(create_route.calls[0].request.content)
    assert sent["requiredActions"] == ["UPDATE_PASSWORD"]
    assert sent["credentials"][0]["temporary"] is True
    generated = sent["credentials"][0]["value"]
    assert len(generated) >= 20
    assert generated not in resp.text  # never displayed


@respx.mock
def test_bastion_account_duplicate_detected_before_write(client, db_session):
    """Exact pre-check finds an existing user → no POST /users write attempted."""
    realm = _realm(db_session)
    _group(db_session, realm)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    respx.get(f"{KC_ADMIN}/users", params={"username": "jdoe", "exact": "true"}).respond(
        200, json=[{"id": "existing-1", "username": "jdoe"}]
    )
    create_route = respx.post(f"{KC_ADMIN}/users").respond(201)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data=_create_payload(realm.id),
    )
    assert resp.status_code == 502
    body = resp.json()
    assert body["ok"] is False
    assert "existe déjà" in body["errors"][0]

    assert not create_route.called  # write call avoided (spec §4/§7)
    account = db_session.query(BastionAccount).filter_by(username="jdoe").first()
    assert account.status == "pending"
    assert account.keycloak_user_id is None
    assert "existe déjà" in account.last_error


@respx.mock
def test_bastion_account_keycloak_failure_no_phantom(client, db_session):
    realm = _realm(db_session)
    _group(db_session, realm)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    _mock_no_duplicate()
    respx.post(f"{KC_ADMIN}/users").respond(500)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data=_create_payload(realm.id),
    )
    assert resp.status_code == 502
    body = resp.json()
    assert body["ok"] is False
    assert body["status"] == "pending"

    account = db_session.query(BastionAccount).filter_by(username="jdoe").first()
    assert account.status == "pending"
    assert account.keycloak_user_id is None  # no phantom account
    assert "HTTP 500" in account.last_error


def test_bastion_account_creation_realm_not_enabled(client, db_session):
    realm = _realm(db_session, provisioning_enabled=False)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data=_create_payload(realm.id),
    )
    assert resp.status_code == 400
    assert "Provisioning non activé" in resp.json()["errors"]["_form"]
    assert db_session.query(BastionAccount).count() == 0


def test_bastion_account_creation_duplicate_internal(client, db_session):
    """Existing BastionAccount for (realm, username) blocks before any call."""
    realm = _realm(db_session)
    db_session.add(
        BastionAccount(
            realm_id=realm.id,
            username="jdoe",
            email="jdoe@example.com",
            status="keycloak_created",
            keycloak_user_id="kc-old",
            created_by="admin@example.com",
        )
    )
    db_session.commit()

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data=_create_payload(realm.id),
    )
    assert resp.status_code == 400
    assert "existe déjà" in resp.json()["errors"]["_form"]
    assert db_session.query(BastionAccount).count() == 1


def test_bastion_account_creation_requires_organization(client, db_session):
    realm = _realm(db_session)
    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data={
            "realm_id": str(realm.id),
            "username": "jdoe",
            "email": "jdoe@example.com",
        },
    )
    assert resp.status_code == 400
    assert "Société" in resp.json()["errors"]["_form"] or "organisation" in resp.json()["errors"]["_form"].lower()
    assert db_session.query(BastionAccount).count() == 0


def test_users_new_form_renders_before_dynamic_route(client, db_session):
    """/admin/rbac/users/new must not be captured by /users/{keycloak_user_id}."""
    _realm(db_session)
    resp = client.get("/admin/rbac/users/new", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Nouvel utilisateur" in resp.text
    assert "Société" in resp.text or "organisation" in resp.text.lower()


@respx.mock
def test_bastion_account_creates_company_group_when_missing(client, db_session):
    """New société → Keycloak POST /groups + RBACGroup + user assignment."""
    realm = _realm(db_session)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    _mock_no_duplicate()
    respx.get(f"{KC_ADMIN}/groups").respond(200, json=[])
    group_create = respx.post(f"{KC_ADMIN}/groups").respond(
        201, headers={"Location": f"{KC_ADMIN}/groups/g-sdis"}
    )
    respx.post(f"{KC_ADMIN}/users").respond(
        201, headers={"Location": f"{KC_ADMIN}/users/kc-new-1"}
    )
    assign = respx.put(f"{KC_ADMIN}/users/kc-new-1/groups/g-sdis").respond(204)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data=_create_payload(realm.id, organization="SDIS 999"),
    )
    assert resp.status_code == 200, resp.text
    assert group_create.called
    assert assign.called
    company = (
        db_session.query(RBACGroup)
        .filter_by(realm_id=realm.id, name="SDIS 999")
        .first()
    )
    assert company is not None
    assert company.keycloak_group_id == "g-sdis"
    account = db_session.query(BastionAccount).filter_by(username="jdoe").first()
    assert account.organization == "SDIS 999"
    assert company.id in (account.pending_group_ids or [])


def test_users_page_lists_bastion_accounts_without_grants(client, db_session):
    """Local accounts must appear even without AccessGrant / other-realm picker."""
    ar = _realm(db_session)
    clients = RealmConfig(
        slug="clients",
        name="CLIENTS",
        issuer_url=f"{KC_BASE}/realms/CLIENTS",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", _settings()),
        redirect_uri="https://portal.test/oauth2/clients/callback",
        oauth2_proxy_port=4182,
        enabled=True,
        groups_sync_enabled=False,
        provisioning_enabled=True,
        keycloak_provision_client_id="bastion-admin-provision",
        keycloak_provision_client_secret_encrypted=encrypt_secret(
            "prov-secret", _settings()
        ),
    )
    db_session.add(clients)
    db_session.commit()
    db_session.refresh(clients)
    db_session.add(
        BastionAccount(
            realm_id=clients.id,
            username="toto",
            email="toto@example.com",
            status="pending",
            origin="bastion",
            last_error="view-users missing",
            created_by="admin@example.com",
        )
    )
    db_session.add(
        BastionAccount(
            realm_id=clients.id,
            username="alice",
            email="alice@example.com",
            status="keycloak_created",
            origin="bastion",
            keycloak_user_id="kc-alice",
            created_by="admin@example.com",
        )
    )
    db_session.commit()

    # Default list tab shows bastion accounts (picker realms live under list_tab=open).
    resp = client.get(f"/admin/rbac/users?realm_id={ar.id}", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert "Comptes créés via le bastion" in resp.text
    assert "toto" in resp.text
    assert "alice" in resp.text
    assert "clients" in resp.text

    open_tab = client.get(
        f"/admin/rbac/users?realm_id={ar.id}&list_tab=open", headers=ADMIN_HEADERS
    )
    assert open_tab.status_code == 200
    assert 'option value="%s"' % clients.id in open_tab.text or f'value="{clients.id}"' in open_tab.text

    fiche = client.get(
        f"/admin/rbac/users/view?account_id="
        f"{db_session.query(BastionAccount).filter_by(username='toto').one().id}",
        headers=ADMIN_HEADERS,
    )
    assert fiche.status_code == 200
    assert "toto" in fiche.text
    assert "Identité" in fiche.text
    assert 'href="/admin/rbac/matrix"' not in fiche.text
    assert 'href="/admin/rbac/governance"' not in fiche.text


@respx.mock
def test_bastion_account_creation_assigns_foreign_realm_group(client, db_session):
    """Groups from another realm create a linked Keycloak identity there."""
    target = _realm(db_session)
    other = RealmConfig(
        slug="other",
        name="OTHER",
        issuer_url=f"{KC_BASE}/realms/OTHER",
        client_id="portal",
        client_secret_encrypted=encrypt_secret("secret", _settings()),
        redirect_uri="https://portal.test/oauth2/other/callback",
        oauth2_proxy_port=4181,
        enabled=True,
        keycloak_provision_client_id="bastion-admin-provision",
        keycloak_provision_client_secret_encrypted=encrypt_secret(
            "prov-secret", _settings()
        ),
        provisioning_enabled=True,
    )
    db_session.add(other)
    db_session.commit()
    db_session.refresh(other)
    foreign = _group(db_session, other)  # group belongs to OTHER, not target
    company = _group(db_session, target, name=ORG, kc_id="g-company")

    other_admin = f"{KC_BASE}/admin/realms/OTHER"
    other_token = f"{KC_BASE}/realms/OTHER/protocol/openid-connect/token"

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    respx.post(other_token).respond(200, json={"access_token": "other-token"})
    _mock_no_duplicate()
    respx.get(
        f"{other_admin}/users",
        params={"username": "jdoe", "exact": "true", "max": "2"},
    ).respond(200, json=[])
    respx.get(
        f"{other_admin}/users",
        params={"email": "jdoe@example.com", "exact": "true", "max": "2"},
    ).respond(200, json=[])
    respx.post(f"{KC_ADMIN}/users").respond(
        201, headers={"Location": f"{KC_ADMIN}/users/kc-new-1"}
    )
    respx.post(f"{other_admin}/users").respond(
        201, headers={"Location": f"{other_admin}/users/kc-other-1"}
    )
    foreign_group_route = respx.put(
        f"{other_admin}/users/kc-other-1/groups/{foreign.keycloak_group_id}"
    ).respond(204)
    company_group_route = respx.put(
        f"{KC_ADMIN}/users/kc-new-1/groups/{company.keycloak_group_id}"
    ).respond(204)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data=_create_payload(target.id, group_ids=str(foreign.id)),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True
    assert foreign_group_route.called
    assert company_group_route.called
    linked = (
        db_session.query(BastionAccount)
        .filter_by(realm_id=other.id, username="jdoe")
        .first()
    )
    assert linked is not None
    assert linked.keycloak_user_id == "kc-other-1"


def test_users_new_form_groups_tagged_by_realm(client, db_session):
    """Each group checkbox carries data-realm-id for multi-realm selection."""
    realm = _realm(db_session)
    group = _group(db_session, realm)
    resp = client.get("/admin/rbac/users/new", headers=ADMIN_HEADERS)
    assert resp.status_code == 200
    assert f'data-realm-id="{group.realm_id}"' in resp.text
    assert "data-realm-select" in resp.text
    assert "data-group-filter" in resp.text
    assert "data-group-label=" in resp.text
    assert "reveal_password" in resp.text
    assert "tous realms" in resp.text.lower()


@respx.mock
def test_create_account_reveals_password_once_when_not_emailed(client, db_session):
    """HTML create without email → one-shot password on account detail, then gone."""
    realm = _realm(db_session)
    _group(db_session, realm)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    _mock_no_duplicate()
    create_route = respx.post(f"{KC_ADMIN}/users").respond(
        201, headers={"Location": f"{KC_ADMIN}/users/kc-reveal-1"}
    )
    respx.put(f"{KC_ADMIN}/users/kc-reveal-1/groups/g1").respond(204)

    resp = client.post(
        "/admin/rbac/users/new",
        headers=ADMIN_HEADERS,
        data=_create_payload(realm.id, reveal_password="on"),
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.text
    assert "/admin/rbac/accounts/" in resp.headers["location"]
    assert "portal_temp_cred" in resp.headers.get("set-cookie", "")

    import json as _json

    generated = _json.loads(create_route.calls[0].request.content)["credentials"][0][
        "value"
    ]
    detail = client.get(resp.headers["location"], headers=ADMIN_HEADERS)
    assert detail.status_code == 200
    assert generated in detail.text
    assert "affichage unique" in detail.text.lower()

    again = client.get(resp.headers["location"], headers=ADMIN_HEADERS)
    assert again.status_code == 200
    assert generated not in again.text


@respx.mock
def test_bastion_account_retry_keycloak_after_failure(client, db_session):
    """Pending account can be re-pushed via Relancer Keycloak (explicit retry)."""
    realm = _realm(db_session)
    group = _group(db_session, realm)

    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    _mock_no_duplicate(username="toto", email="toto@example.com")
    respx.post(f"{KC_ADMIN}/users").respond(403, text="missing view-users")

    fail = client.post(
        "/admin/rbac/users/new",
        headers=JSON_HEADERS,
        data=_create_payload(
            realm.id,
            username="toto",
            email="toto@example.com",
            group_ids=str(group.id),
        ),
    )
    assert fail.status_code == 502
    account = db_session.query(BastionAccount).filter_by(username="toto").first()
    assert account is not None
    assert account.status == "pending"
    assert account.origin == "bastion"
    assert account.pending_group_ids == [group.id]
    assert account.keycloak_user_id is None

    respx.reset()
    respx.post(TOKEN_URL).respond(200, json={"access_token": "prov-token"})
    _mock_no_duplicate(username="toto", email="toto@example.com")
    respx.post(f"{KC_ADMIN}/users").respond(
        201, headers={"Location": f"{KC_ADMIN}/users/kc-toto"}
    )
    respx.put(f"{KC_ADMIN}/users/kc-toto/groups/g1").respond(204)

    retry = client.post(
        f"/admin/rbac/accounts/{account.id}/retry-keycloak",
        headers=JSON_HEADERS,
    )
    assert retry.status_code == 200, retry.text
    body = retry.json()
    assert body["ok"] is True
    assert body["keycloak_user_id"] == "kc-toto"

    db_session.refresh(account)
    assert account.status in ("keycloak_created", "provisioned")
    assert account.keycloak_user_id == "kc-toto"
    assert account.last_error is None

    detail = client.get(f"/admin/rbac/accounts/{account.id}", headers=ADMIN_HEADERS)
    assert detail.status_code == 200
    assert "Créé bastion" in detail.text
    assert "Relancer Keycloak" not in detail.text
