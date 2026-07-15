"""Keycloak Admin API client and RBAC groups sync."""

from __future__ import annotations

from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from app.models import RBACGroup, RealmConfig, utcnow
from app.secret_crypto import decrypt_secret
from app.sso_settings import Settings


def _issuer_parts(issuer_url: str) -> tuple[str, str]:
    if "/realms/" not in issuer_url:
        raise ValueError("Issuer URL invalide (doit contenir /realms/)")
    base = issuer_url.split("/realms/")[0].rstrip("/")
    realm_name = issuer_url.rstrip("/").split("/realms/")[-1]
    if not base or not realm_name:
        raise ValueError("Issuer URL invalide")
    return base, realm_name


def _view_users_error() -> str:
    return (
        "Le compte de service n'a pas le rôle realm-management:view-users. "
        "Vérifiez la configuration côté Keycloak (view-users et query-groups requis)."
    )


async def _admin_get(realm: RealmConfig, settings: Settings, path: str) -> httpx.Response:
    token = await get_admin_token(realm, settings)
    base, realm_name = _issuer_parts(realm.issuer_url)
    url = f"{base}/admin/realms/{realm_name}{path}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        return await client.get(url, headers={"Authorization": f"Bearer {token}"})


async def fetch_group_members(
    realm: RealmConfig, keycloak_group_id: str, settings: Settings
) -> list[dict]:
    resp = await _admin_get(realm, settings, f"/groups/{keycloak_group_id}/members")
    if resp.status_code == 403:
        raise ValueError(_view_users_error())
    if resp.status_code >= 400:
        raise ValueError(f"Échec lecture membres du groupe (HTTP {resp.status_code})")
    data = resp.json()
    return data if isinstance(data, list) else []


async def search_keycloak_users(
    realm: RealmConfig, query: str, settings: Settings, *, max_results: int = 20
) -> list[dict]:
    q = (query or "").strip()
    if not q:
        return []
    resp = await _admin_get(
        realm,
        settings,
        f"/users?search={quote(q)}&max={max_results}",
    )
    if resp.status_code == 403:
        raise ValueError(_view_users_error())
    if resp.status_code >= 400:
        raise ValueError(f"Échec recherche utilisateurs (HTTP {resp.status_code})")
    data = resp.json()
    return data if isinstance(data, list) else []


async def fetch_user_groups(
    realm: RealmConfig, keycloak_user_id: str, settings: Settings
) -> list[dict]:
    resp = await _admin_get(realm, settings, f"/users/{keycloak_user_id}/groups")
    if resp.status_code == 403:
        raise ValueError(_view_users_error())
    if resp.status_code >= 400:
        raise ValueError(f"Échec lecture groupes utilisateur (HTTP {resp.status_code})")
    data = resp.json()
    return data if isinstance(data, list) else []


async def fetch_keycloak_user(
    realm: RealmConfig, keycloak_user_id: str, settings: Settings
) -> dict | None:
    resp = await _admin_get(realm, settings, f"/users/{keycloak_user_id}")
    if resp.status_code == 404:
        return None
    if resp.status_code == 403:
        raise ValueError(_view_users_error())
    if resp.status_code >= 400:
        raise ValueError(f"Échec lecture utilisateur (HTTP {resp.status_code})")
    return resp.json()


async def get_admin_token(realm: RealmConfig, settings: Settings) -> str:
    if not realm.keycloak_admin_client_id or not realm.keycloak_admin_client_secret_encrypted:
        raise ValueError(
            "Compte de service non configuré pour ce realm. "
            "Renseignez le Client ID/Secret (admin) dans la fiche realm."
        )
    token_endpoint = f"{realm.issuer_url.rstrip('/')}/protocol/openid-connect/token"
    client_secret = decrypt_secret(realm.keycloak_admin_client_secret_encrypted, settings)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": realm.keycloak_admin_client_id,
                "client_secret": client_secret,
            },
        )
    content_type = resp.headers.get("content-type", "")
    body = resp.json() if content_type.startswith("application/json") else {}
    if resp.status_code >= 400:
        if body.get("error") == "invalid_client":
            raise ValueError("Client ID ou secret du compte de service invalide")
        raise ValueError(f"Échec récupération token admin (HTTP {resp.status_code})")
    token = body.get("access_token")
    if not token:
        raise ValueError("Réponse token admin invalide (access_token manquant)")
    return token


def _flatten_groups(groups: list[dict]) -> list[dict]:
    out: list[dict] = []
    stack = list(groups or [])
    while stack:
        g = stack.pop()
        if isinstance(g, dict):
            out.append(g)
            sub = g.get("subGroups") or []
            if isinstance(sub, list) and sub:
                stack.extend(sub)
    return out


async def fetch_keycloak_groups(realm: RealmConfig, settings: Settings) -> list[dict]:
    token = await get_admin_token(realm, settings)
    base, realm_name = _issuer_parts(realm.issuer_url)
    admin_url = f"{base}/admin/realms/{realm_name}/groups?briefRepresentation=false"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(admin_url, headers={"Authorization": f"Bearer {token}"})
    if resp.status_code == 403:
        raise ValueError(
            "Le compte de service n'a pas le rôle realm-management:query-groups. "
            "Vérifiez la configuration côté Keycloak."
        )
    if resp.status_code >= 400:
        raise ValueError(f"Échec lecture groupes Keycloak (HTTP {resp.status_code})")
    return resp.json()


async def sync_keycloak_groups(realm: RealmConfig, db: Session, settings: Settings) -> dict:
    if not realm.groups_sync_enabled:
        raise ValueError(
            "Import des groupes non activé pour ce realm. "
            "Configurez le compte de service dans la fiche realm."
        )

    try:
        raw = await fetch_keycloak_groups(realm, settings)
    except httpx.TimeoutException as exc:
        raise ValueError(f"Keycloak injoignable depuis le serveur : {exc}") from exc
    except httpx.RequestError as exc:
        raise ValueError(f"Keycloak injoignable depuis le serveur : {exc}") from exc

    groups = _flatten_groups(raw if isinstance(raw, list) else [])
    now = utcnow()
    imported = 0
    updated = 0

    for g in groups:
        kc_id = str(g.get("id") or "").strip()
        name = str(g.get("name") or "").strip()
        path = str(g.get("path") or "").strip()
        if not kc_id or not name or not path:
            continue

        existing = (
            db.query(RBACGroup)
            .filter(RBACGroup.realm_id == realm.id, RBACGroup.keycloak_group_id == kc_id)
            .first()
        )
        if not existing:
            db.add(
                RBACGroup(
                    realm_id=realm.id,
                    keycloak_group_id=kc_id,
                    name=name,
                    path=path,
                    synced_at=now,
                )
            )
            imported += 1
        else:
            changed = False
            if existing.name != name:
                existing.name = name
                changed = True
            if existing.path != path:
                existing.path = path
                changed = True
            existing.synced_at = now
            if changed:
                updated += 1

    db.flush()

    # Orphans: groups in DB for this realm not refreshed this run.
    # Use equality check on the run timestamp to avoid timezone/SQLite quirks.
    orphaned = (
        db.query(RBACGroup)
        .filter(
            RBACGroup.realm_id == realm.id,
            RBACGroup.keycloak_group_id.is_not(None),
            (RBACGroup.synced_at.is_(None) | (RBACGroup.synced_at != now)),
        )
        .count()
    )

    realm.last_groups_sync_at = now
    realm.last_groups_sync_status = "ok"
    realm.last_groups_sync_error = None

    return {
        "realm_id": realm.id,
        "status": "ok",
        "imported": imported,
        "updated": updated,
        "orphaned": orphaned,
        "synced_at": now.isoformat(),
    }

