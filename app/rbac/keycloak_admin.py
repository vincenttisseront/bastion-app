"""Keycloak Admin API client and RBAC groups sync."""

from __future__ import annotations

import re
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


def _manage_users_error() -> str:
    return (
        "Le compte de service n'a pas le rôle realm-management:manage-users. "
        "Ce rôle est requis pour POST /admin/realms/{realm}/users/{id}/logout "
        "(Keycloak UserResource.logout → auth.users().requireManage)."
    )


def _provision_manage_users_error() -> str:
    return (
        "Le compte de service provisioning n'a pas le rôle "
        "realm-management:manage-users. Vérifiez la configuration côté Keycloak "
        "(manage-users + view-users requis pour créer des utilisateurs)."
    )


USER_CONFLICT_MESSAGE = "Un compte avec cet identifiant existe déjà dans ce realm"


# Residual window after Admin API logout: oauth2-proxy keeps its local cookie until
# cookie_refresh (~1h) or an active revalidation. Documented for UI honesty.
SSO_LOGOUT_RESIDUAL_NOTE = (
    "Sessions Keycloak invalidées côté IdP. Le cookie oauth2-proxy local peut rester "
    "valide jusqu'au prochain refresh (cookie_refresh ≈ 1 h avec la config actuelle) "
    "ou jusqu'à une revalidation active — la coupure portail n'est pas instantanée."
)


async def _admin_get(
    realm: RealmConfig, settings: Settings, path: str, *, token: str | None = None
) -> httpx.Response:
    token = token or await get_admin_token(realm, settings)
    base, realm_name = _issuer_parts(realm.issuer_url)
    url = f"{base}/admin/realms/{realm_name}{path}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        return await client.get(url, headers={"Authorization": f"Bearer {token}"})


async def _admin_send(
    realm: RealmConfig,
    settings: Settings,
    method: str,
    path: str,
    *,
    json: dict | list | None = None,
    token: str | None = None,
) -> httpx.Response:
    """POST/PUT against the Keycloak Admin API.

    ``token`` selects the service account: pass a provision token for writes
    (see get_provision_token); default falls back to the sync/admin account.
    """
    token = token or await get_admin_token(realm, settings)
    base, realm_name = _issuer_parts(realm.issuer_url)
    url = f"{base}/admin/realms/{realm_name}{path}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            return await client.request(
                method,
                url,
                json=json,
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.TimeoutException as exc:
        raise ValueError(
            f"Keycloak injoignable ou timeout lors de l'appel admin ({path})"
        ) from exc
    except httpx.RequestError as exc:
        raise ValueError(
            f"Keycloak injoignable lors de l'appel admin ({path}): {exc}"
        ) from exc


async def _admin_post(
    realm: RealmConfig,
    settings: Settings,
    path: str,
    *,
    json: dict | list | None = None,
    token: str | None = None,
) -> httpx.Response:
    return await _admin_send(realm, settings, "POST", path, json=json, token=token)


async def _admin_put(
    realm: RealmConfig,
    settings: Settings,
    path: str,
    *,
    json: dict | list | None = None,
    token: str | None = None,
) -> httpx.Response:
    return await _admin_send(realm, settings, "PUT", path, json=json, token=token)


async def logout_keycloak_user(
    realm: RealmConfig, keycloak_user_id: str, settings: Settings
) -> dict:
    """
    Invalidate all Keycloak sessions for a user via Admin API.

    Endpoint: POST /admin/realms/{realm}/users/{id}/logout
    Required realm-management role: manage-users (requireManage on UserResource).
    """
    uid = (keycloak_user_id or "").strip()
    if not uid:
        raise ValueError("Identifiant utilisateur Keycloak manquant")
    # Write call (manage-users). Prefer the dedicated provision (write) account when
    # configured so the sync account can stay read-only; fall back to the historical
    # admin/sync account for realms without a provision account yet (Tâche 0 —
    # migration du logout vers le compte d'écriture dédié).
    token = (
        await get_provision_token(realm, settings)
        if provisioning_configured(realm)
        else None
    )
    resp = await _admin_post(realm, settings, f"/users/{uid}/logout", token=token)
    if resp.status_code == 403:
        raise ValueError(_manage_users_error())
    if resp.status_code == 404:
        raise ValueError("Utilisateur Keycloak introuvable pour le logout SSO")
    if resp.status_code >= 400:
        raise ValueError(
            f"Échec logout Keycloak Admin API (HTTP {resp.status_code})"
        )
    return {
        "ok": True,
        "keycloak_user_id": uid,
        "realm_slug": realm.slug,
        "residual_note": SSO_LOGOUT_RESIDUAL_NOTE,
    }


async def fetch_group_members(
    realm: RealmConfig,
    keycloak_group_id: str,
    settings: Settings,
    *,
    max_results: int = 500,
) -> list[dict]:
    max_results = max(1, min(int(max_results), 2000))
    resp = await _admin_get(
        realm,
        settings,
        f"/groups/{keycloak_group_id}/members?max={max_results}",
    )
    if resp.status_code == 403:
        raise ValueError(_view_users_error())
    if resp.status_code >= 400:
        raise ValueError(f"Échec lecture membres du groupe (HTTP {resp.status_code})")
    data = resp.json()
    return data if isinstance(data, list) else []


async def count_keycloak_users(
    realm: RealmConfig,
    settings: Settings,
    *,
    enabled: bool | None = None,
) -> int:
    """
    Count users via Keycloak Admin ``GET /users/count``.

    ``enabled=True/False`` filters active/disabled; ``None`` = all.
    """
    path = "/users/count"
    if enabled is True:
        path += "?enabled=true"
    elif enabled is False:
        path += "?enabled=false"
    resp = await _admin_get(realm, settings, path)
    if resp.status_code == 403:
        raise ValueError(_view_users_error())
    if resp.status_code >= 400:
        raise ValueError(f"Échec comptage utilisateurs (HTTP {resp.status_code})")
    try:
        return int(resp.json())
    except (TypeError, ValueError) as exc:
        raise ValueError("Réponse Keycloak /users/count invalide") from exc


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


from app.search_fuzzy import fold_text, score_query_against_fields


def _fold_text(value: str) -> str:
    """Backward-compatible alias — prefer app.search_fuzzy.fold_text."""
    return fold_text(value)


def _user_search_fields(user: dict) -> list[str]:
    fields = [
        user.get("username") or "",
        user.get("email") or "",
        user.get("firstName") or "",
        user.get("lastName") or "",
        " ".join(
            p
            for p in (user.get("firstName") or "", user.get("lastName") or "")
            if p
        ),
    ]
    return [f for f in fields if f]


def score_user_against_query(query: str, user: dict) -> float:
    """difflib ratio in [0, 1] — best field match (substring boost)."""
    return score_query_against_fields(query, _user_search_fields(user))


async def search_keycloak_users_fuzzy(
    realm: RealmConfig,
    query: str,
    settings: Settings,
    *,
    limit: int = 8,
    min_score: float = 0.52,
    broad_max: int = 100,
) -> list[dict]:
    """
    Option A — Keycloak candidate pool + stdlib fuzzy rank.

    Keycloak Admin `/users?search=` is prefix/substring-oriented (no typo tolerance).
    We fetch the native match plus a broader prefix pool (first 2 chars, max=100 —
    reasonable for typical iBanFirst realms), then rank with SequenceMatcher and
    return the top ``limit`` above ``min_score``. Native hits are always kept.
    No new dependency (difflib / unicodedata).
    """
    q = (query or "").strip()
    if len(q) < 2:
        return []

    native = await search_keycloak_users(realm, q, settings, max_results=20)
    prefix = q[:2]
    broad: list[dict] = []
    if prefix.casefold() != q.casefold():
        broad = await search_keycloak_users(
            realm, prefix, settings, max_results=broad_max
        )

    by_id: dict[str, dict] = {}
    for user in native + broad:
        uid = user.get("id")
        if isinstance(uid, str) and uid:
            by_id[uid] = user

    native_ids = {
        u.get("id") for u in native if isinstance(u.get("id"), str)
    }
    ranked: list[tuple[float, dict]] = []
    for user in by_id.values():
        score = score_user_against_query(q, user)
        if user.get("id") in native_ids:
            score = max(score, 0.99)
        if score >= min_score or user.get("id") in native_ids:
            ranked.append((score, user))

    ranked.sort(
        key=lambda item: (
            -item[0],
            (item[1].get("username") or item[1].get("email") or ""),
        )
    )
    return [user for _, user in ranked[: max(1, limit)]]


async def find_keycloak_user_exact(
    realm: RealmConfig,
    settings: Settings,
    *,
    username: str | None = None,
    email: str | None = None,
    token: str | None = None,
) -> dict | None:
    """Exact-match user lookup (``?username=…&exact=true`` / ``?email=…&exact=true``).

    Dedicated duplicate pre-check before user creation (audit §1.4) — the existing
    search_keycloak_users() is substring/fuzzy-oriented and MUST NOT be used here.
    Returns the first matching user dict, or None.
    """

    async def _query(param: str, value: str) -> dict | None:
        resp = await _admin_get(
            realm,
            settings,
            f"/users?{param}={quote(value)}&exact=true&max=2",
            token=token,
        )
        if resp.status_code == 403:
            raise ValueError(_view_users_error())
        if resp.status_code >= 400:
            raise ValueError(
                f"Échec vérification de doublon (HTTP {resp.status_code})"
            )
        data = resp.json()
        if isinstance(data, list) and data:
            return data[0]
        return None

    uname = (username or "").strip()
    mail = (email or "").strip()
    if uname:
        found = await _query("username", uname)
        if found:
            return found
    if mail:
        found = await _query("email", mail)
        if found:
            return found
    return None


async def create_keycloak_user(
    realm: RealmConfig,
    settings: Settings,
    *,
    username: str,
    email: str,
    first_name: str | None = None,
    last_name: str | None = None,
    initial_password: str,
    temporary_password: bool = True,
) -> str:
    """Create a Keycloak user via the WRITE (provision) service account.

    Password policy (décision actée §9.1): randomly generated by the caller +
    ``requiredActions: ["UPDATE_PASSWORD"]`` so the user must change it at first
    login. ``initial_password`` is sent to Keycloak only — never logged, never
    stored, never returned.

    Returns the new Keycloak user id (``Location`` header).
    """
    token = await get_provision_token(realm, settings)
    payload: dict = {
        "username": username,
        "email": email,
        "enabled": True,
        "emailVerified": False,
        "requiredActions": ["UPDATE_PASSWORD"] if temporary_password else [],
        "credentials": [
            {
                "type": "password",
                "value": initial_password,
                "temporary": bool(temporary_password),
            }
        ],
    }
    if first_name:
        payload["firstName"] = first_name
    if last_name:
        payload["lastName"] = last_name

    resp = await _admin_post(realm, settings, "/users", json=payload, token=token)
    if resp.status_code == 409:
        raise ValueError(USER_CONFLICT_MESSAGE)
    if resp.status_code == 403:
        raise ValueError(_provision_manage_users_error())
    if resp.status_code >= 400:
        raise ValueError(
            f"Échec création utilisateur Keycloak (HTTP {resp.status_code})"
        )

    location = resp.headers.get("location", "")
    user_id = location.rstrip("/").rsplit("/", 1)[-1] if location else ""
    if not user_id:
        # Some proxies strip Location — fall back to the exact lookup.
        found = await find_keycloak_user_exact(
            realm, settings, username=username, token=token
        )
        user_id = str(found.get("id") or "") if found else ""
    if not user_id:
        raise ValueError(
            "Utilisateur créé mais identifiant Keycloak introuvable "
            "(header Location absent et recherche exacte vide)"
        )
    return user_id


async def update_keycloak_user(
    realm: RealmConfig,
    settings: Settings,
    *,
    keycloak_user_id: str,
    email: str | None = None,
    first_name: str | None = None,
    last_name: str | None = None,
    enabled: bool | None = None,
    token: str | None = None,
) -> None:
    """GET + PUT /users/{id} — merge identity fields (WRITE provision account)."""
    uid = (keycloak_user_id or "").strip()
    if not uid:
        raise ValueError("Identifiant utilisateur Keycloak manquant")
    token = token or await get_provision_token(realm, settings)
    current: dict | None = None
    try:
        current = await fetch_keycloak_user(realm, uid, settings)
    except ValueError:
        current = None
    if current is None:
        # Prefer provision token for write path when sync account lacks view-users
        resp = await _admin_get(realm, settings, f"/users/{uid}", token=token)
        if resp.status_code == 404:
            raise ValueError("Utilisateur Keycloak introuvable")
        if resp.status_code >= 400:
            raise ValueError(f"Échec lecture utilisateur Keycloak (HTTP {resp.status_code})")
        current = resp.json() if resp.content else {}
    if not isinstance(current, dict):
        raise ValueError("Réponse Keycloak utilisateur invalide")

    payload = dict(current)
    if email is not None:
        payload["email"] = email.strip()
    if first_name is not None:
        payload["firstName"] = (first_name or "").strip()
    if last_name is not None:
        payload["lastName"] = (last_name or "").strip()
    if enabled is not None:
        payload["enabled"] = bool(enabled)
    # Never re-send credentials blob from a GET (may be incomplete / empty).
    payload.pop("credentials", None)

    resp = await _admin_put(
        realm, settings, f"/users/{uid}", json=payload, token=token
    )
    if resp.status_code == 403:
        raise ValueError(_provision_manage_users_error())
    if resp.status_code == 404:
        raise ValueError("Utilisateur Keycloak introuvable")
    if resp.status_code == 409:
        raise ValueError("Conflit Keycloak (email déjà utilisé)")
    if resp.status_code >= 400:
        raise ValueError(f"Échec mise à jour Keycloak (HTTP {resp.status_code})")


async def add_user_to_keycloak_group(
    realm: RealmConfig,
    settings: Settings,
    *,
    keycloak_user_id: str,
    keycloak_group_id: str,
    token: str | None = None,
) -> None:
    """PUT /users/{id}/groups/{group_id} with the WRITE (provision) account."""
    token = token or await get_provision_token(realm, settings)
    resp = await _admin_put(
        realm,
        settings,
        f"/users/{keycloak_user_id}/groups/{keycloak_group_id}",
        token=token,
    )
    if resp.status_code == 403:
        raise ValueError(_provision_manage_users_error())
    if resp.status_code == 404:
        raise ValueError("Utilisateur ou groupe Keycloak introuvable pour l'assignation")
    if resp.status_code >= 400:
        raise ValueError(
            f"Échec ajout au groupe Keycloak (HTTP {resp.status_code})"
        )


async def create_keycloak_group(
    realm: RealmConfig,
    settings: Settings,
    *,
    name: str,
    token: str | None = None,
) -> str:
    """POST /groups — create a top-level group; return Keycloak group id."""
    name = (name or "").strip()
    if not name:
        raise ValueError("Nom de groupe Keycloak requis")
    token = token or await get_provision_token(realm, settings)

    async def _find_id() -> str:
        resp = await _admin_get(
            realm,
            settings,
            "/groups?briefRepresentation=false",
            token=token,
        )
        if resp.status_code >= 400:
            return ""
        data = resp.json()
        groups = data if isinstance(data, list) else []
        for g in _flatten_groups(groups):
            if (g.get("name") or "").strip().lower() == name.lower():
                return str(g.get("id") or "")
        return ""

    resp = await _admin_post(
        realm, settings, "/groups", json={"name": name}, token=token
    )
    if resp.status_code == 403:
        raise ValueError(_provision_manage_users_error())
    if resp.status_code == 409:
        gid = await _find_id()
        if gid:
            return gid
        raise ValueError(f"Groupe Keycloak « {name} » en conflit (409) sans id résolu")
    if resp.status_code >= 400:
        raise ValueError(f"Échec création groupe Keycloak (HTTP {resp.status_code})")
    location = resp.headers.get("location", "")
    group_id = location.rstrip("/").rsplit("/", 1)[-1] if location else ""
    if not group_id:
        group_id = await _find_id()
    if not group_id:
        raise ValueError(
            f"Groupe « {name} » créé mais identifiant Keycloak introuvable"
        )
    return group_id


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


async def _client_credentials_token(
    issuer_url: str,
    client_id: str,
    client_secret_encrypted: str,
    settings: Settings,
) -> str:
    """client_credentials token for ANY per-realm service account.

    Single parameterized core (audit §1.2) — callers pick the credential pair:
    get_admin_token (read/sync account) or get_provision_token (write account).
    Never duplicated per account.
    """
    token_endpoint = f"{issuer_url.rstrip('/')}/protocol/openid-connect/token"
    client_secret = decrypt_secret(client_secret_encrypted, settings)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
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


async def get_admin_token(realm: RealmConfig, settings: Settings) -> str:
    """Token for the read-oriented sync service account (groups sync, user search)."""
    if not realm.keycloak_admin_client_id or not realm.keycloak_admin_client_secret_encrypted:
        raise ValueError(
            "Compte de service non configuré pour ce realm. "
            "Renseignez le Client ID/Secret (admin) dans la fiche realm."
        )
    return await _client_credentials_token(
        realm.issuer_url,
        realm.keycloak_admin_client_id,
        realm.keycloak_admin_client_secret_encrypted,
        settings,
    )


def provisioning_configured(realm: RealmConfig) -> bool:
    return bool(
        getattr(realm, "keycloak_provision_client_id", None)
        and getattr(realm, "keycloak_provision_client_secret_encrypted", None)
    )


async def get_provision_token(realm: RealmConfig, settings: Settings) -> str:
    """Token for the WRITE service account (manage-users) — user provisioning."""
    if not provisioning_configured(realm):
        raise ValueError(
            "Compte de service provisioning non configuré pour ce realm. "
            "Renseignez le Client ID/Secret (provisioning) dans la fiche realm."
        )
    return await _client_credentials_token(
        realm.issuer_url,
        realm.keycloak_provision_client_id,
        realm.keycloak_provision_client_secret_encrypted,
        settings,
    )


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


def parse_groups_sync_include(raw: str | None) -> list[str]:
    """Newline- or comma-separated group names / paths. Empty = no filter."""
    if not raw:
        return []
    out: list[str] = []
    for part in raw.replace(",", "\n").splitlines():
        token = part.strip()
        if token and token not in out:
            out.append(token)
    return out


def _norm_group_token(value: str) -> str:
    """Collapse spaces / hyphens / underscores so « ARSYSTEMS Users » ≈ « ARSYSTEMS-Users »."""
    return re.sub(r"[\s_\-]+", "", (value or "").strip().lower())


def group_matches_sync_include(name: str, path: str, include: list[str]) -> bool:
    if not include:
        return True
    name_l = (name or "").strip().lower()
    path_l = (path or "").strip().lower()
    name_n = _norm_group_token(name_l)
    path_n = _norm_group_token(path_l)
    path_base = path_l.rsplit("/", 1)[-1] if path_l else ""
    path_base_n = _norm_group_token(path_base)
    for rule in include:
        r = rule.strip().lower()
        if not r:
            continue
        r_n = _norm_group_token(r)
        if name_l == r or path_l == r or name_n == r_n or path_n == r_n or path_base_n == r_n:
            return True
        # Path prefix: "/Societes" matches "/Societes/ABIOM"
        if path_l.startswith(r.rstrip("/") + "/") or path_l.rstrip("/") == r.rstrip("/"):
            return True
        # Normalized prefix on path segments
        if r_n and path_n.startswith(r_n):
            return True
    return False


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
    include = parse_groups_sync_include(getattr(realm, "groups_sync_include", None))
    now = utcnow()
    imported = 0
    updated = 0
    skipped = 0
    members_refreshed = 0
    members_total = 0
    # Refresh member counts only when an allowlist is set (avoids N Keycloak calls on 200+ groups).
    refresh_members = bool(include)
    synced_rows: list[RBACGroup] = []

    for g in groups:
        kc_id = str(g.get("id") or "").strip()
        name = str(g.get("name") or "").strip()
        path = str(g.get("path") or "").strip()
        if not kc_id or not name or not path:
            continue
        if not group_matches_sync_include(name, path, include):
            skipped += 1
            continue

        existing = (
            db.query(RBACGroup)
            .filter(RBACGroup.realm_id == realm.id, RBACGroup.keycloak_group_id == kc_id)
            .first()
        )
        if not existing:
            existing = RBACGroup(
                realm_id=realm.id,
                keycloak_group_id=kc_id,
                name=name,
                path=path,
                synced_at=now,
            )
            db.add(existing)
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
        synced_rows.append(existing)

    db.flush()

    if refresh_members:
        for row in synced_rows:
            if not row.keycloak_group_id:
                continue
            try:
                members = await fetch_group_members(realm, row.keycloak_group_id, settings)
            except Exception:
                continue
            count = len(members)
            row.member_count = count
            members_refreshed += 1
            members_total += count

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
        "skipped": skipped,
        "members_refreshed": members_refreshed,
        "members_total": members_total,
        "synced_at": now.isoformat(),
    }

