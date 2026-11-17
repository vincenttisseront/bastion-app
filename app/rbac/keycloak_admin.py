"""Keycloak Admin API client and RBAC groups sync."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from urllib.parse import quote, unquote

import httpx
from sqlalchemy.orm import Session

from app import re_safe
from app.models import RBACGroup, RealmConfig, utcnow
from app.secret_crypto import decrypt_secret
from app.sso_settings import Settings

logger = logging.getLogger(__name__)

_MSG_KC_USER_ID_MISSING = "Identifiant utilisateur Keycloak manquant"
_MSG_KC_USER_NOT_FOUND = "Utilisateur Keycloak introuvable"
_KC_REALMS_PATH = "/realms/"

# Concurrent Keycloak member-count refreshes during group sync.
_MEMBER_REFRESH_CONCURRENCY = 8
# GET /groups defaults to max=100 and empty subGroups (Keycloak 23+).
_GROUPS_PAGE_SIZE = 100
_GROUPS_HARD_CAP = 5000
_GROUPS_TREE_TIMEOUT = 30.0
_MSG_QUERY_GROUPS = (
    "Le compte de service n'a pas le rôle realm-management:query-groups. "
    "Vérifiez la configuration côté Keycloak."
)

# Service-account tokens: (token endpoint, client_id, encrypted secret) -> (token, expiry).
_TOKEN_CACHE: dict[tuple[str, str, str], tuple[str, float]] = {}
_TOKEN_EXPIRY_MARGIN_SECONDS = 30.0


def _issuer_parts(issuer_url: str) -> tuple[str, str]:
    if _KC_REALMS_PATH not in issuer_url:
        raise ValueError("Issuer URL invalide (doit contenir /realms/)")
    base = issuer_url.split(_KC_REALMS_PATH)[0].rstrip("/")
    realm_name = issuer_url.rstrip("/").split(_KC_REALMS_PATH)[-1]
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
    "Sessions Keycloak invalidées côté IdP ; session native bastion_session "
    "révoquée immédiatement. Si l'utilisateur était encore sur oauth2-proxy, "
    "le cookie local peut rester valide jusqu'au prochain refresh "
    "(cookie_refresh ≈ 1 h) ou jusqu'à une revalidation active."
)


# Keycloak 26.8.2+ rejects (401) Admin REST API tokens that lack this built-in
# client scope. The upgrade assigns it to admin-cli / security-admin-console
# only: custom service-account clients (sync, provisioning) need it by hand.
KC_ADMIN_API_SCOPE = "kc-admin-api"


def _unverified_claims(token: str | None) -> dict:
    """JWT payload decoded WITHOUT signature check: error messages only."""
    try:
        segment = (token or "").split(".")[1]
        data = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (IndexError, ValueError):  # binascii / unicode / JSON errors are ValueError
        return {}
    return data if isinstance(data, dict) else {}


class KeycloakAdminError(ValueError):
    """Keycloak Admin API / token endpoint failure, with the facts logs need.

    Still a ValueError, so every existing ``except ValueError`` keeps working.
    ``url`` never carries the query string (user searches) and nothing here
    carries a token or a secret: ``token_scope`` is the token's scope claim.
    """

    def __init__(
        self,
        message: str,
        *,
        cause: str,
        status: int | None = None,
        url: str | None = None,
        client_id: str | None = None,
        token_scope: str | None = None,
    ) -> None:
        super().__init__(message)
        self.cause = cause
        self.status = status
        self.url = (url or "").split("?", 1)[0] or None
        self.client_id = client_id or None
        self.token_scope = token_scope or None


def _admin_401_diagnosis(token: str | None, called_url: str | None) -> tuple[str, str]:
    """(cause, explanation) for a 401 from the Admin API, from the rejected token."""
    claims = _unverified_claims(token)
    client = str(claims.get("azp") or "").strip()
    who = f"du client « {client} »" if client else "du compte de service"
    if claims and KC_ADMIN_API_SCOPE not in str(claims.get("scope") or "").split():
        return "missing_admin_api_scope", (
            f"le token {who} ne porte pas le client scope « {KC_ADMIN_API_SCOPE} » : "
            "depuis Keycloak 26.8.2, l'Admin REST API refuse un tel token. Dans "
            f"Keycloak, ajoutez « {KC_ADMIN_API_SCOPE} » aux client scopes par défaut "
            "(Default) de ce client, puis rechargez : le bastion renouvelle le token "
            "de lui-même."
        )
    hint = (
        f"Keycloak a refusé le token {who} (même après renouvellement). "
        "Vérifiez l'URL issuer du realm (hostname public de Keycloak), les "
        "révocations (not-before) du realm et, sur Keycloak 26.8.2 ou plus, le "
        f"client scope « {KC_ADMIN_API_SCOPE} » du client. Les journaux Keycloak "
        "donnent la cause exacte."
    )
    base, sep, rest = (called_url or "").partition("/admin/realms/")
    issuer = str(claims.get("iss") or "").rstrip("/")
    if sep and issuer:
        expected = f"{base}/realms/{unquote(rest.split('/', 1)[0].split('?', 1)[0])}"
        if issuer != expected:
            hint += f" Issuer du token : {issuer} ; realm appelé : {expected}."
    return "token_rejected", hint


def _admin_error(
    label: str, status: int, token: str | None, url: str | None
) -> KeycloakAdminError:
    """Error for an Admin API call that answered ``status`` (>= 400)."""
    claims = _unverified_claims(token)
    facts = {
        "status": status,
        "url": url,
        "client_id": str(claims.get("azp") or ""),
        "token_scope": str(claims.get("scope") or ""),
    }
    if status != 401:
        return KeycloakAdminError(f"{label} (HTTP {status})", cause="http_error", **facts)
    cause, hint = _admin_401_diagnosis(token, url)
    return KeycloakAdminError(f"{label} (HTTP 401) : {hint}", cause=cause, **facts)


def _admin_failure(label: str, resp: httpx.Response) -> KeycloakAdminError:
    """Error for a failed Admin API call; a 401 says why Keycloak refused it."""
    try:
        request = resp.request
    except RuntimeError:  # response built without a request (stubs)
        return _admin_error(label, resp.status_code, None, None)
    scheme, _, bearer = request.headers.get("Authorization", "").partition(" ")
    token = bearer.strip() if scheme.lower() == "bearer" else None
    return _admin_error(label, resp.status_code, token, str(request.url))


def _evict_cached_token(token: str) -> None:
    """Drop a service-account token Keycloak just rejected (HTTP 401).

    The cache trusts ``expires_in``, but Keycloak can invalidate a token earlier
    (restart with lost sessions, realm not-before push, key rotation). Without
    this, every admin call fails until the cached entry expires.
    """
    for key, (cached, _expiry) in list(_TOKEN_CACHE.items()):
        if cached == token:
            _TOKEN_CACHE.pop(key, None)


async def _admin_get(
    realm: RealmConfig, settings: Settings, path: str, *, token: str | None = None
) -> httpx.Response:
    caller_token = bool(token)
    token = token or await get_admin_token(realm, settings)
    base, realm_name = _issuer_parts(realm.issuer_url)
    safe_path = _safe_admin_api_path(path)
    url = f"{base}/admin/realms/{realm_name}{safe_path}"

    async def _get(bearer: str) -> httpx.Response:
        async with httpx.AsyncClient(timeout=10.0) as client:
            return await client.get(url, headers={"Authorization": f"Bearer {bearer}"})

    resp = await _get(token)
    if resp.status_code == 401:
        _evict_cached_token(token)
        if not caller_token:
            # Token we minted ourselves: retry once with a fresh one.
            resp = await _get(await get_admin_token(realm, settings))
    return resp


def _safe_admin_api_path(path: str) -> str:
    """Reject traversal / absolute URLs in Keycloak Admin API path suffixes."""
    text = (path or "").strip()
    if not text.startswith("/") or text.startswith("//"):
        raise ValueError("invalid Keycloak admin API path")
    if ".." in text or "://" in text or "\\" in text:
        raise ValueError("invalid Keycloak admin API path")
    return text


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
    caller_token = bool(token)
    token = token or await get_admin_token(realm, settings)
    base, realm_name = _issuer_parts(realm.issuer_url)
    safe_path = _safe_admin_api_path(path)
    url = f"{base}/admin/realms/{realm_name}{safe_path}"

    async def _send(bearer: str) -> httpx.Response:
        async with httpx.AsyncClient(timeout=10.0) as client:
            return await client.request(
                method,
                url,
                json=json,
                headers={"Authorization": f"Bearer {bearer}"},
            )

    try:
        resp = await _send(token)
        if resp.status_code == 401:
            # 401 = rejected at authentication, before the write ran: safe to retry.
            _evict_cached_token(token)
            if not caller_token:
                resp = await _send(await get_admin_token(realm, settings))
        return resp
    except httpx.TimeoutException as exc:
        raise ValueError(
            f"Keycloak injoignable ou timeout lors de l'appel admin ({safe_path})"
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
        raise ValueError(_MSG_KC_USER_ID_MISSING)
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
        raise _admin_failure("Échec logout Keycloak Admin API", resp)
    return {
        "ok": True,
        "keycloak_user_id": uid,
        "realm_slug": realm.slug,
        "residual_note": SSO_LOGOUT_RESIDUAL_NOTE,
    }


async def list_keycloak_user_sessions(
    realm: RealmConfig, keycloak_user_id: str, settings: Settings
) -> list[dict]:
    """GET /users/{id}/sessions — active Keycloak SSO sessions for one user."""
    uid = (keycloak_user_id or "").strip()
    if not uid:
        return []
    resp = await _admin_get(realm, settings, f"/users/{uid}/sessions")
    if resp.status_code == 403:
        raise ValueError(_view_users_error())
    if resp.status_code == 404:
        return []
    if resp.status_code >= 400:
        raise _admin_failure("Échec lecture sessions utilisateur", resp)
    data = resp.json()
    return data if isinstance(data, list) else []


async def delete_keycloak_session(
    realm: RealmConfig, session_id: str, settings: Settings
) -> None:
    """DELETE /sessions/{id} — revoke one Keycloak session."""
    sid = (session_id or "").strip()
    if not sid:
        raise ValueError("Identifiant de session Keycloak manquant")
    token = (
        await get_provision_token(realm, settings)
        if provisioning_configured(realm)
        else None
    )
    resp = await _admin_send(realm, settings, "DELETE", f"/sessions/{sid}", token=token)
    if resp.status_code == 403:
        raise ValueError(_manage_users_error())
    if resp.status_code == 404:
        return
    if resp.status_code >= 400:
        raise _admin_failure("Échec révocation session Keycloak", resp)


async def find_keycloak_user_by_identity(
    realm: RealmConfig,
    identity: str,
    settings: Settings,
) -> dict | None:
    """Exact email/username match in a realm (for self-service forgot password)."""
    ident = (identity or "").strip()
    if not ident:
        return None
    ident_l = ident.lower()
    for attr in ("email", "username"):
        hit = await _exact_user_attr_lookup(
            realm, settings, attr=attr, ident=ident, ident_l=ident_l
        )
        if hit is not None:
            return hit
    candidates = await search_keycloak_users(realm, ident, settings, max_results=5)
    return _first_identity_match(candidates, ident_l)


async def _exact_user_attr_lookup(
    realm: RealmConfig,
    settings: Settings,
    *,
    attr: str,
    ident: str,
    ident_l: str,
) -> dict | None:
    resp = await _admin_get(
        realm, settings, f"/users?{attr}={quote(ident)}&exact=true&max=2"
    )
    if resp.status_code >= 400:
        return None
    data = resp.json()
    if not isinstance(data, list):
        return None
    match = _first_identity_match(data, ident_l)
    if match is not None:
        return match
    if len(data) == 1:
        return data[0]
    return None


def _first_identity_match(users: list, ident_l: str) -> dict | None:
    for user in users:
        email = (user.get("email") or "").strip().lower()
        username = (user.get("username") or "").strip().lower()
        if email == ident_l or username == ident_l:
            return user
    return None


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
        raise _admin_failure("Échec lecture membres du groupe", resp)
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
        raise _admin_failure("Échec comptage utilisateurs", resp)
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
        raise _admin_failure("Échec recherche utilisateurs", resp)
    data = resp.json()
    return data if isinstance(data, list) else []


from app.search_fuzzy import score_query_against_fields


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
    reasonable for typical realms), then rank with SequenceMatcher and
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
            raise _admin_failure("Échec vérification de doublon", resp)
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
        # Admin-entered email is trusted — avoids oauth2-proxy rejecting
        # email_verified=false for newly provisioned users.
        "emailVerified": True,
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
        raise _admin_failure("Échec création utilisateur Keycloak", resp)

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
    email_verified: bool | None = None,
    add_required_actions: list[str] | None = None,
    token: str | None = None,
) -> None:
    """GET + PUT /users/{id} — merge identity fields (WRITE provision account)."""
    uid = (keycloak_user_id or "").strip()
    if not uid:
        raise ValueError(_MSG_KC_USER_ID_MISSING)
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
            raise ValueError(_MSG_KC_USER_NOT_FOUND)
        if resp.status_code >= 400:
            raise _admin_failure("Échec lecture utilisateur Keycloak", resp)
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
    if email_verified is not None:
        payload["emailVerified"] = bool(email_verified)
        if email_verified:
            actions = [
                a
                for a in (payload.get("requiredActions") or [])
                if a != "VERIFY_EMAIL"
            ]
            payload["requiredActions"] = actions
    if add_required_actions:
        actions = [str(a) for a in (payload.get("requiredActions") or []) if a]
        for action in add_required_actions:
            name = (action or "").strip()
            if name and name not in actions:
                actions.append(name)
        payload["requiredActions"] = actions
    # Never re-send credentials blob from a GET (may be incomplete / empty).
    payload.pop("credentials", None)

    resp = await _admin_put(
        realm, settings, f"/users/{uid}", json=payload, token=token
    )
    if resp.status_code == 403:
        raise ValueError(_provision_manage_users_error())
    if resp.status_code == 404:
        raise ValueError(_MSG_KC_USER_NOT_FOUND)
    if resp.status_code == 409:
        raise ValueError("Conflit Keycloak (email déjà utilisé)")
    if resp.status_code >= 400:
        raise _admin_failure("Échec mise à jour Keycloak", resp)


async def reset_keycloak_password(
    realm: RealmConfig,
    settings: Settings,
    *,
    keycloak_user_id: str,
    new_password: str,
    temporary: bool = True,
    token: str | None = None,
) -> None:
    """PUT /users/{id}/reset-password — temporary forces UPDATE_PASSWORD at next login."""
    uid = (keycloak_user_id or "").strip()
    if not uid:
        raise ValueError(_MSG_KC_USER_ID_MISSING)
    if not (new_password or "").strip():
        raise ValueError("Mot de passe requis")
    token = token or await get_manage_users_token(realm, settings)
    payload = {
        "type": "password",
        "value": new_password,
        "temporary": bool(temporary),
    }
    logger.info(
        "keycloak_admin reset_password start realm_slug=%s user_id=%s temporary=%s",
        getattr(realm, "slug", None) or "-",
        uid,
        bool(temporary),
    )
    resp = await _admin_put(
        realm,
        settings,
        f"/users/{uid}/reset-password",
        json=payload,
        token=token,
    )
    body_snip = ""
    if resp.status_code >= 400:
        body_snip = " ".join((resp.text or "").split())[:180]
    logger.info(
        "keycloak_admin reset_password done realm_slug=%s user_id=%s "
        "status=%s temporary=%s body=%s",
        getattr(realm, "slug", None) or "-",
        uid,
        resp.status_code,
        bool(temporary),
        body_snip or "-",
    )
    if resp.status_code == 403:
        raise ValueError(_provision_manage_users_error())
    if resp.status_code == 404:
        raise ValueError(_MSG_KC_USER_NOT_FOUND)
    if resp.status_code >= 400:
        raise _admin_failure("Échec reset mot de passe Keycloak", resp)


async def delete_keycloak_user(
    realm: RealmConfig,
    settings: Settings,
    *,
    keycloak_user_id: str,
    token: str | None = None,
) -> bool:
    """DELETE /users/{id} with the WRITE (provision) service account.

    Returns True when the user was deleted, False when already absent (404 —
    idempotent cleanup). Raises ValueError on any other failure so the caller
    never records a silent partial delete.
    """
    uid = (keycloak_user_id or "").strip()
    if not uid:
        raise ValueError(_MSG_KC_USER_ID_MISSING)
    token = token or await get_provision_token(realm, settings)
    resp = await _admin_send(realm, settings, "DELETE", f"/users/{uid}", token=token)
    if resp.status_code == 404:
        return False
    if resp.status_code == 403:
        raise ValueError(_provision_manage_users_error())
    if resp.status_code >= 400:
        raise _admin_failure("Échec suppression utilisateur Keycloak", resp)
    return True


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
        raise _admin_failure("Échec ajout au groupe Keycloak", resp)


async def remove_user_from_keycloak_group(
    realm: RealmConfig,
    settings: Settings,
    *,
    keycloak_user_id: str,
    keycloak_group_id: str,
    token: str | None = None,
) -> None:
    """DELETE /users/{id}/groups/{group_id} with the WRITE (provision) account."""
    token = token or await get_provision_token(realm, settings)
    resp = await _admin_send(
        realm,
        settings,
        "DELETE",
        f"/users/{keycloak_user_id}/groups/{keycloak_group_id}",
        token=token,
    )
    if resp.status_code == 404:
        return
    if resp.status_code == 403:
        raise ValueError(_provision_manage_users_error())
    if resp.status_code >= 400:
        raise _admin_failure("Échec retrait du groupe Keycloak", resp)


async def delete_keycloak_group(
    realm: RealmConfig,
    settings: Settings,
    *,
    keycloak_group_id: str,
    token: str | None = None,
) -> bool:
    """DELETE /groups/{id} with the WRITE (provision) service account.

    Returns True when the group was deleted, False when already absent (404 —
    idempotent cleanup). Raises ValueError on any other failure.
    """
    gid = (keycloak_group_id or "").strip()
    if not gid:
        raise ValueError("Identifiant groupe Keycloak manquant")
    token = token or await get_provision_token(realm, settings)
    resp = await _admin_send(realm, settings, "DELETE", f"/groups/{gid}", token=token)
    if resp.status_code == 404:
        return False
    if resp.status_code == 403:
        raise ValueError(_provision_manage_users_error())
    if resp.status_code >= 400:
        raise _admin_failure("Échec suppression groupe Keycloak", resp)
    return True


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

    existing = await find_keycloak_group_by_match_key(
        realm, settings, organization=name, token=token
    )
    if existing and existing.get("id"):
        return str(existing["id"])

    resp = await _admin_post(
        realm, settings, "/groups", json={"name": name}, token=token
    )
    if resp.status_code == 403:
        raise ValueError(_provision_manage_users_error())
    if resp.status_code == 409:
        again = await find_keycloak_group_by_match_key(
            realm, settings, organization=name, token=token
        )
        if again and again.get("id"):
            return str(again["id"])
        raise ValueError(f"Groupe Keycloak « {name} » en conflit (409) sans id résolu")
    if resp.status_code >= 400:
        raise _admin_failure("Échec création groupe Keycloak", resp)
    return await _resolve_created_group_id(realm, settings, name=name, resp=resp, token=token)


async def _resolve_created_group_id(
    realm: RealmConfig,
    settings: Settings,
    *,
    name: str,
    resp,
    token: str,
) -> str:
    location = resp.headers.get("location", "")
    group_id = location.rstrip("/").rsplit("/", 1)[-1] if location else ""
    if not group_id:
        again = await find_keycloak_group_by_match_key(
            realm, settings, organization=name, token=token
        )
        group_id = str((again or {}).get("id") or "")
    if not group_id:
        raise ValueError(
            f"Groupe « {name} » créé mais identifiant Keycloak introuvable"
        )
    return group_id


async def find_keycloak_group_by_match_key(
    realm: RealmConfig,
    settings: Settings,
    *,
    organization: str,
    token: str | None = None,
) -> dict | None:
    """Locate a Keycloak group whose name matches the organization key (spaces/_/-)."""
    from app.rbac.organization_names import organization_match_key

    key = organization_match_key(organization)
    if not key:
        return None
    token = token or await get_provision_token(realm, settings)
    groups = await _load_keycloak_groups_list(realm, settings, token=token)
    matches = [
        g
        for g in _flatten_groups(groups)
        if isinstance(g, dict)
        and (
            organization_match_key((g.get("name") or "").strip()) == key
            or organization_match_key((g.get("path") or "").strip()) == key
        )
    ]
    if not matches:
        return None
    return _pick_best_group_match(matches, organization)


async def _load_keycloak_groups_list(
    realm: RealmConfig, settings: Settings, *, token: str
) -> list:
    try:
        return await _fetch_keycloak_groups_with_token(realm, settings, token)
    except ValueError as exc:
        if "query-groups" not in str(exc):
            raise
        # Fall back to sync account (query-groups) when provision lacks it.
        raw = await fetch_keycloak_groups(realm, settings)
        return raw if isinstance(raw, list) else []


def _pick_best_group_match(matches: list[dict], organization: str) -> dict:
    # Prefer exact case-insensitive name, then top-level path.
    want = (organization or "").strip().lower()

    def _score(g: dict) -> tuple[int, int]:
        exact = 1 if (g.get("name") or "").strip().lower() == want else 0
        path = (g.get("path") or "").strip()
        depth = path.count("/") if path else 99
        return (exact, -depth)

    matches.sort(key=_score, reverse=True)
    return matches[0]


async def fetch_user_groups(
    realm: RealmConfig, keycloak_user_id: str, settings: Settings
) -> list[dict]:
    resp = await _admin_get(realm, settings, f"/users/{keycloak_user_id}/groups")
    if resp.status_code == 403:
        raise ValueError(_view_users_error())
    if resp.status_code >= 400:
        raise _admin_failure("Échec lecture groupes utilisateur", resp)
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
        raise _admin_failure("Échec lecture utilisateur", resp)
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
    cache_key = (token_endpoint, client_id, client_secret_encrypted)
    cached = _TOKEN_CACHE.get(cache_key)
    if cached is not None and cached[1] > time.monotonic():
        return cached[0]
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
        facts = {"status": resp.status_code, "url": token_endpoint, "client_id": client_id}
        if body.get("error") == "invalid_client":
            raise KeycloakAdminError(
                "Client ID ou secret du compte de service invalide",
                cause="invalid_client",
                **facts,
            )
        raise KeycloakAdminError(
            f"Échec récupération token admin (HTTP {resp.status_code})",
            cause="token_endpoint_error",
            **facts,
        )
    token = body.get("access_token")
    if not token:
        raise ValueError("Réponse token admin invalide (access_token manquant)")
    try:
        lifetime = float(body.get("expires_in") or 0) - _TOKEN_EXPIRY_MARGIN_SECONDS
    except (TypeError, ValueError):
        lifetime = 0.0
    if lifetime > 0:
        _TOKEN_CACHE[cache_key] = (token, time.monotonic() + lifetime)
    return token


def clear_admin_token_cache() -> None:
    """Forget cached service-account tokens (tests, secret rotation)."""
    _TOKEN_CACHE.clear()


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


def admin_client_configured(realm: RealmConfig) -> bool:
    return bool(
        (realm.keycloak_admin_client_id or "").strip()
        and (realm.keycloak_admin_client_secret_encrypted or "").strip()
    )


def manage_users_configured(realm: RealmConfig) -> bool:
    """Service account that can reset user passwords via Admin API."""
    return provisioning_configured(realm) or admin_client_configured(realm)


async def get_manage_users_token(realm: RealmConfig, settings: Settings) -> str:
    if provisioning_configured(realm):
        return await get_provision_token(realm, settings)
    return await get_admin_token(realm, settings)


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


def _groups_page_query(first: int) -> str:
    return (
        f"briefRepresentation=false&populateHierarchy=false"
        f"&first={int(first)}&max={_GROUPS_PAGE_SIZE}"
    )


async def _get_groups_page(
    client: httpx.AsyncClient, url: str, headers: dict[str, str]
) -> tuple[int, list]:
    resp = await client.get(url, headers=headers)
    data = resp.json() if resp.status_code < 400 else []
    return resp.status_code, data if isinstance(data, list) else []


async def _paginate_group_collection(
    client: httpx.AsyncClient, collection_url: str, headers: dict[str, str]
) -> tuple[int, list[dict]]:
    first = 0
    out: list[dict] = []
    status = 200
    while first < _GROUPS_HARD_CAP:
        status, batch = await _get_groups_page(
            client, f"{collection_url}?{_groups_page_query(first)}", headers
        )
        if status >= 400:
            return status, out
        if not batch:
            break
        out.extend(batch)
        if len(batch) < _GROUPS_PAGE_SIZE:
            break
        first += _GROUPS_PAGE_SIZE
    return status, out


async def _hydrate_group_tree(
    client: httpx.AsyncClient,
    groups_base: str,
    headers: dict[str, str],
    groups: list[dict],
) -> list[dict]:
    """Fill empty subGroups via GET /groups/{id}/children (Keycloak 23+)."""
    sem = asyncio.Semaphore(_MEMBER_REFRESH_CONCURRENCY)

    async def hydrate(group: dict) -> dict:
        if not isinstance(group, dict):
            return {}
        gid = str(group.get("id") or "").strip()
        kids = group.get("subGroups") if isinstance(group.get("subGroups"), list) else []
        if not kids and gid:
            async with sem:
                status, kids = await _paginate_group_collection(
                    client, f"{groups_base}/{quote(gid, safe='')}/children", headers
                )
            if status == 403:
                raise ValueError(_MSG_QUERY_GROUPS)
            if status >= 400:
                kids = []
        filled = await asyncio.gather(*[hydrate(child) for child in kids])
        out = dict(group)
        out["subGroups"] = list(filled)
        return out

    return list(await asyncio.gather(*[hydrate(g) for g in groups]))


async def _fetch_keycloak_groups_with_token(
    realm: RealmConfig, settings: Settings, token: str
) -> list[dict]:
    base, realm_name = _issuer_parts(realm.issuer_url)
    groups_base = f"{base}/admin/realms/{realm_name}/groups"
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=_GROUPS_TREE_TIMEOUT) as client:
        status, roots = await _paginate_group_collection(client, groups_base, headers)
        if status == 403:
            raise KeycloakAdminError(
                _MSG_QUERY_GROUPS,
                cause="missing_role",
                status=403,
                url=groups_base,
                client_id=realm.keycloak_admin_client_id,
            )
        if status == 401:
            # Next sync mints a fresh token instead of reusing the rejected one.
            _evict_cached_token(token)
        if status >= 400:
            raise _admin_error("Échec lecture groupes Keycloak", status, token, groups_base)
        return await _hydrate_group_tree(client, groups_base, headers, roots)


async def fetch_keycloak_groups(realm: RealmConfig, settings: Settings) -> list[dict]:
    token = await get_admin_token(realm, settings)
    return await _fetch_keycloak_groups_with_token(realm, settings, token)


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
    return re_safe.sub(r"[\s_\-]+", "", (value or "").strip().lower())


def group_matches_sync_include(name: str, path: str, include: list[str]) -> bool:
    if not include:
        return True
    name_l = (name or "").strip().lower()
    path_l = (path or "").strip().lower()
    name_n = _norm_group_token(name_l)
    path_n = _norm_group_token(path_l)
    path_base = path_l.rsplit("/", 1)[-1] if path_l else ""
    path_base_n = _norm_group_token(path_base)
    return any(
        _include_rule_matches(
            rule,
            name_l=name_l,
            path_l=path_l,
            name_n=name_n,
            path_n=path_n,
            path_base_n=path_base_n,
        )
        for rule in include
    )


def _include_rule_matches(
    rule: str,
    *,
    name_l: str,
    path_l: str,
    name_n: str,
    path_n: str,
    path_base_n: str,
) -> bool:
    r = rule.strip().lower()
    if not r:
        return False
    r_n = _norm_group_token(r)
    if name_l == r or path_l == r or name_n == r_n or path_n == r_n or path_base_n == r_n:
        return True
    # Path prefix: "/Societes" matches "/Societes/ABIOM"
    if path_l.startswith(r.rstrip("/") + "/") or path_l.rstrip("/") == r.rstrip("/"):
        return True
    # Normalized prefix on path segments
    return bool(r_n and path_n.startswith(r_n))


async def sync_keycloak_groups(realm: RealmConfig, db: Session, settings: Settings) -> dict:
    if not realm.groups_sync_enabled:
        raise ValueError(
            "Import des groupes non activé pour ce realm. "
            "Configurez le compte de service dans la fiche realm."
        )

    try:
        raw = await fetch_keycloak_groups(realm, settings)
    except httpx.RequestError as exc:  # timeouts included
        raise KeycloakAdminError(
            f"Keycloak injoignable depuis le serveur : {exc or type(exc).__name__}",
            cause="unreachable",
            url=realm.issuer_url,
            client_id=realm.keycloak_admin_client_id,
        ) from exc

    groups = _flatten_groups(raw if isinstance(raw, list) else [])
    fetched = len(groups)
    include = parse_groups_sync_include(getattr(realm, "groups_sync_include", None))
    now = utcnow()
    imported = 0
    updated = 0
    skipped = 0
    members_refreshed = 0
    members_total = 0
    # Always refresh member counts so list/filter coherence matches Keycloak.
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
                realm_slug=realm.slug,
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
            if (existing.realm_slug or "") != (realm.slug or ""):
                existing.realm_slug = realm.slug
                changed = True
            existing.synced_at = now
            if changed:
                updated += 1
        synced_rows.append(existing)

    db.flush()

    rows_to_refresh = [row for row in synced_rows if row.keycloak_group_id]
    members_failed = 0
    members_error: str | None = None
    if rows_to_refresh:
        sem = asyncio.Semaphore(_MEMBER_REFRESH_CONCURRENCY)

        async def _refresh_one(row: RBACGroup) -> tuple[RBACGroup, int | None, str | None]:
            async with sem:
                try:
                    members = await fetch_group_members(
                        realm, row.keycloak_group_id, settings
                    )
                    return row, len(members), None
                except ValueError as exc:  # Admin API answer: one summary line below
                    return row, None, str(exc)
                except Exception as exc:
                    logger.exception(
                        "Failed to refresh members for group %s (%s)",
                        row.name,
                        row.keycloak_group_id,
                    )
                    return row, None, type(exc).__name__

        results = await asyncio.gather(*[_refresh_one(r) for r in rows_to_refresh])
        for row, count, error in results:
            if count is None:
                members_failed += 1
                members_error = members_error or error
                continue
            row.member_count = count
            members_refreshed += 1
            members_total += count
        if members_failed:
            logger.warning(
                "Keycloak member counts not refreshed realm=%s client=%s "
                "failed=%d/%d first_error=%s",
                realm.slug,
                realm.keycloak_admin_client_id,
                members_failed,
                len(rows_to_refresh),
                members_error,
            )

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
        "fetched": fetched,
        "imported": imported,
        "updated": updated,
        "orphaned": orphaned,
        "skipped": skipped,
        "members_refreshed": members_refreshed,
        "members_total": members_total,
        "members_failed": members_failed,
        "members_error": members_error,
        "synced_at": now.isoformat(),
    }

