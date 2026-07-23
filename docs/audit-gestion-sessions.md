# Audit — Gestion des sessions (suivi)

> Document de suivi issu de l'audit du 2026-07-23 (`audit-gestion-sessions`).
> Ne remplace pas le Pod source ; enregistre l'état d'implémentation dans `bastion-app`.

## §9 — Ordre d'implémentation

| # | Point | Statut |
|---|---|---|
| 1 | Enforce AccessGrant sur auth_request subdomain | **Corrigé** (2026-07-23) |
| 2 | Cookie oauth2 12h/1h + alignement Keycloak `ssoSessionMaxLifespan` | **Outil de vérif. livré** — valeurs prod à confirmer via Admin |
| 3 | Révocation break-glass (jti + denylist) | **Corrigé** (2026-07-23) |
| 4 | Révoquer toutes les sessions app + logout Keycloak (par utilisateur) | **Corrigé** (2026-07-23) |
| 5 | Vue `/sessions` enrichie | Partiel (jti BREAKGLASS + revoke via registre + bouton déconnexion) |
| 6 | TTL break-glass configurable + idle | Idle 30 min fait ; durée absolue encore hardcodée |

---

## §8 / Point 4 — Révoquer toutes les sessions (app + SSO) par utilisateur

| Date | Statut | Résumé |
|------|--------|--------|
| 2026-07-23 | **Corrigé** | `revoke-all` robotic/vault + Keycloak Admin logout + bouton combiné (hors break-glass). |

### Implémentation réelle

- **(a) App** : `POST /admin/users/{identity}/sessions/revoke-all` — réutilise `revoke_active_session` pour chaque session `kind=app` active ; audit consolidé `sessions.revoke_all_app` avec liste révoquées / échecs (pas d’arrêt sur la première erreur).
- **(b) SSO** : `POST /admin/users/{identity}/sessions/revoke-sso` — `POST /admin/realms/{realm}/users/{id}/logout` via `get_admin_token()` ; rôle requis **`realm-management:manage-users`** (documenté dans `docs/rbac-enforcement-audit.md` §7).
- **Combiné** : `POST /admin/users/{identity}/sessions/disconnect` — (a) puis (b), réponses séparées `app_sessions` / `sso` (jamais un statut global trompeur).
- **UI** : bouton « Déconnecter cet utilisateur » sur fiche RBAC utilisateurs et `/sessions` — résultats détaillés des deux leviers ; break-glass hors périmètre.
- **Délai résiduel SSO** : après logout Admin API, le cookie oauth2-proxy local peut rester valide jusqu’au prochain **`cookie_refresh` (≈ 1 h)** ou une revalidation active — documenté dans l’UI et `SSO_LOGOUT_RESIDUAL_NOTE` (pas de coupure portail instantanée annoncée).
- **Tests** : `pytest -k "revoke_all or keycloak_logout"`

---

## §8 / Point 3 — Révocation individuelle break-glass (jti)

| Date | Statut | Résumé |
|------|--------|--------|
| 2026-07-23 | **Corrigé** | Claim `jti` + table `breakglass_sessions` (denylist). JWT reste la source d'identité/exp. |

### Implémentation réelle

- **Modèle** : `BreakGlassSession` (`jti` unique, username, issued/expires, revoked*) — migration `022_breakglass_sessions`
- **Émission** : `issue_breakglass_token()` au login API + page `/breakglass` — écrit la ligne + JWT
- **Validation** : `validate_breakglass_cookie(..., db=)` rejette `jti` manquant (legacy) et `revoked=True`
- **API** : `GET /api/admin/breakglass/sessions`, `POST /api/admin/breakglass/sessions/{jti}/revoke` + audit `breakglass_session_revoked`
- **UI** : `/sessions` stocke `jti` dans `details` ; « Révoquer » sur une ligne BREAKGLASS appelle aussi la denylist
- **Purge** : `purge_expired_breakglass_sessions` (rétention **7 jours** après `expires_at`) branchée sur `expire_stale_sessions`
- **Tests** : `pytest -k breakglass` (dont revoke → 401 immédiat sur `/internal/oauth2-auth`)

---

## §6.2 / §8 — AccessGrant ↔ session active (proxy / subdomain)

| Date | Statut | Résumé |
|------|--------|--------|
| 2026-07-23 | **Confirmé** (gap) | `/internal/subdomain-auth` et `/internal/oauth2-auth` ne vérifiaient que la session, pas le grant applicatif. |
| 2026-07-23 | **Corrigé** | Enforcement `AccessGrant` `launch+` sur `/internal/subdomain-auth` via `get_effective_apps_for_user` / `user_can_launch_application`. Refus → **403** + audit `access_denied_no_grant`. |

### Implémentation réelle

- **Fichier** : `app/subdomain/subdomain_auth.py`
- **Helper** : `user_can_launch_application()` dans `app/rbac/effective_access_service.py`
- **`/internal/oauth2-auth`** : **inchangé** pour les grants — protège uniquement le portail (`/apps`, `/dashboard`) ; tout utilisateur authentifié doit y accéder. Docstring explicite dans `app/auth.py`.
- **Proxy legacy `/proxy/{slug}/`** : pas de second handler FastAPI ; redirections Nginx vers subdomain (voir `app/proxy/proxy_service.py`). L'enforcement est donc celui de `subdomain-auth`.
- **Break-glass** : accès total aux apps subdomain **sans** AccessGrant (secours admin IdP down) — commenté dans le code.
- **RFC1918 bypass** : inchangé (200 sans identité → pas de contrôle grant).
- **Tests** : `tests/test_subdomain_auth_access_grant.py` (grant launch → 200 ; sans grant / view-only / grant révoqué + cookie encore valide → 403 ; break-glass → 200 ; portail oauth2-auth sans grant → OK).

### Effet attendu en prod

Retirer un `AccessGrant` coupe l'accès direct par URL **immédiatement** (prochaine requête `auth_request`), sans attendre l'expiration du cookie oauth2-proxy.

---

## §8 / Point 2 — Cookie oauth2-proxy 12h/1h vs Keycloak SSO lifespan

### Cible

| Paramètre | Valeur cible |
|---|---|
| `cookie_expire` (oauth2-proxy) | `12h` |
| `cookie_refresh` (oauth2-proxy) | `1h` |
| `ssoSessionMaxLifespan` (Keycloak) | **≤ 43200 s (12h)** |
| `ssoSessionIdleTimeout` | Documenté (souvent 30 min) — refresh horaire le maintient actif tant que l’utilisateur revient |

### Confirmé dans le code / générateur (2026-07-23)

| Source | `cookie_expire` | `cookie_refresh` |
|---|---|---|
| `generate_oauth2_proxy_config()` | `12h` | `1h` |
| `docker/oauth2-core/oauth2-proxy.cfg.example` | `12h` | `1h` |
| Smoke Ansible (post apply-infra) | exige `12h` / `1h` sur cfg core | idem |

**Keycloak as-code** : aucune définition de `ssoSessionMaxLifespan` dans ce repo (`bastion-app`). Toute correction IdP = **Admin Console Keycloak** (ou pipeline Keycloak externe s’il existe hors de ce dépôt). Realm `AR-SYSTEMS` est **partagé** (federation AD) — ne pas baisser le max lifespan sans valider l’impact hors portail.

### Outil de vérification prod

- UI : **Admin → Realms → Alignement sessions SSO** (`/admin/realms/session-alignment`)
- JSON : `GET /api/admin/realms/session-alignment`
- Lit : fichier export `exports/oauth2/{slug}/oauth2-proxy.cfg` (+ miroir core) **et** Keycloak Admin API (`ssoSessionMaxLifespan`, idle, client session max).
- Prérequis : compte de service realm avec **`view-realm`** (en plus de `view-users` / `query-groups` ; et **`manage-users`** pour le logout Admin API du point 4).

### Tableau de conformité (à remplir après apply + ouverture de la page)

> Remplir en prod via `/admin/realms/session-alignment` (copier les colonnes). État au moment de la livraison outil : **non lu depuis cet environnement de dev** (pas d’accès SSH/Keycloak Admin depuis le poste agent).

| realm | cookie_expire déployé | cookie_refresh déployé | ssoSessionMaxLifespan | ssoSessionIdleTimeout | cohérent ? |
|---|---|---|---|---|---|
| `ar-systems` (core) | *à lire en prod* | *à lire en prod* | *à lire en prod* | *à lire en prod* | *oui/non* |
| *(autres realms activés)* | … | … | … | … | … |

### Corrections / méthode (Tâche 3)

| Si… | Alors… | Méthode |
|---|---|---|
| Export sans `12h`/`1h` | Admin → Realms → Apply infrastructure (+ apply-infra-docker) | Pipeline bastion (DB = source de vérité) |
| `ssoSessionMaxLifespan` > 12h | Baisser à ≤ 43200 **uniquement** si aucun autre usage du realm ne l’exige ; sinon documenter le compromis ou realm dédié bastion | Admin Console Keycloak (pas as-code dans ce repo) |
| Compte service sans `view-realm` | Ajouter le rôle realm-management | Console Keycloak |

### Test bout en bout (Tâche 4) — procédure

1. **Non-prod / realm de test** : réduire temporairement à `cookie_expire=5m` / `cookie_refresh=2m` + max lifespan Keycloak ≤ 5m — **ne pas** le faire sur `AR-SYSTEMS` prod.
2. Prod (observational) : login → activité après > 1h → pas de redirect `/auth/login` (refresh silencieux).
3. Prod : attendre échéance max (ou session idle Keycloak) → redirect login propre, **pas** 500/502 nginx/oauth2.

Statut test E2E au 2026-07-23 : **non exécuté** depuis l’agent (pas d’accès prod longue durée).

---

## Email OIDC manquant (Hervé vs Vincent) — 2026-07-23

| Cause possible | Diagnostic | Correctif |
|---|---|---|
| `emailVerified=false` + oauth2-proxy sans flag | Admin → RBAC → Utilisateur → badge emailVerified | `insecure_oidc_allow_unverified_email` (export) + **apply infra** |
| Champ Email vide dans Keycloak/AD | Même écran : warning « Pas d'email dans Keycloak » | Remplir Email (ou mapper LDAP `mail` / `userPrincipalName`) |
| Claim absent malgré Email KC | Fallback runtime bastion | `resolve_user_email()` (Admin API) sur `/apps`, `/profile`, `open-with-identity` |

Comparer Hervé et Vincent sur **Admin → RBAC → Utilisateurs** : Email + emailVerified doivent être équivalents si les fiches Keycloak le sont. Preuve `/sessions` : Vincent a l’UPN, Hervé avait le short name — bug portail (X-Email vide), pas Keycloak fiche AD.
