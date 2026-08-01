# BFF OIDC — session native bastion (`bastion_session`)

> Livrable V1 (portail seul) — 2026-08. Le navigateur **ne parle jamais à Keycloak** :
> le bastion exécute un authorization-code + PKCE en headless (réseau interne),
> puis émet un JWT cookie `bastion_session` révocable via `OidcSession.jti`.

## Décisions retenues

| # | Point | Décision |
|---|---|---|
| 1 | Flow IdP | Authorization code + PKCE S256 **côté serveur** (`app/oidc_bff_client.py`) |
| 2 | Session portail | Cookie JWT HS256 `bastion_session` + table `oidc_sessions` (denylist `jti`) |
| 3 | Cohabitation | oauth2-proxy (`_oauth2_proxy` / cookies realm) **reste actif** ; dual-accept sur `/internal/oauth2-auth` |
| 4 | Feature flag | **Par realm** : `RealmConfig.oidc_native_session_enabled` (Admin UI) + CSV env optionnel |
| 5 | MFA / required action | **OTP TOTP** en 2 POST headless (`OidcLoginAttempt`) ; WebAuthn / required-action → `UnsupportedAuthFlowError` + audit |
| 6 | Sous-domaines | **Hors V1** — `/internal/subdomain-auth` inchangé (V2 séparée) |
| 7 | Realm pilote | **Pas** `ar-systems` en premier — realm secondaire / faible trafic (voir § Rollout) |

## Hors périmètre (V1)

- `/internal/subdomain-auth` et applications derrière nginx subdomain SSO
- Remplacement / extinction d’oauth2-proxy
- MFA / WebAuthn / required actions Keycloak dans le BFF
- Rotation anti-replay de `bastion_session` (pattern break-glass `chain_id`) — non livré en V1

---

## Architecture du flow

```
Navigateur                    Bastion (FastAPI)                 Keycloak (interne)
    |                               |                                  |
    |  GET /login                  |                                  |
    |  (formulaire natif)           |                                  |
    |------------------------------>|                                  |
    |                               |                                  |
    |  POST /auth/login             |                                  |
    |  username + password (+ rd)   |                                  |
    |------------------------------>|                                  |
    |                               |  GET  …/auth  (PKCE S256)         |
    |                               |--------------------------------->|
    |                               |  HTML kc-form-login               |
    |                               |<---------------------------------|
    |                               |  POST action (user/pass)         |
    |                               |--------------------------------->|
    |                               |  302 Location ?code=&state=      |
    |                               |  (follow_redirects=False)        |
    |                               |<---------------------------------|
    |                               |  POST …/token (code+verifier)    |
    |                               |--------------------------------->|
    |                               |  access / refresh / id_token     |
    |                               |<---------------------------------|
    |                               |                                  |
    |                               |  INSERT oidc_sessions (jti)      |
    |                               |  JWT type=oidc + Set-Cookie      |
    |  302 rd (ou JSON si API)      |                                  |
    |<------------------------------|                                  |
    |                               |                                  |
    |  GET /apps (nginx auth_request)|                                 |
    |------------------------------>|  GET /internal/oauth2-auth       |
    |                               |  1) bastion_session si realm du JWT pilote-ON |
    |                               |  2) sinon oauth2-proxy /oauth2/auth
    |                               |  3) sinon break-glass            |
    |  200 + X-Auth-Request-*       |                                  |
    |<------------------------------|                                  |
```

### Points d’entrée code

| Élément | Emplacement |
|---------|-------------|
| Client headless Keycloak | `app/oidc_bff_client.py` → `perform_headless_login` |
| Config BFF par realm | `app/oidc_bff_config_service.py` (Fernet) |
| Login / logout / validate | `app/oidc_bff.py` |
| Dual-accept portal | `app/auth.py` → `/internal/oauth2-auth` |
| Gate par realm | `app/oidc_native_session.py` |
| Toggle Admin | `POST /admin/realms/{id}/oidc-native-session/enable\|disable` |
| UI login | `GET /login` (+ `/auth/login`) — `app/templates/auth/login.html` |
| Modèle + migrations | `OidcSession` (`052`), flag realm (`053`), colonnes BFF (`054_oidc_bff_realm_config`) |
| Settings | `app/sso_settings.py` (`OIDC_NATIVE_SESSION_ENABLED_REALMS` CSV + cookie/JWT TTL) |
| Tests E2E / pilote | `tests/test_oidc_native_e2e.py`, `tests/test_oidc_native_session_realm.py` |

### Comportement login HTML vs API

- Formulaire HTML envoie `rd` → succès = **302** vers `rd` (défaut `/apps`) + cookie ; échec = re-render avec « Identifiants invalides. »
- POST sans `rd` (clients API / tests) → JSON `{"status":"ok",…}` ou **401** / **429**
- Rate-limit process-local : 5 échecs / 60 s (IP + username) — `OIDC_LOGIN_MAX_FAILURES`

### Audit

| Action | Quand |
|--------|-------|
| `oidc_login_success` | Session émise (`username` / `realm` / `jti` / `sub` — **jamais** password ni tokens) |
| `oidc_login_failed` | Credentials / erreur BFF |
| `oidc_login_unsupported_flow` | MFA / required-action Keycloak — **filtre admin** (détail technique dans `details`, UI user générique) |
| `oidc_login_otp_required` / `_otp_success` / `_otp_failed` | Étape TOTP (jamais le code OTP en clair) |
| `oidc_logout` | Révocation `jti` + clear cookie |
| `realm.oidc_native_session_enabled` / `_disabled` | Toggle Admin par realm |
| `realm.oidc_bff_config_set` | Enregistrement config BFF (pas de secret en clair dans `details`) |

---

## Deux mécanismes de session (cohabitation)

```
                    ┌─────────────────────────────────────┐
                    │     /internal/oauth2-auth (portail) │
                    └─────────────────────────────────────┘
                                      │
                    cookie bastion_session présent ?
                         │                      │
                        oui                    non
                         │                      │
              JWT valide + jti non révoqué ?    │
                         │                      │
              realm du JWT pilote-enabled ?     │
                    │            │              │
                  oui          non              │
                    │            │              │
                 200 +           └──────┬───────┘
                 X-Auth-Request-*       │
                                        ▼
                        cookie oauth2-proxy → GET proxy/oauth2/auth
                                   │
                              200/202 OK ──► 200 + headers proxy
                                   │
                                 sinon
                                   ▼
                        cookie bg_session → break-glass (inchangé)
                                   │
                                 sinon → 401
```

| Famille | Cookie | Source de vérité | Révocation | Qui émet |
|---------|--------|------------------|------------|----------|
| **A — SSO legacy** | `_oauth2_proxy` / cookies realm | oauth2-proxy | rotate `cookie_secret` / logout IdP | oauth2-proxy (navigateur → Keycloak) |
| **B — break-glass** | `bg_session` | JWT + `breakglass_sessions` | `jti` / chaîne | bastion (compte local) |
| **N — native OIDC (V1)** | `bastion_session` | JWT + `oidc_sessions` | `jti` (`POST /auth/logout`) | bastion BFF headless |

Pendant la transition : le bouton SSO Keycloak reste pour le realm **défaut** tant qu’il n’est pas pilote-ON ; le formulaire natif apparaît pour le (premier) realm pilote activé.

---

## Activation par realm

| Source | Priorité | Comment |
|--------|----------|---------|
| Admin → Realms → **OIDC natif ON/OFF** | Principale | Colonne `realm_configs.oidc_native_session_enabled` ; audit `realm.oidc_native_session_*` |
| Env `OIDC_NATIVE_SESSION_ENABLED_REALMS` | Bootstrap ops | CSV de slugs (ex. `pilot-clients`) — utile avant/ sans UI ; **OR** avec le flag DB |

Gate runtime : `is_oidc_native_session_enabled_for_realm()` (`app/oidc_native_session.py`).

### Realm pilote recommandé

**Ne pas démarrer par `ar-systems`** (défaut / fort trafic). Choisir un realm :

1. déjà présent dans Admin → Realms, **non défaut**, faible volume de logins, utilisateurs internes volontaires ; **ou**
2. un realm Keycloak dédié `pilot-oidc` / sandbox, miroir bastion, comptes de test sans MFA.

Critères : Standard Flow OK, pas de required-action forcée au login, URL Keycloak **interne** joignable depuis bastion (configurée dans Admin → Realms → Client OIDC BFF).  
Sur `/login` : bouton SSO (défaut) + formulaire natif (pilote) coexistent.

---

## Configuration BFF par realm (base SQLite)

Source de vérité : colonnes `RealmConfig` (pas de variables d’env client BFF).

| Champ | Stockage | Notes |
|-------|----------|-------|
| `oidc_keycloak_base_url` | clair | Base URL interne Keycloak pour **ce** realm |
| `oidc_bff_client_id` | clair | Client confidentiel headless |
| `oidc_bff_client_secret_encrypted` | Fernet | Même clé que les credentials (`PORTAL_SECRET_ENCRYPTION_KEY` / vault Fernet) |
| `oidc_bff_redirect_uri` | clair | URI enregistrée côté Keycloak ; jamais suivie par le navigateur |
| `oidc_native_session_enabled` | bool | Toggle pilote (Admin liste Realms) |

API service : `get_oidc_bff_config` / `set_oidc_bff_config` (`app/oidc_bff_config_service.py`).  
Si le realm est pilote-ON mais la config BFF est incomplète → **`POST /auth/login` répond 503** (« OIDC natif non configuré… ») — **aucun** fallback silencieux vers une valeur par défaut.

### UI Admin → Realms

Sur le formulaire realm (section **Client OIDC BFF**) :

- URL Keycloak interne, client ID, client secret (**écriture seule** / masqué, jamais réaffiché), redirect URI
- Bouton **Tester la connexion** → `GET {base}/realms/{slug}/.well-known/openid-configuration` (ping discovery, sans login)

### Secret JWT session (global, pas par realm)

Le HMAC `bastion_session` reste **portal-global** (comme le pattern historique `OIDC_SESSION_JWT_SECRET`) :

1. Env `OIDC_SESSION_JWT_SECRET` si défini
2. Sinon `PortalSettings.oidc_session_jwt_secret_encrypted` (Fernet, générable via `generate_oidc_session_jwt_secret`)
3. Sinon secret auto process (`Settings` validator)

Ne **pas** dupliquer ce secret par realm.

---

## Variables de configuration (env)

Via env / AWX Extra Vars → `app/sso_settings.py`.  
**Ne jamais** coller les secrets session / Fernet dans les cfg oauth2 générés sous `exports/` (miroirs).

| Variable | Défaut | Rôle |
|----------|--------|------|
| `OIDC_NATIVE_SESSION_ENABLED_REALMS` | `""` | CSV de slugs pilotes (complément au toggle Admin) |
| `OIDC_SESSION_JWT_SECRET` | auto (si vide / collision BG/vault) | HMAC HS256 du JWT `bastion_session` — **distinct** de `BREAKGLASS_JWT_SECRET` et du token vault |
| `OIDC_SESSION_COOKIE_NAME` | `bastion_session` | Nom du cookie |
| `OIDC_SESSION_MAX_AGE` | `43200` (12 h) | TTL cookie + `exp` JWT |
| `SSO_PORTAL_DEFAULT_REALM_SLUG` | `ar-systems` | Realm utilisé si le formulaire n’envoie pas `realm` |
| `PORTAL_SECRET_ENCRYPTION_KEY` / vault Fernet | — | Chiffrement des secrets BFF en base |

~~`OIDC_KEYCLOAK_INTERNAL_BASE_URL` / `OIDC_BFF_CLIENT_ID` / `OIDC_BFF_CLIENT_SECRET` / `OIDC_BFF_REDIRECT_URI`~~ — **retirées** ; configurer via Admin → Realms.

### Client Keycloak attendu (V1)

- Type : **confidential**
- Standard flow : oui ; Direct Access Grants : **non** (ROPC non utilisé)
- Redirect URI : exactement celle saisie dans Admin (ex. `https://portal…/.bastion/oidc/callback`)
- PKCE : S256 (imposé côté bastion)
- Réseau : joignable depuis le conteneur/process bastion via l’URL interne du realm
- Créer / vérifier d’abord **uniquement** sur le realm pilote

---

## Procédure de bascule progressive

1. **Préparer** (checklist) — migrations `052`+`053`+`054`, config BFF Admin sur le **seul** realm pilote, client Keycloak — **sans** activer le toggle.
2. Déployer le code ; `/login` = bouton SSO uniquement tant qu’aucun realm n’est pilote-ON.
3. Admin → Realms → renseigner **Client OIDC BFF** + **Tester la connexion** ; puis **OIDC natif ON** sur le realm pilote (ou CSV temporaire) — **pas** `ar-systems`.
4. Smoke :
   - `/login` → SSO (défaut) + formulaire natif (pilote)
   - Login test pilote → `bastion_session` → `/apps` OK via `/internal/oauth2-auth`
   - Admin → Logs → `oidc_login_success` (realm = pilote)
   - Forcer un user MFA → `oidc_login_unsupported_flow` visible (pas un silence)
5. **Observation** : **2 semaines** ou **≥ 50** `oidc_login_success` sur le pilote (le premier atteint gagne) ; surveiller `oidc_login_failed` / `oidc_login_unsupported_flow` ; TTL vs `OIDC_SESSION_MAX_AGE`.
6. Généraliser : activer d’autres realms un par un ; `ar-systems` en dernier.
7. Rollback : **OIDC natif OFF** sur le realm (Admin) — immédiat, sans redéploiement ; cookies `bastion_session` de ce realm sont ignorés (fallthrough oauth2-proxy).

---

## Checklist rollout prod

### Pré-requis infra

- [ ] Migration Alembic **`052_oidc_sessions`** appliquée
- [ ] Migration Alembic **`053_oidc_native_session_realm`** appliquée
- [ ] Migration Alembic **`054_oidc_bff_realm_config`** appliquée
- [ ] Table `oidc_sessions` + colonnes BFF / flag sur `realm_configs`
- [ ] Bastion joignable Keycloak en **interne** (URL saisie dans Admin BFF)

### Secrets

- [ ] Fernet portal configuré (`PORTAL_SECRET_ENCRYPTION_KEY` / vault)
- [ ] Générer `OIDC_SESSION_JWT_SECRET` (ou via `generate_oidc_session_jwt_secret` → PortalSettings) — **≠** break-glass / vault token
- [ ] Admin → Realms → client ID + secret BFF + redirect URI **par realm pilote** (secret écriture seule)
- [ ] Vérifier absence des secrets dans logs / `exports/` / réponses API

### Keycloak (avant activation)

- [ ] Client confidentiel créé **sur le realm pilote uniquement**
- [ ] Redirect URI exacte ; Standard flow ON ; Direct grants OFF
- [ ] Compte(s) de test **sans MFA** pour le smoke initial
- [ ] Bouton Admin **Tester la connexion** (discovery) → OK

### Activation pilote

- [ ] Déployer le build (BFF + migrations)
- [ ] Choisir le realm pilote (≠ `ar-systems`)
- [ ] Config BFF enregistrée + discovery OK
- [ ] Admin → Realms → **OIDC natif ON** (vérifier audit `realm.oidc_native_session_enabled`)
- [ ] Smoke formulaire + `/internal/oauth2-auth` + logs `oidc_login_*`
- [ ] Confirmer qu’un realm non listé reste 100 % oauth2-proxy
- [ ] Période d’observation (2 semaines / 50 logins) avant généralisation

### Non-régression attendue (V1)

- [ ] Break-glass LAN inchangé
- [ ] `/internal/subdomain-auth` **non modifié**
- [ ] Bypass RFC1918 portail toujours désactivé sur `/internal/oauth2-auth`

---

## Liens

- Client headless : `app/oidc_bff_client.py`
- Config BFF DB : `app/oidc_bff_config_service.py`
- Routes session : `app/oidc_bff.py`
- Auth request portail : `app/auth.py`
- Politique cookie oauth2 (legacy) : `docs/oauth2-cookie-secret-policy.md`
- OIDC realm SQLite (issuer / client portal oauth2-proxy) : Admin → Realms — **distinct** du client BFF headless
- Tests : `tests/test_oidc_bff_client.py`, `tests/test_oidc_bff.py`, `tests/test_oidc_native_e2e.py`, `tests/test_native_login_page.py`
