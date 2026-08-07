> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/bff-oidc-native-session.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# BFF OIDC â€” session native bastion (`bastion_session`)

> Livrable V1 (portail seul) â€” 2026-08. Le navigateur **ne parle jamais Ã  Keycloak** :
> le bastion exÃ©cute un authorization-code + PKCE en headless (rÃ©seau interne),
> puis Ã©met un JWT cookie `bastion_session` rÃ©vocable via `OidcSession.jti`.

## DÃ©cisions retenues

| # | Point | DÃ©cision |
|---|---|---|
| 1 | Flow IdP | Authorization code + PKCE S256 **cÃ´tÃ© serveur** (`app/oidc_bff_client.py`) |
| 2 | Session portail | Cookie JWT HS256 `bastion_session` + table `oidc_sessions` (denylist `jti`) |
| 3 | Cohabitation | oauth2-proxy (`_oauth2_proxy` / cookies realm) **reste actif** ; dual-accept sur `/internal/oauth2-auth` |
| 4 | Feature flag | **Par realm** : `RealmConfig.oidc_native_session_enabled` (Admin UI) + CSV env optionnel |
| 5 | MFA / required action | **OTP TOTP** en 2 POST headless (`OidcLoginAttempt`) ; WebAuthn / required-action â†’ `UnsupportedAuthFlowError` + audit |
| 6 | Sous-domaines | **Hors V1** â€” `/internal/subdomain-auth` inchangÃ© (V2 sÃ©parÃ©e) |
| 7 | Realm pilote | **Pas** `ar-systems` en premier â€” realm secondaire / faible trafic (voir Â§ Rollout) |

## Hors pÃ©rimÃ¨tre (V1)

- `/internal/subdomain-auth` et applications derriÃ¨re nginx subdomain SSO
- Remplacement / extinction dâ€™oauth2-proxy
- MFA / WebAuthn / required actions Keycloak dans le BFF
- Rotation anti-replay de `bastion_session` (pattern break-glass `chain_id`) â€” non livrÃ© en V1

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
    |                               |  GET  â€¦/auth  (PKCE S256)         |
    |                               |--------------------------------->|
    |                               |  HTML kc-form-login               |
    |                               |<---------------------------------|
    |                               |  POST action (user/pass)         |
    |                               |--------------------------------->|
    |                               |  302 Location ?code=&state=      |
    |                               |  (follow_redirects=False)        |
    |                               |<---------------------------------|
    |                               |  POST â€¦/token (code+verifier)    |
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

### Points dâ€™entrÃ©e code

| Ã‰lÃ©ment | Emplacement |
|---------|-------------|
| Client headless Keycloak | `app/oidc_bff_client.py` â†’ `perform_headless_login` |
| Config BFF par realm | `app/oidc_bff_config_service.py` (Fernet) |
| Login / logout / validate | `app/oidc_bff.py` |
| Dual-accept portal | `app/auth.py` â†’ `/internal/oauth2-auth` |
| Gate par realm | `app/oidc_native_session.py` |
| Toggle Admin | `POST /admin/realms/{id}/oidc-native-session/enable\|disable` |
| UI login | `GET /login` (+ `/auth/login`) â€” `app/templates/auth/login.html` |
| ModÃ¨le + migrations | `OidcSession` (`052`), flag realm (`053`), colonnes BFF (`054_oidc_bff_realm_config`) |
| Settings | `app/sso_settings.py` (`OIDC_NATIVE_SESSION_ENABLED_REALMS` CSV + cookie/JWT TTL) |
| Tests E2E / pilote | `tests/test_oidc_native_e2e.py`, `tests/test_oidc_native_session_realm.py` |

### Comportement login HTML vs API

- Formulaire HTML envoie `rd` â†’ succÃ¨s = **302** vers `rd` (dÃ©faut `/apps`) + cookie ; Ã©chec = re-render avec Â« Identifiants invalides. Â»
- POST sans `rd` (clients API / tests) â†’ JSON `{"status":"ok",â€¦}` ou **401** / **429**
- Rate-limit process-local : 5 Ã©checs / 60 s (IP + username) â€” `OIDC_LOGIN_MAX_FAILURES`

### Audit

| Action | Quand |
|--------|-------|
| `oidc_login_success` | Session Ã©mise (`username` / `realm` / `jti` / `sub` â€” **jamais** password ni tokens) |
| `oidc_login_failed` | Credentials / erreur BFF |
| `oidc_login_unsupported_flow` | MFA / required-action Keycloak â€” **filtre admin** (dÃ©tail technique dans `details`, UI user gÃ©nÃ©rique) |
| `oidc_login_otp_required` / `_otp_success` / `_otp_failed` | Ã‰tape TOTP (jamais le code OTP en clair) |
| `oidc_logout` | RÃ©vocation `jti` + clear cookie |
| `realm.oidc_native_session_enabled` / `_disabled` | Toggle Admin par realm |
| `realm.oidc_bff_config_set` | Enregistrement config BFF (pas de secret en clair dans `details`) |

---

## Deux mÃ©canismes de session (cohabitation)

```
                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                    â”‚     /internal/oauth2-auth (portail) â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                      â”‚
                    cookie bastion_session prÃ©sent ?
                         â”‚                      â”‚
                        oui                    non
                         â”‚                      â”‚
              JWT valide + jti non rÃ©voquÃ© ?    â”‚
                         â”‚                      â”‚
              realm du JWT pilote-enabled ?     â”‚
                    â”‚            â”‚              â”‚
                  oui          non              â”‚
                    â”‚            â”‚              â”‚
                 200 +           â””â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”˜
                 X-Auth-Request-*       â”‚
                                        â–¼
                        cookie oauth2-proxy â†’ GET proxy/oauth2/auth
                                   â”‚
                              200/202 OK â”€â”€â–º 200 + headers proxy
                                   â”‚
                                 sinon
                                   â–¼
                        cookie bg_session â†’ break-glass (inchangÃ©)
                                   â”‚
                                 sinon â†’ 401
```

| Famille | Cookie | Source de vÃ©ritÃ© | RÃ©vocation | Qui Ã©met |
|---------|--------|------------------|------------|----------|
| **A â€” SSO legacy** | `_oauth2_proxy` / cookies realm | oauth2-proxy | rotate `cookie_secret` / logout IdP | oauth2-proxy (navigateur â†’ Keycloak) |
| **B â€” break-glass** | `bg_session` | JWT + `breakglass_sessions` | `jti` / chaÃ®ne | bastion (compte local) |
| **N â€” native OIDC (V1)** | `bastion_session` | JWT + `oidc_sessions` | `jti` (`POST /auth/logout`) | bastion BFF headless |

Pendant la transition : le bouton SSO Keycloak reste pour le realm **dÃ©faut** tant quâ€™il nâ€™est pas pilote-ON ; le formulaire natif apparaÃ®t pour le (premier) realm pilote activÃ©.

---

## Activation par realm

| Source | PrioritÃ© | Comment |
|--------|----------|---------|
| Admin â†’ Realms â†’ **OIDC natif ON/OFF** | Principale | Colonne `realm_configs.oidc_native_session_enabled` ; audit `realm.oidc_native_session_*` |
| Env `OIDC_NATIVE_SESSION_ENABLED_REALMS` | Bootstrap ops | CSV de slugs (ex. `pilot-clients`) â€” utile avant/ sans UI ; **OR** avec le flag DB |

Gate runtime : `is_oidc_native_session_enabled_for_realm()` (`app/oidc_native_session.py`).

### Realm pilote recommandÃ©

**Ne pas dÃ©marrer par `ar-systems`** (dÃ©faut / fort trafic). Choisir un realm :

1. dÃ©jÃ  prÃ©sent dans Admin â†’ Realms, **non dÃ©faut**, faible volume de logins, utilisateurs internes volontaires ; **ou**
2. un realm Keycloak dÃ©diÃ© `pilot-oidc` / sandbox, miroir bastion, comptes de test sans MFA.

CritÃ¨res : Standard Flow OK, pas de required-action forcÃ©e au login, URL Keycloak **interne** joignable depuis bastion (configurÃ©e dans Admin â†’ Realms â†’ Client OIDC BFF).  
Sur `/login` : bouton SSO (dÃ©faut) + formulaire natif (pilote) coexistent.

---

## Configuration BFF par realm (base SQLite)

Source de vÃ©ritÃ© : colonnes `RealmConfig` (pas de variables dâ€™env client BFF).

| Champ | Stockage | Notes |
|-------|----------|-------|
| `oidc_keycloak_base_url` | clair | Base URL interne Keycloak pour **ce** realm |
| `oidc_bff_client_id` | clair | Client confidentiel headless |
| `oidc_bff_client_secret_encrypted` | Fernet | MÃªme clÃ© que les credentials (`PORTAL_SECRET_ENCRYPTION_KEY` / vault Fernet) |
| `oidc_bff_redirect_uri` | clair | URI enregistrÃ©e cÃ´tÃ© Keycloak ; jamais suivie par le navigateur |
| `oidc_native_session_enabled` | bool | Toggle pilote (Admin liste Realms) |

API service : `get_oidc_bff_config` / `set_oidc_bff_config` (`app/oidc_bff_config_service.py`).  
Si le realm est pilote-ON mais la config BFF est incomplÃ¨te â†’ **`POST /auth/login` rÃ©pond 503** (Â« OIDC natif non configurÃ©â€¦ Â») â€” **aucun** fallback silencieux vers une valeur par dÃ©faut.

### UI Admin â†’ Realms

Sur le formulaire realm (section **Client OIDC BFF**) :

- URL Keycloak interne, client ID, client secret (**Ã©criture seule** / masquÃ©, jamais rÃ©affichÃ©), redirect URI
- Bouton **Tester la connexion** â†’ `GET {base}/realms/{slug}/.well-known/openid-configuration` (ping discovery, sans login)

### Secret JWT session (global, pas par realm)

Le HMAC `bastion_session` reste **portal-global** (comme le pattern historique `OIDC_SESSION_JWT_SECRET`) :

1. Env `OIDC_SESSION_JWT_SECRET` si dÃ©fini
2. Sinon `PortalSettings.oidc_session_jwt_secret_encrypted` (Fernet, gÃ©nÃ©rable via `generate_oidc_session_jwt_secret`)
3. Sinon secret auto process (`Settings` validator)

Ne **pas** dupliquer ce secret par realm.

---

## Variables de configuration (env)

Via env / AWX Extra Vars â†’ `app/sso_settings.py`.  
**Ne jamais** coller les secrets session / Fernet dans les cfg oauth2 gÃ©nÃ©rÃ©s sous `exports/` (miroirs).

| Variable | DÃ©faut | RÃ´le |
|----------|--------|------|
| `OIDC_NATIVE_SESSION_ENABLED_REALMS` | `""` | CSV de slugs pilotes (complÃ©ment au toggle Admin) |
| `OIDC_SESSION_JWT_SECRET` | auto (si vide / collision BG/vault) | HMAC HS256 du JWT `bastion_session` â€” **distinct** de `BREAKGLASS_JWT_SECRET` et du token vault |
| `OIDC_SESSION_COOKIE_NAME` | `bastion_session` | Nom du cookie |
| `OIDC_SESSION_MAX_AGE` | `43200` (12 h) | TTL cookie + `exp` JWT |
| `SSO_PORTAL_DEFAULT_REALM_SLUG` | `ar-systems` | Realm utilisÃ© si le formulaire nâ€™envoie pas `realm` |
| `PORTAL_SECRET_ENCRYPTION_KEY` / vault Fernet | â€” | Chiffrement des secrets BFF en base |

~~`OIDC_KEYCLOAK_INTERNAL_BASE_URL` / `OIDC_BFF_CLIENT_ID` / `OIDC_BFF_CLIENT_SECRET` / `OIDC_BFF_REDIRECT_URI`~~ â€” **retirÃ©es** ; configurer via Admin â†’ Realms.

### Client Keycloak attendu (V1)

- Type : **confidential**
- Standard flow : oui ; Direct Access Grants : **non** (ROPC non utilisÃ©)
- Redirect URI : exactement celle saisie dans Admin (ex. `https://portalâ€¦/.bastion/oidc/callback`)
- PKCE : S256 (imposÃ© cÃ´tÃ© bastion)
- RÃ©seau : joignable depuis le conteneur/process bastion via lâ€™URL interne du realm
- CrÃ©er / vÃ©rifier dâ€™abord **uniquement** sur le realm pilote

---

## ProcÃ©dure de bascule progressive

1. **PrÃ©parer** (checklist) â€” migrations `052`+`053`+`054`, config BFF Admin sur le **seul** realm pilote, client Keycloak â€” **sans** activer le toggle.
2. DÃ©ployer le code ; `/login` = bouton SSO uniquement tant quâ€™aucun realm nâ€™est pilote-ON.
3. Admin â†’ Realms â†’ renseigner **Client OIDC BFF** + **Tester la connexion** ; puis **OIDC natif ON** sur le realm pilote (ou CSV temporaire) â€” **pas** `ar-systems`.
4. Smoke :
   - `/login` â†’ SSO (dÃ©faut) + formulaire natif (pilote)
   - Login test pilote â†’ `bastion_session` â†’ `/apps` OK via `/internal/oauth2-auth`
   - Admin â†’ Logs â†’ `oidc_login_success` (realm = pilote)
   - Forcer un user MFA â†’ `oidc_login_unsupported_flow` visible (pas un silence)
5. **Observation** : **2 semaines** ou **â‰¥ 50** `oidc_login_success` sur le pilote (le premier atteint gagne) ; surveiller `oidc_login_failed` / `oidc_login_unsupported_flow` ; TTL vs `OIDC_SESSION_MAX_AGE`.
6. GÃ©nÃ©raliser : activer dâ€™autres realms un par un ; `ar-systems` en dernier.
7. Rollback : **OIDC natif OFF** sur le realm (Admin) â€” immÃ©diat, sans redÃ©ploiement ; cookies `bastion_session` de ce realm sont ignorÃ©s (fallthrough oauth2-proxy).

---

## Checklist rollout prod

### PrÃ©-requis infra

- [ ] Migration Alembic **`052_oidc_sessions`** appliquÃ©e
- [ ] Migration Alembic **`053_oidc_native_session_realm`** appliquÃ©e
- [ ] Migration Alembic **`054_oidc_bff_realm_config`** appliquÃ©e
- [ ] Table `oidc_sessions` + colonnes BFF / flag sur `realm_configs`
- [ ] Bastion joignable Keycloak en **interne** (URL saisie dans Admin BFF)

### Secrets

- [ ] Fernet portal configurÃ© (`PORTAL_SECRET_ENCRYPTION_KEY` / vault)
- [ ] GÃ©nÃ©rer `OIDC_SESSION_JWT_SECRET` (ou via `generate_oidc_session_jwt_secret` â†’ PortalSettings) â€” **â‰ ** break-glass / vault token
- [ ] Admin â†’ Realms â†’ client ID + secret BFF + redirect URI **par realm pilote** (secret Ã©criture seule)
- [ ] VÃ©rifier absence des secrets dans logs / `exports/` / rÃ©ponses API

### Keycloak (avant activation)

- [ ] Client confidentiel crÃ©Ã© **sur le realm pilote uniquement**
- [ ] Redirect URI exacte ; Standard flow ON ; Direct grants OFF
- [ ] Compte(s) de test **sans MFA** pour le smoke initial
- [ ] Bouton Admin **Tester la connexion** (discovery) â†’ OK

### Activation pilote

- [ ] DÃ©ployer le build (BFF + migrations)
- [ ] Choisir le realm pilote (â‰  `ar-systems`)
- [ ] Config BFF enregistrÃ©e + discovery OK
- [ ] Admin â†’ Realms â†’ **OIDC natif ON** (vÃ©rifier audit `realm.oidc_native_session_enabled`)
- [ ] Smoke formulaire + `/internal/oauth2-auth` + logs `oidc_login_*`
- [ ] Confirmer quâ€™un realm non listÃ© reste 100 % oauth2-proxy
- [ ] PÃ©riode dâ€™observation (2 semaines / 50 logins) avant gÃ©nÃ©ralisation

### Non-rÃ©gression attendue (V1)

- [ ] Break-glass LAN inchangÃ©
- [ ] `/internal/subdomain-auth` **non modifiÃ©**
- [ ] Bypass RFC1918 portail toujours dÃ©sactivÃ© sur `/internal/oauth2-auth`

---

## Liens

- Client headless : `app/oidc_bff_client.py`
- Config BFF DB : `app/oidc_bff_config_service.py`
- Routes session : `app/oidc_bff.py`
- Auth request portail : `app/auth.py`
- Politique cookie oauth2 (legacy) : `docs/oauth2-cookie-secret-policy.md`
- OIDC realm SQLite (issuer / client portal oauth2-proxy) : Admin â†’ Realms â€” **distinct** du client BFF headless
- Tests : `tests/test_oidc_bff_client.py`, `tests/test_oidc_bff.py`, `tests/test_oidc_native_e2e.py`, `tests/test_native_login_page.py`

