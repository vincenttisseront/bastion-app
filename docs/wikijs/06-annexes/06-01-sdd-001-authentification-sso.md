> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/sdd/SDD-001-authentification-sso.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# SDD-001 â€” Authentification SSO

| Attribut | Valeur |
|----------|--------|
| **Statut** | AcceptÃ© |
| **Date** | 2026-06-17 |
| **PÃ©rimÃ¨tre** | Flux utilisateur, admin, logout, break-glass, identitÃ© FastAPI |
| **HÃ´te** | `portal.ar-systems.fr` (`vmdmz-reverse01`) |

---

## 1. Contexte

Le portail combine Nginx (`auth_request`), FastAPI (identitÃ© et RBAC) et oauth2-proxy (session OIDC Keycloak). Des itÃ©rations antÃ©rieures ont introduit plusieurs chemins parallÃ¨les (core `:4180`, legacy `:4181`, core-admin `:4190`), provoquant 403 CSRF, 500 Nginx et cookies incohÃ©rents.

Cette SDD fige le modÃ¨le **unique** validÃ© en production.

---

## 2. DÃ©cision

**Un seul flux dâ€™authentification** pour le catalogue, lâ€™admin et le proxy transparent :

```
Navigateur â†’ Nginx auth_request /portal_auth_check
          â†’ FastAPI GET /internal/oauth2-auth
          â†’ oauth2-proxy GET /oauth2/auth (realm ar-systems, :4180)
          â†’ 200 (session) ou 401 (login)
```

Lâ€™admin (`/admin`, `/api/admin`) utilise **le mÃªme** `auth_request` et la **mÃªme** session SSO que lâ€™accueil. La distinction admin se fait **uniquement** dans FastAPI via `require_admin`.

---

## 3. Invariants

### 3.1 Nginx â†’ FastAPI (`auth_request`)

| RÃ¨gle | DÃ©tail |
|-------|--------|
| **MUST** | Sous-requÃªte interne `location = /portal_auth_check` |
| **MUST** | Upstream `GET /internal/oauth2-auth` sur `127.0.0.1:8000` |
| **MUST** | Header `X-Portal-Internal-Token` alignÃ© entre `.env` et snippet Nginx |
| **MUST** | `error_page 401 = @portal_oauth2_signin` sur routes protÃ©gÃ©es catalogue/admin |
| **MUST NOT** | `auth_request /portal_core_auth_check` ou upstream direct `:4190` |
| **MUST NOT** | Retourner autre chose que 200/401 depuis `/internal/oauth2-auth` |

### 3.2 FastAPI `/internal/oauth2-auth`

| Condition | Code HTTP |
|-----------|-----------|
| Session oauth2 valide | **200** + headers `X-Auth-Request-*` |
| Session absente / invalide | **401** |
| Jeton interne Nginx invalide ou absent | **401** |
| oauth2-proxy injoignable | **401** |
| oauth2-proxy rÃ©pond 400/403/5xx | **401** (normalisÃ©) |
| Exception non gÃ©rÃ©e | **401** |

ImplÃ©mentation : `_oauth2_upstream_to_auth_request_response()` dans `main.py`.

### 3.3 IdentitÃ© applicative

| RÃ¨gle | DÃ©tail |
|-------|--------|
| **MUST** | IdentitÃ© via headers Nginx : `X-Email`, `X-Groups`, `X-Preferred-Username`, `X-Portal-Realm-Slug` |
| **MUST** | Admin = intersection groupes Keycloak avec `portal_admin_groups` (dÃ©faut `portal-admins`) ou `local_admins` ou break-glass |
| **MUST** | Utilisateur authentifiÃ© non-admin sur `/admin` â†’ **403** JSON (pas de redirect SSO) |
| **MUST NOT** | Faire confiance aux headers `X-*` sans `X-Portal-Internal-Token` valide depuis Nginx |

### 3.4 Redirection login

| RÃ¨gle | DÃ©tail |
|-------|--------|
| **MUST** | `@portal_oauth2_signin` â†’ `302 /oauth2/ar-systems/start?rd=$portal_oauth2_rd_safe` |
| **MUST** | `rd` toujours **relatif** (map `portal_oauth2_rd_safe`) |
| **MUST NOT** | `/oauth2/core/start` ni chemin hors slug realm |

### 3.5 Break-glass

| RÃ¨gle | DÃ©tail |
|-------|--------|
| **MUST** | Route `/breakglass` sans `auth_request`, LAN RFC1918 uniquement |
| **MUST** | Cookie `portal_breakglass_token` (JWT) validÃ© cÃ´tÃ© FastAPI |
| **MAY** | Nginx accorde `auth_request` 200 sur **prÃ©sence** du cookie (validation JWT cÃ´tÃ© app) |

### 3.6 Proxy transparent `/proxy/{slug}/` â€” DÃ‰PRÃ‰CIÃ‰ (juillet 2026)

RetirÃ© du dÃ©pÃ´t `awx-playbook` (`e56fa58`). Voir [SSO_PORTAL_BASTION_FEATURES_INVENTORY.md](../SSO_PORTAL_BASTION_FEATURES_INVENTORY.md).

| RÃ¨gle | DÃ©tail |
|-------|--------|
| ~~**MUST**~~ | ~~`auth_request /portal_proxy_resolve`~~ â€” **retirÃ©** |
| ~~**MUST**~~ | ~~Erreurs backend confinÃ©es au bloc proxy~~ â€” N/A |
---

## 4. Routes publiques (sans SSO Nginx)

Ces chemins **MUST NOT** avoir `auth_request` :

- `/health`, `/api/health`
- `/static/*`, `/favicon.ico`
- `/auth/*` (entrÃ©e SSO FastAPI)
- `/breakglass` (restriction IP sÃ©parÃ©e)
- `/oauth2/ar-systems/*`, `/oauth2/static/*` (proxy oauth2-proxy)
- Realms secondaires exportÃ©s (`clients`, etc.) â€” proxy direct uniquement

---

## 5. Fichiers de rÃ©fÃ©rence

| Fichier | RÃ´le |
|---------|------|
| `files/portal/app/main.py` | `/internal/oauth2-auth`, routes admin |
| `files/portal/app/auth.py` | `get_user_context`, `require_admin` |
| `files/portal/app/breakglass.py` | JWT break-glass |
| `files/portal/app/subdomain_auth.py` | Auth RBAC subdomain *(templates nginx hors repo)* |
| `templates/snippets/proxy_portal_admin_location.conf.j2` | Bloc admin Nginx |
| `files/nginx-portal-proxy.map.conf` | Maps `portal_oauth2_rd_safe` |

---

## 6. Validation

Voir [auth-test-plan.md](../auth-test-plan.md) sections 2, 4, 5.

ContrÃ´les minimaux post-dÃ©ploiement :

```bash
# Sans session â†’ 302 login (pas 500)
curl -sk -o /dev/null -w '%{http_code}\n' \
  https://portal.ar-systems.fr/admin --resolve portal.ar-systems.fr:443:127.0.0.1

# oauth2-auth direct â†’ 401 uniquement
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "X-Portal-Internal-Token: $(grep ^PORTAL_INTERNAL_TOKEN /opt/sso-portal/.env | cut -d= -f2-)" \
  http://127.0.0.1:8000/internal/oauth2-auth
```

