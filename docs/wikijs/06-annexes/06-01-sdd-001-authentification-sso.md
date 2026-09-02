> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d'origine :** docs/sdd/SDD-001-authentification-sso.md — garder les deux synchronisés (voir docs/wikijs/MAINTENANCE.md).

---
# SDD-001 — Authentification SSO

| Attribut | Valeur |
|----------|--------|
| **Statut** | Accepté |
| **Date** | 2026-06-17 |
| **Périmètre** | Flux utilisateur, admin, logout, break-glass, identité FastAPI |
| **Hôte** | `portal.ar-systems.fr` (`vmdmz-reverse01`) |

---

## 1. Contexte

Le portail combine Nginx (`auth_request`), FastAPI (identité et RBAC) et oauth2-proxy (session OIDC Keycloak). Des itérations antérieures ont introduit plusieurs chemins parallèles (core `:4180`, legacy `:4181`, core-admin `:4190`), provoquant 403 CSRF, 500 Nginx et cookies incohérents.

Cette SDD fige le modèle **unique** validé en production.

---

## 2. Décision

**Un seul flux d’authentification** pour le catalogue, l’admin et le proxy transparent :

```
Navigateur → Nginx auth_request /portal_auth_check
          → FastAPI GET /internal/oauth2-auth
          → oauth2-proxy GET /oauth2/auth (realm ar-systems, :4180)
          → 200 (session) ou 401 (login)
```

L’admin (`/admin`, `/api/admin`) utilise **le même** `auth_request` et la **même** session SSO que l’accueil. La distinction admin se fait **uniquement** dans FastAPI via `require_admin`.

---

## 3. Invariants

### 3.1 Nginx → FastAPI (`auth_request`)

| Règle | Détail |
|-------|--------|
| **MUST** | Sous-requête interne `location = /portal_auth_check` |
| **MUST** | Upstream `GET /internal/oauth2-auth` sur `127.0.0.1:8000` |
| **MUST** | Header `X-Portal-Internal-Token` aligné entre `.env` et snippet Nginx |
| **MUST** | `error_page 401 = @portal_oauth2_signin` sur routes protégées catalogue/admin |
| **MUST NOT** | `auth_request /portal_core_auth_check` ou upstream direct `:4190` |
| **MUST NOT** | Retourner autre chose que 200/401 depuis `/internal/oauth2-auth` |

### 3.2 FastAPI `/internal/oauth2-auth`

| Condition | Code HTTP |
|-----------|-----------|
| Session oauth2 valide | **200** + headers `X-Auth-Request-*` |
| Session absente / invalide | **401** |
| Jeton interne Nginx invalide ou absent | **401** |
| oauth2-proxy injoignable | **401** |
| oauth2-proxy répond 400/403/5xx | **401** (normalisé) |
| Exception non gérée | **401** |

Implémentation : `_oauth2_upstream_to_auth_request_response()` dans `main.py`.

### 3.3 Identité applicative

| Règle | Détail |
|-------|--------|
| **MUST** | Identité via headers Nginx : `X-Email`, `X-Groups`, `X-Preferred-Username`, `X-Portal-Realm-Slug` |
| **MUST** | Admin = intersection groupes Keycloak avec `portal_admin_groups` (défaut `portal-admins`) ou `local_admins` ou break-glass |
| **MUST** | Utilisateur authentifié non-admin sur `/admin` → **302 `/apps`** en navigation HTML ; **403** JSON si client API (`Accept: application/json`) |
| **MUST NOT** | Faire confiance aux headers `X-*` sans `X-Portal-Internal-Token` valide depuis Nginx |

### 3.4 Redirection login

| Règle | Détail |
|-------|--------|
| **MUST** | `@portal_oauth2_signin` → `302 /oauth2/ar-systems/start?rd=$portal_oauth2_rd_safe` |
| **MUST** | `rd` toujours **relatif** (map `portal_oauth2_rd_safe`) |
| **MUST NOT** | `/oauth2/core/start` ni chemin hors slug realm |

### 3.5 Break-glass

| Règle | Détail |
|-------|--------|
| **MUST** | Route `/breakglass` sans `auth_request`, LAN RFC1918 uniquement |
| **MUST** | Cookie `portal_breakglass_token` (JWT) validé côté FastAPI |
| **MAY** | Nginx accorde `auth_request` 200 sur **présence** du cookie (validation JWT côté app) |

### 3.6 Proxy transparent `/proxy/{slug}/` — DÉPRÉCIÉ (juillet 2026)

Retiré du dépôt `awx-playbook` (`e56fa58`). Voir [SSO_PORTAL_BASTION_FEATURES_INVENTORY.md](../SSO_PORTAL_BASTION_FEATURES_INVENTORY.md).

| Règle | Détail |
|-------|--------|
| ~~**MUST**~~ | ~~`auth_request /portal_proxy_resolve`~~ — **retiré** |
| ~~**MUST**~~ | ~~Erreurs backend confinées au bloc proxy~~ — N/A |
---

## 4. Routes publiques (sans SSO Nginx)

Ces chemins **MUST NOT** avoir `auth_request` :

- `/health`, `/api/health`
- `/static/*`, `/favicon.ico`
- `/auth/*` (entrée SSO FastAPI)
- `/breakglass` (restriction IP séparée)
- `/oauth2/ar-systems/*`, `/oauth2/static/*` (proxy oauth2-proxy)
- Realms secondaires exportés (`clients`, etc.) — proxy direct uniquement

---

## 5. Fichiers de référence

| Fichier | Rôle |
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

Contrôles minimaux post-déploiement :

```bash
# Sans session → 302 login (pas 500)
curl -sk -o /dev/null -w '%{http_code}\n' \
  https://portal.ar-systems.fr/admin --resolve portal.ar-systems.fr:443:127.0.0.1

# oauth2-auth direct → 401 uniquement
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "X-Portal-Internal-Token: $(grep ^PORTAL_INTERNAL_TOKEN /opt/sso-portal/.env | cut -d= -f2-)" \
  http://127.0.0.1:8000/internal/oauth2-auth
```
