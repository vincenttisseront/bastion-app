> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d'origine :** docs/sdd/SDD-002-nginx-vhost-portail.md — garder les deux synchronisés (voir docs/wikijs/MAINTENANCE.md).

---
# SDD-002 — Vhost Nginx portail

| Attribut | Valeur |
|----------|--------|
| **Statut** | Accepté — **proxy `/proxy/` et subdomain retirés du dépôt** (juillet 2026, `e56fa58`) |
| **Date** | 2026-06-17 (mise à jour 2026-07-10) |
| **Périmètre** | `vhost_sso_portal.conf`, snippets, maps, exports |
| **Fichier prod** | `/etc/nginx/conf.d/vhost_sso_portal.conf` |
| **Playbook** | `linux_sso_portal.yml` uniquement (hors `linux_nginx_dmz.yml`) |

---

## 1. Contexte

Nginx est le point d’entrée TLS et le garde SSO. Une configuration obsolète sur le serveur (bloc `portal_core_auth_check` → `:4190`) a causé des **500** sur `/admin` alors que `/` fonctionnait — preuve que le vhost doit être **généré uniquement par Ansible** et conforme à cette SDD.

---

## 2. Décision

Un **vhost unique** `portal.ar-systems.fr` avec :

- locations publiques en `^~` (priorité sur `location /`)
- un seul point d’auth interne : `/portal_auth_check`
- inclusion conditionnelle du bloc core-admin **désactivée** (`oauth2_core_admin_enabled: false`)
- export realms dynamique **sans** dupliquer `ar-systems` ni les assets oauth2 statiques

---

## 3. Locations normatives

### 3.1 Internes (non exposées client)

| Location | Rôle |
|----------|------|
| `= /portal_auth_check` | Sous-requête auth catalogue + admin |
| `= /portal_proxy_resolve` | ~~Sous-requête auth proxy transparent~~ — **retiré** (`e56fa58`) |
| `@portal_oauth2_signin` | Redirect 302 vers `/oauth2/ar-systems/start` |
| `@portal_logout_anonymous` | Redirect 302 `/` si logout sans session |

**MUST NOT exister en prod :**

- `= /portal_core_auth_check`
- `@portal_core_oauth2_signin`
- `location ~ ^/oauth2/core/`

### 3.2 Protégées (`auth_request /portal_auth_check`)

| Location | Notes |
|----------|-------|
| `location /` | Catalogue portail |
| `^~ /admin` | + `X-Frame-Options: DENY` |
| `^~ /api/admin` | API admin JSON |
| `= /logout` | `error_page 401 = @portal_logout_anonymous` |

Chaque bloc **MUST** contenir **exactement une** directive `auth_request /portal_auth_check`.

### 3.3 Publiques (pas d’auth_request)

| Location | Upstream |
|----------|----------|
| `= /health`, `= /api/health` | FastAPI `:8000` |
| `^~ /static/` | FastAPI `:8000` |
| `= /favicon.ico` | Alias fichier statique |
| `^~ /auth/` | FastAPI `:8000` |
| `^~ /breakglass` | FastAPI `:8000` + allow LAN |
| `~ ^/oauth2/ar-systems/` | oauth2-proxy **:4180** |
| `^~ /oauth2/static/` | oauth2-proxy **:4180** |
| `~ ^/oauth2/{autre-realm}/` | Port du realm (export) |

### 3.4 Proxy transparent — **DÉPRÉCIÉ dans awx-playbook**

| Location | Auth | Statut |
|----------|------|--------|
| `~ ^/proxy/{slug}/` | `auth_request /portal_proxy_resolve` | **Retiré** — ne plus déployer depuis ce dépôt |
| `= /portal_proxy_resolve` | Sous-requête resolve | **Retiré** du template `nginx-portal.conf.j2` |

Les sections historiques proxy/subdomain sont documentées dans [SSO_PORTAL_BASTION_FEATURES_INVENTORY.md](../SSO_PORTAL_BASTION_FEATURES_INVENTORY.md) pour reprise dans le dépôt applicatif.

---

## 4. Snippets Ansible (obligatoires)

| Snippet | Rôle |
|---------|------|
| `proxy_portal_trusted_internal.conf` | `X-Portal-Internal-Token` Nginx → FastAPI |
| `proxy_portal_strip_identity.conf` | Supprime headers `X-User`/`X-Email` entrants |
| `proxy_portal_forwarded.conf` | `X-Forwarded-*`, `X-Real-IP` |
| `proxy_portal_fastapi.conf` | Timeouts, buffers proxy FastAPI |

**MUST** : `portal_auth_check` inclut `proxy_portal_trusted_internal.conf`.

**MUST** : jeton identique entre `/opt/sso-portal/.env` (`PORTAL_INTERNAL_TOKEN`) et le snippet.

---

## 5. Maps (`files/nginx-portal-proxy.map.conf`)

| Map | Rôle |
|-----|------|
| `portal_oauth2_rd` | `rd` relatif ; `/` → `%2F` |
| `portal_oauth2_rd_safe` | Filet si `rd` vide |
| `portal_x_auth_source` | Source auth (sso, break-glass, rfc1918) |

**MUST NOT** : autoriser `rd` en URL absolue vers oauth2-proxy (400).

---

## 6. Export dynamique

Fichier : `/var/lib/sso-portal/exports/nginx-portal-realms.conf`

| Règle | Détail |
|-------|--------|
| **MUST** | Généré par `render_nginx_realms_fragment()` |
| **MUST** | Sauter le realm `ar-systems` si `oauth2_core_static_enabled` (Ansible gère `:4180`) |
| **MUST NOT** | Réintroduire `ar-systems` sur `:4181` via apply-infrastructure |
| **MUST NOT** | Dupliquer `/oauth2/static/` dans l’export |

---

## 7. Déploiement

| Règle | Détail |
|-------|--------|
| **MUST** | Vhost déployé par AWX (`linux_sso_portal.yml`) depuis `templates/nginx-portal.conf.j2` |
| **MUST** | `nginx -t` avant reload ; backup vhost avant remplacement (tâches Ansible) |
| **MUST NOT** | Patcher manuellement le vhost en prod sans reporter le changement dans le template |
| **SHOULD** | `systemctl restart nginx` après changement majeur auth (workers) |

---

## 8. Validation

```bash
# Aucune référence core-admin
sudo grep -rn 'portal_core\|4190\|oauth2/core' /etc/nginx/conf.d/ /etc/nginx/snippets/ \
  || echo "OK"

# Un seul auth_request par bloc admin
sudo awk '/location \^~ \/admin/,/^    }/' /etc/nginx/conf.d/vhost_sso_portal.conf | grep auth_request

# Sans session → 302 (pas 500)
curl -sk -o /dev/null -w '%{http_code}\n' \
  https://portal.ar-systems.fr/admin --resolve portal.ar-systems.fr:443:127.0.0.1
```

Voir [auth-test-plan.md](../auth-test-plan.md) sections 2, 3, 7.
