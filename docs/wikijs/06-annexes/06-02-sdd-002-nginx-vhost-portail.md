> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/sdd/SDD-002-nginx-vhost-portail.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# SDD-002 â€” Vhost Nginx portail

| Attribut | Valeur |
|----------|--------|
| **Statut** | AcceptÃ© â€” **proxy `/proxy/` et subdomain retirÃ©s du dÃ©pÃ´t** (juillet 2026, `e56fa58`) |
| **Date** | 2026-06-17 (mise Ã  jour 2026-07-10) |
| **PÃ©rimÃ¨tre** | `vhost_sso_portal.conf`, snippets, maps, exports |
| **Fichier prod** | `/etc/nginx/conf.d/vhost_sso_portal.conf` |
| **Playbook** | `linux_sso_portal.yml` uniquement (hors `linux_nginx_dmz.yml`) |

---

## 1. Contexte

Nginx est le point dâ€™entrÃ©e TLS et le garde SSO. Une configuration obsolÃ¨te sur le serveur (bloc `portal_core_auth_check` â†’ `:4190`) a causÃ© des **500** sur `/admin` alors que `/` fonctionnait â€” preuve que le vhost doit Ãªtre **gÃ©nÃ©rÃ© uniquement par Ansible** et conforme Ã  cette SDD.

---

## 2. DÃ©cision

Un **vhost unique** `portal.ar-systems.fr` avec :

- locations publiques en `^~` (prioritÃ© sur `location /`)
- un seul point dâ€™auth interne : `/portal_auth_check`
- inclusion conditionnelle du bloc core-admin **dÃ©sactivÃ©e** (`oauth2_core_admin_enabled: false`)
- export realms dynamique **sans** dupliquer `ar-systems` ni les assets oauth2 statiques

---

## 3. Locations normatives

### 3.1 Internes (non exposÃ©es client)

| Location | RÃ´le |
|----------|------|
| `= /portal_auth_check` | Sous-requÃªte auth catalogue + admin |
| `= /portal_proxy_resolve` | ~~Sous-requÃªte auth proxy transparent~~ â€” **retirÃ©** (`e56fa58`) |
| `@portal_oauth2_signin` | Redirect 302 vers `/oauth2/ar-systems/start` |
| `@portal_logout_anonymous` | Redirect 302 `/` si logout sans session |

**MUST NOT exister en prod :**

- `= /portal_core_auth_check`
- `@portal_core_oauth2_signin`
- `location ~ ^/oauth2/core/`

### 3.2 ProtÃ©gÃ©es (`auth_request /portal_auth_check`)

| Location | Notes |
|----------|-------|
| `location /` | Catalogue portail |
| `^~ /admin` | + `X-Frame-Options: DENY` |
| `^~ /api/admin` | API admin JSON |
| `= /logout` | `error_page 401 = @portal_logout_anonymous` |

Chaque bloc **MUST** contenir **exactement une** directive `auth_request /portal_auth_check`.

### 3.3 Publiques (pas dâ€™auth_request)

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

### 3.4 Proxy transparent â€” **DÃ‰PRÃ‰CIÃ‰ dans awx-playbook**

| Location | Auth | Statut |
|----------|------|--------|
| `~ ^/proxy/{slug}/` | `auth_request /portal_proxy_resolve` | **RetirÃ©** â€” ne plus dÃ©ployer depuis ce dÃ©pÃ´t |
| `= /portal_proxy_resolve` | Sous-requÃªte resolve | **RetirÃ©** du template `nginx-portal.conf.j2` |

Les sections historiques proxy/subdomain sont documentÃ©es dans [SSO_PORTAL_BASTION_FEATURES_INVENTORY.md](../SSO_PORTAL_BASTION_FEATURES_INVENTORY.md) pour reprise dans le dÃ©pÃ´t applicatif.

---

## 4. Snippets Ansible (obligatoires)

| Snippet | RÃ´le |
|---------|------|
| `proxy_portal_trusted_internal.conf` | `X-Portal-Internal-Token` Nginx â†’ FastAPI |
| `proxy_portal_strip_identity.conf` | Supprime headers `X-User`/`X-Email` entrants |
| `proxy_portal_forwarded.conf` | `X-Forwarded-*`, `X-Real-IP` |
| `proxy_portal_fastapi.conf` | Timeouts, buffers proxy FastAPI |

**MUST** : `portal_auth_check` inclut `proxy_portal_trusted_internal.conf`.

**MUST** : jeton identique entre `/opt/sso-portal/.env` (`PORTAL_INTERNAL_TOKEN`) et le snippet.

---

## 5. Maps (`files/nginx-portal-proxy.map.conf`)

| Map | RÃ´le |
|-----|------|
| `portal_oauth2_rd` | `rd` relatif ; `/` â†’ `%2F` |
| `portal_oauth2_rd_safe` | Filet si `rd` vide |
| `portal_x_auth_source` | Source auth (sso, break-glass, rfc1918) |

**MUST NOT** : autoriser `rd` en URL absolue vers oauth2-proxy (400).

---

## 6. Export dynamique

Fichier : `/var/lib/sso-portal/exports/nginx-portal-realms.conf`

| RÃ¨gle | DÃ©tail |
|-------|--------|
| **MUST** | GÃ©nÃ©rÃ© par `render_nginx_realms_fragment()` |
| **MUST** | Sauter le realm `ar-systems` si `oauth2_core_static_enabled` (Ansible gÃ¨re `:4180`) |
| **MUST NOT** | RÃ©introduire `ar-systems` sur `:4181` via apply-infrastructure |
| **MUST NOT** | Dupliquer `/oauth2/static/` dans lâ€™export |

---

## 7. DÃ©ploiement

| RÃ¨gle | DÃ©tail |
|-------|--------|
| **MUST** | Vhost dÃ©ployÃ© par AWX (`linux_sso_portal.yml`) depuis `templates/nginx-portal.conf.j2` |
| **MUST** | `nginx -t` avant reload ; backup vhost avant remplacement (tÃ¢ches Ansible) |
| **MUST NOT** | Patcher manuellement le vhost en prod sans reporter le changement dans le template |
| **SHOULD** | `systemctl restart nginx` aprÃ¨s changement majeur auth (workers) |

---

## 8. Validation

```bash
# Aucune rÃ©fÃ©rence core-admin
sudo grep -rn 'portal_core\|4190\|oauth2/core' /etc/nginx/conf.d/ /etc/nginx/snippets/ \
  || echo "OK"

# Un seul auth_request par bloc admin
sudo awk '/location \^~ \/admin/,/^    }/' /etc/nginx/conf.d/vhost_sso_portal.conf | grep auth_request

# Sans session â†’ 302 (pas 500)
curl -sk -o /dev/null -w '%{http_code}\n' \
  https://portal.ar-systems.fr/admin --resolve portal.ar-systems.fr:443:127.0.0.1
```

Voir [auth-test-plan.md](../auth-test-plan.md) sections 2, 3, 7.

