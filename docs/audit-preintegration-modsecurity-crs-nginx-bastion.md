# Audit pré-intégration ModSecurity v3 + OWASP CRS — nginx-bastion

**Date :** 2026-08-05  
**Périmètre :** état factuel du conteneur `docker/nginx/` et des sources associées (`nginx/`, générateurs Python, Compose).  
**Contrainte :** audit uniquement — aucune modification de config/code dans le cadre de cette mission.  
**Doc de conception croisé :** `owasp-modsecurity-crs-nginx-bastion.md` **introuvable** dans le dépôt et sous le profil utilisateur ; la section « Écarts » croise les hypothèses énoncées dans la mission d’audit.

---

## 1. Image de base et build nginx

### 1.1 Dockerfile — image, paquets, modules

Fichier : [`docker/nginx/Dockerfile`](../docker/nginx/Dockerfile)

```dockerfile
# Bastion nginx — edge TLS (80→443) + HTTP interne :8080 pour le routage Host
# Certs ACME montés en lecture seule sous /etc/nginx/ssl
FROM nginx:1.27-alpine

RUN apk add --no-cache bash gettext wget jq findutils openssl \
    && rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /etc/nginx/snippets /etc/nginx/includes /var/lib/sso-portal/exports \
    && mkdir -p /var/www/nginx-errors /var/log/nginx/apps /etc/nginx/ssl /etc/nginx/ssl-local
```

| Élément | Valeur exacte |
|---------|---------------|
| Image de base | `nginx:1.27-alpine` (L3) |
| Paquets apk | `bash`, `gettext`, `wget`, `jq`, `findutils`, `openssl` (L5) |
| Paquets WAF / ModSecurity | **Aucun** (`libmodsecurity`, `nginx-mod-http-modsecurity`, etc. absents) |
| `load_module` | **Aucun** dans `Dockerfile`, `nginx.conf`, ni sous `docker/nginx/` |
| Entrypoint / CMD | `/docker-entrypoint-portal.sh` ; `nginx -g "daemon off;"` (L31–32) |
| Ports exposés | `80`, `443`, `8080` (L29) |

### 1.2 `nginx -V` / modules présents

- **Aucune** occurrence de `nginx -V` dans le Dockerfile, les scripts sous `docker/nginx/`, ni logs de build versionnés.
- Preuve d’usage du module **built-in** `ngx_http_realip_module` : directives `set_real_ip_from` / `real_ip_header` / `real_ip_recursive` dans [`docker/nginx/nginx.conf`](../docker/nginx/nginx.conf) L70–75 (module stock de l’image officielle Alpine nginx — non ajouté par ce Dockerfile).
- Preuve d’absence de module ModSecurity dynamique : zero `load_module`, zero paquet ModSecurity.

### 1.3 Mécanisme WAF existant — confirmation d’absence (avec stub nommé)

Recherche `modsecurity` / `ModSecurity` / `coraza` / `waf` sous `docker/nginx/` et `nginx/` :

| Fichier | Ligne | Extrait | Nature |
|---------|-------|---------|--------|
| [`docker/nginx/nginx.conf`](../docker/nginx/nginx.conf) | **86** | `# Stub for error_pages (no WAF maps in container)` | Commentaire exact demandé par la mission |
| [`docker/nginx/includes/waf-basic.conf`](../docker/nginx/includes/waf-basic.conf) | 1–2 | Voir ci-dessous | Stub **vide** (no-op) |
| [`docker/nginx/templates/vhost_sso_portal.conf.template`](../docker/nginx/templates/vhost_sso_portal.conf.template) | 37 | `include /etc/nginx/includes/waf-basic.conf;` | Include inert |
| [`nginx/vhosts/vhost_sso_portal.conf.j2`](../nginx/vhosts/vhost_sso_portal.conf.j2) | 52 | même `include` | Include inert |
| [`nginx/vhosts/vhost_transfer_crushftp.conf.j2`](../nginx/vhosts/vhost_transfer_crushftp.conf.j2) | 53 | `# Pas de waf-basic ici — évite faux positifs…` | Commentaire DMZ |

Contenu intégral de `waf-basic.conf` :

```1:2:docker/nginx/includes/waf-basic.conf
# WAF stub — disabled inside bastion container (host DMZ keeps WAF).
# Intentional empty include so portal vhost `include .../waf-basic.conf` is a no-op.
```

**Verdict §1 :** pas de ModSecurity / Coraza / règles CRS dans le conteneur. Un *hook* de nommage `waf-basic.conf` existe mais est volontairement vide. Le commentaire « no WAF maps in container » est bien à `docker/nginx/nginx.conf` L86.

---

## 2. Vhosts et structure de routage actuels

### 2.1 Inventaire des familles

| Famille | Sources versionnées | Runtime Docker |
|---------|---------------------|----------------|
| Portal SSO | [`nginx/vhosts/vhost_sso_portal.conf.j2`](../nginx/vhosts/vhost_sso_portal.conf.j2), [`docker/nginx/templates/vhost_sso_portal.conf.template`](../docker/nginx/templates/vhost_sso_portal.conf.template) | envsubst → `/etc/nginx/conf.d/vhost_sso_portal.conf` (listen **8080**) |
| Subdomain | [`nginx/vhosts/vhost-subdomain-crushftp.conf.j2`](../nginx/vhosts/vhost-subdomain-crushftp.conf.j2) (DMZ transitionnel) | Généré : [`app/bastion/nginx_subdomain_export.py`](../app/bastion/nginx_subdomain_export.py) → `exports/nginx-subdomain-apps.conf` |
| Public proxy | [`nginx/vhosts/vhost-public-proxy.conf.j2`](../nginx/vhosts/vhost-public-proxy.conf.j2) (DMZ transitionnel) | Généré : [`app/bastion/nginx_public_proxy_export.py`](../app/bastion/nginx_public_proxy_export.py) → `exports/nginx-public-proxy-apps.conf` |

Le répertoire `exports/` n’est **pas** versionné ; sync runtime via [`docker/nginx/sync-exports-to-confd.sh`](../docker/nginx/sync-exports-to-confd.sh).

### 2.2 Ordre `http{}` et point d’insertion ModSecurity vs `real_ip`

Ordre dans [`docker/nginx/nginx.conf`](../docker/nginx/nginx.conf) :

1. mime / sendfile / proxy hash (L10–16)  
2. resolver Docker (L18–19)  
3. `log_format` (L21–33)  
4. maps proto/port/upgrade (L37–49)  
5. **`limit_req_zone`** (L52–53)  
6. **`real_ip`** (L70–75) ← **avant** toute map métier et tout vhost  
7. includes maps breakglass / client-ip / subdomain-auth (L78–84)  
8. stub `$gateway_error_page` + commentaire « no WAF maps » (L86–89)  
9. **`include /etc/nginx/conf.d/*.conf`** (L91) ← vhosts portal + apps

```70:91:docker/nginx/nginx.conf
    set_real_ip_from 172.24.0.108;
    set_real_ip_from 10.5.0.0/16;
    set_real_ip_from 172.17.0.0/16;
    set_real_ip_from 127.0.0.0/8;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    ...
    include /etc/nginx/conf.d/*.conf;
```

**Verdict :** `$remote_addr` est réécrit **avant** le traitement des vhosts. Un futur `modsecurity on;` / `modsecurity_rules_file` placé dans `http{}` après L75 (ou dans les `server{}` de `conf.d`) verra la vraie IP client (sous réserve que le peer TCP soit dans `set_real_ip_from` et que XFF soit posé par reverse01). Les logs / blocages ModSecurity pourront donc s’appuyer sur `$remote_addr` post-real_ip.

### 2.3 Famille A — Portal (`vhost_sso_portal` Docker)

Source de référence runtime : [`docker/nginx/templates/vhost_sso_portal.conf.template`](../docker/nginx/templates/vhost_sso_portal.conf.template)  
Inclut aussi : `error_pages.conf`, `nginx-portal-core-realm-oauth2.conf`, `nginx-portal-oauth2-static.conf`, `exports/nginx-portal-realms.conf`, `subdomain_auth_common.conf`.

| # | Location | auth_request | internal | modsecurity |
|---|----------|--------------|----------|-------------|
| 1 | `= /__bastion_unknown_host` | **off** | **oui** | absent |
| 2 | `= /internal/unknown-host` | (return 404) | **oui** | absent |
| 3 | `@portal_rate_limited` | non | named | absent |
| 4 | `= /__portal_err/404` | **off** | **oui** | absent |
| 5 | `= /__portal_err/500` | **off** | **oui** | absent |
| 6 | `~ /\.` | deny/404 | non | absent |
| 7 | `= /_portal_nginx_ok` | non (allowlist LAN) | non | absent |
| 8 | `= /health` | **off** | non | absent |
| 9 | `= /api/health` | **off** | non | absent |
| 10 | `^~ /static/` | **off** | non | absent |
| 11 | `^~ /media/app-logos/` | **off** | non | absent |
| 12 | `^~ /media/branding/` | **off** | non | absent |
| 13 | `= /favicon.ico` | **off** | non | absent |
| 14 | `= /logout` | **off** | non | absent |
| 15 | `^~ /breakglass` | **off** | non | absent |
| 16 | `= /api/admin/breakglass/login` | **off** | non | absent |
| 17 | `= /api/admin/breakglass/logout` | **off** | non | absent |
| 18 | `^~ /auth/` | **off** | non | absent |
| 19 | `= /login` | **off** | non | absent |
| 20 | `= /internal/oauth2-auth` | — (404) | **oui** | absent |
| 21 | `= /internal/portal-rfc1918-bypass-auth` | — (404) | **oui** | absent |
| 22 | `= /portal_auth_check` | **off** (cible des auth_request) | **oui** | absent |
| 23 | `~ ^/oauth2/ar-systems/(.*)$` (snippet) | non | non | absent |
| 24 | `^~ /oauth2/static/` (snippet) | non | non | absent |
| 25 | `^~ /oauth2/{realm}/` (export realms) | **off** (généré) | non | absent |
| 26 | `@portal_oauth2_signin` | non | named | absent |
| 27 | `^~ /api/apps/` | **oui → `/portal_auth_check`** | non | absent |
| 28 | `^~ /api/admin` | **oui → `/portal_auth_check`** | non | absent |
| 29 | `^~ /admin` | **oui → `/portal_auth_check`** | non | absent |
| 30 | `= /api/internal/session-cookie-hop` | **off** | non | absent |
| 31 | `= /api/internal/crush-cookie-hop` | **off** | non | absent |
| 32 | `^~ /api/internal/` | **oui → `/portal_auth_check`** | non | absent |
| 33 | `= /internal/subdomain-auth` (snippet) | **off** | **oui** | absent |
| 34 | `= /internal/activesync-auth` (snippet) | **off** | **oui** | absent |
| 35 | `/` | **oui → `/portal_auth_check`** | non | absent |
| 36 | `= /50x.html` (error_pages) | non | **oui** | absent |
| 37 | `^~ /nginx-errors/` | non | non | absent |

Extraits représentatifs :

```109:123:docker/nginx/templates/vhost_sso_portal.conf.template
    location = /health {
        auth_request off;
        ...
        proxy_pass http://$bastion_app_upstream/health;
    }

    location = /api/health {
        auth_request off;
        ...
        proxy_pass http://$bastion_app_upstream/api/health;
```

```251:265:docker/nginx/templates/vhost_sso_portal.conf.template
    location = /portal_auth_check {
        internal;
        auth_request off;
        ...
        proxy_pass http://$bastion_app_upstream/internal/oauth2-auth;
```

```407:410:docker/nginx/templates/vhost_sso_portal.conf.template
    location / {
        limit_req zone=portal_api burst=60 nodelay;
        auth_request /portal_auth_check;
```

**AWX j2** ([`nginx/vhosts/vhost_sso_portal.conf.j2`](../nginx/vhosts/vhost_sso_portal.conf.j2)) : même cœur ; deltas notables — pas de stubs unknown-host Docker ; ajoute `@portal_proxy_sso_unavailable` et redirects legacy `/proxy/{slug}/` ; **pose les `add_header` sécurité** (voir §3).

### 2.4 Famille B — Subdomain

#### B1. Template DMZ j2

[`nginx/vhosts/vhost-subdomain-crushftp.conf.j2`](../nginx/vhosts/vhost-subdomain-crushftp.conf.j2)

| Location | auth_request | internal | modsecurity |
|----------|--------------|----------|-------------|
| `= /internal/subdomain-auth` (include) | **off** | **oui** | absent |
| `= /internal/activesync-auth` (include) | **off** | **oui** | absent |
| `^~ /proxy/{slug}/` (redirects snippet) | **off** | non | absent |
| `= /healthz` | **off** | non | absent |
| `= /.bastion/session-cookies` | **off** | **non** (explicite) | absent |
| `/` | **oui → `/internal/subdomain-auth`** | non | absent |
| `@portal_redirect_{slug}` | non | named | absent |

```39:70:nginx/vhosts/vhost-subdomain-crushftp.conf.j2
    location = /healthz {
        auth_request off;
        proxy_pass $app_upstream/;
        ...
    }
    ...
    location / {
        ...
        auth_request /internal/subdomain-auth;
```

#### B2. Export Python runtime (préféré)

[`app/bastion/nginx_subdomain_export.py`](../app/bastion/nginx_subdomain_export.py) → `exports/nginx-subdomain-apps.conf`

| Location (générée) | auth_request | internal |
|--------------------|--------------|----------|
| `= /.bastion/session-cookies` | **off** | **non** |
| CrushFTP : `/WebInterface/new-ui`, `/`, redirects | non (302) | non |
| ActiveSync / Autodiscover (si `allow_activesync`) | **oui → `/internal/activesync-auth`** | non |
| `/` (+ named upstream CrushFTP) | **oui → `/internal/subdomain-auth`** | non |
| `@portal_redirect_{slug}` | non | named |

**Delta important :** l’export Python **n’émet pas** `location = /healthz` (présent seulement dans le j2 DMZ).

Snippet auth (interne) :

```14:17:docker/nginx/snippets/subdomain_auth_common.conf
location = /internal/subdomain-auth {
    internal;
    auth_request off;
```

### 2.5 Famille C — Public proxy

#### C1. j2 DMZ

[`nginx/vhosts/vhost-public-proxy.conf.j2`](../nginx/vhosts/vhost-public-proxy.conf.j2) L17–33 : `= /healthz` et `/` — **aucun** `auth_request`, **aucun** `modsecurity`.

#### C2. Export Python

[`app/bastion/nginx_public_proxy_export.py`](../app/bastion/nginx_public_proxy_export.py) L121–141 :

| Location | auth_request | internal | modsecurity |
|----------|--------------|----------|-------------|
| `= /healthz` | aucun | non | absent |
| `~* ^/v1/webapi/.*/connect/ws` | aucun | non | absent |
| `/` | aucun | non | absent |

Commentaire module : *« no auth_request, oauth2-proxy, hop, or FastAPI /internal/* »*.

### 2.6 Locations « internes / santé » à exclure d’une inspection WAF future

| Endpoint | Fichier exact | Notes |
|----------|---------------|-------|
| `/health` | `docker/nginx/templates/vhost_sso_portal.conf.template` L109–115 | `auth_request off` → FastAPI |
| `/api/health` | même fichier L117–123 | idem |
| `/_portal_nginx_ok` | L99–107 | sonde Compose healthcheck (`docker-compose.yml` L153) |
| `/healthz` | `nginx_public_proxy_export.py` L122–131 ; j2 subdomain L39–44 | **absent** de l’export subdomain Python |
| `/oauth2/static/` | `docker/nginx/snippets/nginx-portal-oauth2-static.conf` L2–10 | assets oauth2-proxy, sans auth_request |
| `/portal_auth_check` | template portal L251–265 | `internal` — sous-requête auth |
| `/internal/subdomain-auth` | `subdomain_auth_common.conf` L14–32 | `internal` |
| `/internal/activesync-auth` | `activesync_auth_common.conf` L4–24 | `internal` |
| `/internal/oauth2-auth` | template L242–245 | `internal` + `return 404` (scellé public) |
| `/internal/portal-rfc1918-bypass-auth` | L246–249 | idem |
| `/internal/unknown-host` | L62–65 | `internal` |
| `/__bastion_unknown_host`, `/__portal_err/*` | template | `internal` |
| `/50x.html` | `error_pages.conf` L5–8 | `internal` |
| `/.bastion/session-cookies` | export subdomain | hop cookie — **pas** `internal` (navigateur) |
| `/api/internal/session-cookie-hop`, `crush-cookie-hop` | template L364–379 | publics HMAC, `auth_request off` |

```1:4:docker/nginx/snippets/nginx-portal-oauth2-static.conf
# oauth2-proxy static assets — sans auth_request
location ^~ /oauth2/static/ {
    proxy_pass http://$oauth2_core_upstream/oauth2/static/;
```

---

## 3. En-têtes de sécurité déjà en place

### 3.1 Snippet / emplacements

#### A. AWX / classique — centralisé au niveau `server` du portal j2

[`nginx/vhosts/vhost_sso_portal.conf.j2`](../nginx/vhosts/vhost_sso_portal.conf.j2) L41–46 (contenu complet de la suite) :

```nginx
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self';" always;
```

Override admin (XFO DENY seulement) L321–323 :

```nginx
    location ^~ /admin {
        add_header X-Frame-Options "DENY" always;
```

#### B. Docker portal — **pas** de suite server-level (correctif F-09)

[`docker/nginx/templates/vhost_sso_portal.conf.template`](../docker/nginx/templates/vhost_sso_portal.conf.template) L29–31 :

```nginx
    # Security headers (HSTS/CSP/…) are set once on the edge reverse proxy
    # (reverse01). Do not re-add them here — duplicates appear as comma-joined
    # values on /health (audit F-09). Keep only cache/rate headers in locations.
```

Seul `add_header` « sécurité » restant côté Docker portal : `X-Frame-Options "DENY"` sur `^~ /admin` (L335).

#### C. Transfer CrushFTP (hors portal, AWX)

[`nginx/vhosts/vhost_transfer_crushftp.conf.j2`](../nginx/vhosts/vhost_transfer_crushftp.conf.j2) L46–50 : nosniff, XFO SAMEORIGIN, **X-XSS-Protection**, Referrer-Policy, HSTS — **pas** de CSP / Permissions-Policy.

### 3.2 F-09 — correctif toujours en place

Test unitaire :

```191:198:tests/security/test_f07_f09_nginx.py
def test_docker_portal_no_duplicate_security_headers_at_server():
    """F-09: edge owns HSTS/CSP; docker must not re-add overlapping add_header."""
    path = ROOT / "docker/nginx/templates/vhost_sso_portal.conf.template"
    text = path.read_text(encoding="utf-8")
    assert "add_header X-Content-Type-Options" not in text.split("location")[0]
    assert "add_header Strict-Transport-Security" not in text
    assert "edge reverse proxy" in text.lower() or "reverse01" in text.lower()
```

Origine audit : [`rapport-audit-securite-bastion-2026-07-25.md`](../rapport-audit-securite-bastion-2026-07-25.md) §F-09 (`/health` renvoyait HSTS/XFO deux fois).

**Verdict :** sur le chemin Docker, F-09 n’a **pas** régressé (headers retirés du template + test). Risque de duplication **persiste** si le chemin AWX j2 (headers au vhost) et reverse01 posent les mêmes headers sur la même réponse.

### 3.3 CSP / COOP / COEP / CORP

| Header | Docker portal template | AWX portal j2 | Ailleurs repo |
|--------|------------------------|---------------|---------------|
| Content-Security-Policy | **absent** (volontaire F-09) | **présent** L46 | — |
| Cross-Origin-Opener-Policy | absent | absent | **aucun** match |
| Cross-Origin-Embedder-Policy | absent | absent | **aucun** |
| Cross-Origin-Resource-Policy | absent | absent | **aucun** |

**Nuance vs hypothèse mission « absence CSP » :** CSP est **déjà posée** sur le template AWX ; absente du runtime Docker (délégation edge).

### 3.4 Impact d’une future CSP stricte `default-src 'self'`

Inventaire `app/templates/` + `app/static/` :

| Pattern | Constat |
|---------|---------|
| CDN / `googleapis` / `cdnjs` / iframes externes | **Aucun** chargement réel. Commentaire [`app/templates/base.html`](../app/templates/base.html) L10 : fonts locales ; la CSP j2 autorise encore Google Fonts (allowlist morte). |
| `<script src="https://…">` | **Aucun** — scripts locaux `/static/js/…` |
| Blocs `<script>` inline | Présents dans ~30 templates admin/portal/auth (ex. `admin/apps/edit.html`, `admin/branding.html`, `auth/login.html`, `sessions/index.html`, `catalogue/index.html`, …) — **cassés** par `script-src 'self'` sans nonce/hash |
| `style=` inline | Très répandu (dizaines de templates ; pics : `admin/rbac/user_view.html` ~61, `admin/files/detail.html` ~33) — OK sous CSP actuelle (`'unsafe-inline'` styles) ; **cassés** si `style-src 'self'` strict |
| `onclick=` / handlers | Ex. `sessions/index.html`, `admin/rbac/account_detail.html` — traités comme script inline |
| Branding CSS vars | `base.html` L2 : `style="{{ branding.css_vars }}"` sur `<html>` |

---

## 4. Rate limiting existant

### 4.1 Zones (`limit_req_zone`)

**Statiques** (fichier versionné), pas générées par Python :

```51:53:docker/nginx/nginx.conf
    # Rate zones (required by portal vhost)
    limit_req_zone $binary_remote_addr zone=portal_login:10m rate=3r/s;
    limit_req_zone $binary_remote_addr zone=portal_api:10m rate=30r/s;
```

Miroir Ansible : [`ansible/roles/sso_portal/tasks/nginx_vhosts.yml`](../ansible/roles/sso_portal/tasks/nginx_vhosts.yml) L40–41 (insertion dans nginx conf hôte si manquant).

### 4.2 `limit_conn` / `limit_conn_zone`

**Aucune** occurrence dans le dépôt.

### 4.3 Applications `limit_req` (Docker portal)

| Location | Zone | burst | nodelay |
|----------|------|-------|---------|
| `= /__bastion_unknown_host` | portal_api | 20 | oui |
| `= /logout` | portal_login | 10 | oui |
| `^~ /breakglass` | portal_login | 5 | oui |
| `= /api/admin/breakglass/login` | portal_login | 5 | oui |
| `= /api/admin/breakglass/logout` | portal_login | 5 | oui |
| `^~ /auth/` | portal_login | 10 | oui |
| `= /login` | portal_login | 10 | oui |
| `^~ /api/apps/` | portal_api | 60 | oui |
| `^~ /api/admin` | portal_api | 60 | oui |
| `^~ /admin` | portal_api | 60 | oui |
| `= /api/internal/session-cookie-hop` | portal_api | 30 | oui |
| `= /api/internal/crush-cookie-hop` | portal_api | 30 | oui |
| `/` | portal_api | 60 | oui |
| `^~ /api/internal/` (préfixe, hors hops exacts) | **aucune** | — | — |

429 → `@portal_rate_limited` + header `X-Rate-Limited-By: portal-nginx`.

Exports subdomain / public_proxy / transfer CrushFTP : **pas** de `limit_req`.

---

## 5. Docker Compose et volumes de logs

### 5.1 Service `nginx`

[`docker-compose.yml`](../docker-compose.yml) L130–165 :

```yaml
  nginx:
    build: ./docker/nginx
    image: bastion-nginx:local
    container_name: bastion-nginx
    environment:
      PORTAL_INTERNAL_TOKEN: ${VAULT_PORTAL_INTERNAL_TOKEN:-${PORTAL_INTERNAL_TOKEN:-}}
      PORTAL_DOMAIN: ${PORTAL_DOMAIN:-portal.ar-systems.fr}
      SSO_PORTAL_DEFAULT_REALM_SLUG: ${SSO_PORTAL_DEFAULT_REALM_SLUG:-ar-systems}
    volumes:
      - ${SSO_PORTAL_DATA_DIR:-./data/sso-portal}/exports:/var/lib/sso-portal/exports:ro
      - ${SSO_PORTAL_DATA_DIR:-./data/sso-portal}/certs:/etc/nginx/ssl:ro
      - ${SSO_PORTAL_DATA_DIR:-./data/sso-portal}/nginx-logs:/var/log/nginx/apps
    networks:
      vpcbr:
        aliases: [bastion-nginx, nginx]
    ports:
      - "80:80"
      - "443:443"
      - "127.0.0.1:8080:8080"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:8080/_portal_nginx_ok"]
    depends_on:
      bastion-app: { condition: service_healthy }
      oauth2-proxy-core: { condition: service_started }
      acme-companion: { condition: service_started }
    restart: unless-stopped
```

- Réseau : `vpcbr` **external**
- Override publish : `docker-compose.publish.yml` restreint les ports (8080 loopback)

### 5.2 Logs — emplacement, mounts, rotation

| Log | Chemin conteneur | Monté hôte ? |
|-----|------------------|--------------|
| error global | `/var/log/nginx/error.log` (`nginx.conf` L2) | **Non** |
| portal access/error | `/var/log/nginx/portal.access.log`, `portal.error.log` (template L19–20) | **Non** |
| per-app | `/var/log/nginx/apps/${slug}.{access,error}.log` | **Oui** → `${SSO_PORTAL_DATA_DIR}/nginx-logs` (aussi RO dans bastion-app L95–96) |

`sync-exports-to-confd.sh` L9–17 : crée `/var/log/nginx/apps` et tente `chmod 0777`.

**logrotate :** aucune config / tâche Ansible / cron dans ce dépôt (grep `logrotate` = 0).  
**Implication Phase A :** un futur `modsec_audit.log` n’héritera d’aucune politique de rétention in-repo ; à aligner explicitement (idéalement sur le bind `nginx-logs` ou un volume dédié + logrotate hôte).

---

## 6. Endpoints sensibles aux faux positifs CRS

### 6.1 `POST /admin/apps/analyze-login-form`

- Prompt historique `prompt-cursor-audit-filtrage-ssrf-analyze-login-form.md` : **introuvable**.
- Route : [`app/web/pages.py`](../app/web/pages.py) L1975–2023.

```python
class _AnalyzeLoginFormBody(BaseModel):
    url: str = Field(min_length=1)
    tls_verify: bool = False

@admin_router.post("/admin/apps/analyze-login-form")
async def admin_analyze_login_form(...):
    """Fetch a remote login page and detect form field names (no credentials sent)."""
    result = await analyze_login_form_url(body.url.strip(), tls_verify=bool(body.tls_verify))
```

**Contenu sur le fil ingress (ce que CRS voit) :** JSON `{ "url": "...", "tls_verify": bool }` uniquement — **pas** de HTML tiers dans le body.

**HTML :** fetch serveur [`app/bastion/login_form_analyzer.py`](../app/bastion/login_form_analyzer.py) — `Accept: text/html…`, max **2 MiB** (`MAX_BODY_BYTES`), max 5 redirects, hosts privés/LAN autorisés volontairement. Parsing BeautifulSoup → JSON de métadonnées de formulaires.

**FP CRS :** URL / query strings dans le JSON ARGS ; éventuelle inspection de **réponse** (noms de champs / hidden values tiers) si activée.

### 6.2 Autres endpoints à risque de faux positifs

| Endpoint | Payload | Risque CRS |
|----------|---------|------------|
| `POST /admin/apps/create`, `…/{slug}/edit` | Form : URLs, description, `login_extra_fields` JSON | texte libre, `<>`, quotes |
| `POST /admin/apps/{slug}/credential` (+ user) | JSON secrets | caractères spéciaux |
| `POST /admin/branding` | textes welcome/footer | HTML-ish |
| `POST /admin/branding/logo`, `/favicon` | `UploadFile` multipart | binaire / magic bytes |
| `POST /admin/apps/{app_id}/logo` | upload image ≤512 KB | binaire |
| `POST /admin/files/deposit`, `POST /files/upload` | multipart + métadonnées | fichiers arbitraires |
| `POST /admin/logs/views` | `filters_json` | JSON / patterns query-like |
| `POST /admin/configuration*`, `/admin/security/*` | webhooks, CIDR, secrets, raisons ban | URLs, SQL-ish |
| `POST /admin/security/hot-store/config` | host/user/password DB | connection strings |
| Realms / RBAC admin JSON | issuers, secrets | URLs / tokens |

Pas d’endpoint « import de config nginx brut » trouvé.

---

## 7. Génération de configuration existante (pattern Phase B)

### 7.1 Générateurs Python → `EXPORTS_DIR`

Orchestration : [`app/admin/export.py`](../app/admin/export.py), [`app/admin/infrastructure.py`](../app/admin/infrastructure.py) (`apply_infrastructure`).

| Générateur | Module | Sorties typiques |
|------------|--------|------------------|
| Public proxy | `app/bastion/nginx_public_proxy_export.py` | `nginx-public-proxy-apps.conf`, inventory JSON, `nginx-public-proxy-apps/{slug}.conf` |
| Subdomain | `app/bastion/nginx_subdomain_export.py` | `nginx-subdomain-apps.conf`, inventory, per-app |
| Known hosts | `app/bastion/nginx_known_hosts_export.py` | `nginx-known-hosts.map` |
| Portal apps / realms | `app/admin/export.py` | `nginx-portal-apps.conf`, `nginx-portal-realms.conf` |
| OAuth2-proxy | `write_oauth2_proxy_export` | `oauth2/{slug}/oauth2-proxy.cfg` (+ miroir plat) |

Exemple write API :

```172:176:app/bastion/nginx_public_proxy_export.py
def write_public_proxy_apps_exports(db: Session, settings: Settings) -> dict[str, str]:
    """Write nginx conf + inventory under EXPORTS_DIR; prune stale per-app files."""
    exports_path = Path(settings.exports_dir)
```

### 7.2 Sync conteneur

[`docker/nginx/sync-exports-to-confd.sh`](../docker/nginx/sync-exports-to-confd.sh) : copie  
`nginx-subdomain-apps.conf`, `nginx-public-proxy-apps.conf`, `nginx-infra-proxy-apps.conf` → `/etc/nginx/conf.d/`, régénère `00-known-hosts-map.conf`.

### 7.3 Séquence apply — `nginx -t` → reload

[`scripts/apply-infra-docker.sh`](../scripts/apply-infra-docker.sh) L159–194 :

1. `docker compose exec -T nginx`  
2. `/sync-exports-to-confd.sh` (ou fallback `cp` + rebuild map)  
3. **`nginx -t && nginx -s reload`** (L194)  
4. Si échec exec → `docker compose restart nginx`

Précédemment dans le même script : compose override oauth2 secondaires, sync cfg core, `up -d`, force-recreate `oauth2-proxy-core`.

**Pattern réutilisable Phase B WAF :** générateur Python → fichier sous `exports/` → sync `conf.d` (ou include dédié) → même garde-fou `nginx -t && nginx -s reload` — sans inventer un second pipeline.

### 7.4 oauth2-proxy (bref)

SoT = `RealmConfig` SQLite → export cfg → miroirs `exports/` + `docker/oauth2-core/` → recreate conteneur. Les fichiers sous `docker/oauth2-core/` ne sont **pas** la source de vérité (aligné règle utilisateur portal SSO).

---

## Écarts par rapport aux hypothèses de conception

> **Limite :** le fichier `owasp-modsecurity-crs-nginx-bastion.md` n’a pas été trouvé. Tableau croisé uniquement contre les hypothèses explicites de la mission d’audit et les faits observés.

| # | Hypothèse (mission / conception implicite) | Réalité constatée | Impact Phase A |
|---|--------------------------------------------|-------------------|----------------|
| E1 | Aucun WAF aujourd’hui dans le conteneur | Confirmé (pas ModSecurity/Coraza). **Mais** stub nommé `waf-basic.conf` + `include` portal + commentaire L86 « no WAF maps in container » | Remplacer le stub no-op plutôt qu’inventer un second hook ; ne pas confondre « include waf » avec WAF actif |
| E2 | `real_ip` doit être résolu **avant** inspection contenu | **Déjà le cas** : L70–75 avant `conf.d` L91 | Point d’insertion ModSecurity après L75 / dans server = aligné ; ne pas placer real_ip *après* ModSecurity |
| E3 | Absence CSP, COOP, COEP, CORP | COOP/COEP/CORP absents. **CSP présente** sur AWX j2 L46 ; absente du template Docker (F-09) | Ne pas re-dupliquer CSP sur Docker si edge la pose ; documenter le double chemin |
| E4 | Headers sécurité centralisés une fois / F-09 corrigé | F-09 Docker **OK** (test + comment). Bifurcation Docker(edge) vs AWX(j2) | Risque de duplication si les deux chemins s’empilent |
| E5 | Image de base prête ou proche pour ModSec | `nginx:1.27-alpine` **stock**, sans module ModSecurity | Rebuild image obligatoire (paquet/module ou image custom) |
| E6 | Zones rate limit à créer | Zones **`portal_login`** / **`portal_api`** déjà nommées et branchées | Ne pas collisionner ; WAF ≠ remplacer ces zones |
| E7 | `analyze-login-form` fait transiter du HTML tiers en entrée | **Faux** : body JSON URL seulement ; HTML fetch serveur | Exclusion CRS : plutôt ARGS URL / uploads multipart que « body HTML » |
| E8 | Commentaire « no WAF maps in container » à retrouver | Trouvé : `docker/nginx/nginx.conf` **L86** | Preuve OK |
| E9 | `/healthz` uniforme sur apps | Présent public_proxy + j2 subdomain ; **absent** export subdomain Python | Exclusion WAF : ne pas supposer `/healthz` partout |
| E10 | Logs prêts pour `modsec_audit.log` | Seuls logs **apps** montés ; portal/global en FS conteneur ; **pas** de logrotate in-repo | Définir volume + rotation avant activation audit ModSec |
| E11 | Doc conception versionné pour croiser | `owasp-modsecurity-crs-nginx-bastion.md` **absent** | Enrichir cette section dès réception du doc |

---

*Fin du rapport d’audit pré-intégration — 2026-08-05.*
