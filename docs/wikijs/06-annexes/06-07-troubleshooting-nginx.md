> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/troubleshooting-nginx.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# Portail SSO AR-Systems â€” DÃ©pannage Nginx et proxy

> **Sujet :** problÃ¨mes rencontrÃ©s en production, causes racines et correctifs appliquÃ©s dans `awx-playbook`.

> **Juillet 2026 â€” pÃ©rimÃ¨tre documentaire**  
> - **Sections 1.1â€“1.3, 1.4 (Wiki.js)** : DMZ infra (`nginx_reverse_proxy_dmz`) â€” **toujours valides**.  
> - **Sections 1.4 (portail), 2â€“4 (proxy `/proxy/`, CrushFTP subpath)** : **archivÃ©es** â€” templates retirÃ©s du dÃ©pÃ´t (`e56fa58`).  
>   Reprise bastion : [SSO_PORTAL_BASTION_FEATURES_INVENTORY.md](../SSO_PORTAL_BASTION_FEATURES_INVENTORY.md).  
> - DÃ©pannage portail catalogue/admin : [02-authentification-sso.md](02-authentification-sso.md), [SDD-002](../sdd/SDD-002-nginx-vhost-portail.md).

---

## 1. Boucles de redirection (`ERR_TOO_MANY_REDIRECTS`)

### 1.1 SymptÃ´mes

- Navigateur affiche Â« Trop de redirections Â» ;
- Logs Nginx : chaÃ®ne de **301** ou **308** avec corps de rÃ©ponse trÃ¨s court (~17â€“18 octets) ;
- Affecte Wiki.js (`wikijs.ar-systems.fr`), parfois d'autres apps derriÃ¨re Traefik.

### 1.2 Diagnostic : qui redirige ?

Depuis `vmdmz-reverse01` (ou tout hÃ´te ayant accÃ¨s au backend) :

```bash
# Test backend direct â€” HTTP
curl -sI -H "Host: wikijs.ar-systems.fr" http://10.0.31.112:80/

# Test backend direct â€” HTTPS
curl -sI -k -H "Host: wikijs.ar-systems.fr" https://10.0.31.112:443/

# Test via vhost public
curl -sI https://wikijs.ar-systems.fr/
```

| RÃ©sultat HTTP:80 | InterprÃ©tation |
|------------------|----------------|
| `308` / `301` â†’ `https://wikijs...` | **Traefik** (ou backend) force HTTPS â€” coupable probable |
| `200 OK` | Backend OK en clair â€” chercher cÃ´tÃ© **Nginx DMZ** |

**Cas observÃ© (juin 2026) :**

```
HTTP/1.1 308 Permanent Redirect
Location: https://wikijs.ar-systems.fr/
Content-Length: 18
```

MÃªme avec `X-Forwarded-Proto: https` sur le port 80, Traefik redirige â€” la redirection globale `entrypoint web â†’ websecure` ne peut pas Ãªtre contournÃ©e par les seuls trust headers.

### 1.3 Correctifs appliquÃ©s

#### A. Backend HTTPS vers Traefik (Wiki.js)

Variables Ansible (`nginx_reverse_proxy_dmz`) :

```yaml
wikijs_backend_protocol: "https"
wikijs_backend_port: 443
```

Nginx DMZ se connecte Ã  **Traefik websecure** au lieu du port 80.

#### B. Snippet trust headers partagÃ©

Fichier : `/etc/nginx/snippets/proxy_backend_forwarded.conf`

```nginx
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto https;      # forcÃ© â€” pas $scheme ambigu
proxy_set_header X-Forwarded-Ssl on;
proxy_set_header X-Forwarded-Port $server_port;
proxy_set_header X-Forwarded-Host $host;
```

Inclus dans :

- `vhost_wikijs.conf.j2` ;
- Portail : `proxy_portal_forwarded.conf.j2` *(linux_sso_portal.yml uniquement)*.

#### C. Port 80 public vs proxy interne

Le bloc `listen 80` des vhosts **ne doit rediriger que le trafic public entrant** :

```nginx
server {
    listen 80;
    server_name wikijs.ar-systems.fr;
    return 301 https://$host$request_uri;
}
```

Ce bloc ne s'applique **pas** aux connexions sortantes Nginx â†’ backend.

#### D. Sonde Ansible

Le rÃ´le `nginx_reverse_proxy_dmz` avertit si `http://backend:80/` renvoie une redirection alors que le backend configurÃ© est HTTP.

### 1.4 Boucles cÃ´tÃ© portail SSO *(archivÃ© â€” proxy `/proxy/` retirÃ©)*

> Les scÃ©narios `/proxy/slug`, `login.html` CrushFTP subpath et `portal_proxy_resolve` ne s'appliquent plus au dÃ©ploiement actuel de `awx-playbook`. ConservÃ©s comme rÃ©fÃ©rence historique pour le dÃ©pÃ´t applicatif.

| ScÃ©nario | Cause | Correctif |
|----------|-------|-----------|
| Login en boucle | `redirect_uri` Keycloak â‰  callback rÃ©el ; **rd= non encodÃ©** (`/proxy/â€¦` dans l'URL) ; refresh concurrent `invalid_grant` | Sign-in via FastAPI `/auth/sso-start` ; cache + verrou auth_request ; vider cookies `_kc_portal_*` |
| Transfer â†” `/auth/login` (`ae=no-session:ck=72`) | Filtre CrushFTP `Cookie: CrushAuth=â€¦` dans le **mÃªme** `location /` que `auth_request` â†’ nginx hÃ©rite le Cookie filtrÃ© (FastAPI sans `bastion_session`, `x=0`) | 1) Rebuild **bastion-app** (â‰¥ named `@app_upstream_*` + snippet `pass_request_headers off`) 2) Apply (re-export Transfer) 3) `grep -E 'try_files.*@app_upstream|pass_request_headers|upstream_cookie'` 4) HAR : plus de `ck=72` |
| Transfer â†” `/auth/login` (`ae=no-session:ck=90`) | Rebuild Cookie rejouÃ© pendant auth avec `$http_cookie` CrushAuth-only â†’ `bastion_session=; CrushAuth=â€¦` (â‰ˆ90) + `x=0` | Snapshot `$cookie_bastion_session` + auth dans `location /` ; filtre CrushFTP seulement dans `@app_upstream_*` |
| Transfer `404` nginx sur `/WebInterface/new-ui/index.html` (auth OK) | Sticky `if ($bastion_fresh_sessionâ€¦)` saute `try_files` (if is evil) | **Pas** de `if` sticky ; `try_files` / `proxy_pass` dans `location /` |
| Transfer `500` nginx sur `/WebInterface/new-ui/index.html` | Map `$bastion_pick_*` â†” `$bastion_pass_*` = cycle â†’ 500 | Pas de maps `pick_*` ; snapshot `$cookie_bastion_session` |
| Transfer `401 Authorization Required` nginx brut (pas de redirect portail) | `#38` `return 418` â†’ `@bastion_auth_gate_*` : `error_page 401` imbriquÃ© ne dÃ©clenche pas `@portal_redirect` | Auth + `error_page 401` dans **le mÃªme** `location /` (pas de handoff 418) |
| `/logout` boucle | 401 â†’ sign_in | FastAPI dÃ©tecte l'absence de session â†’ `302 /` (plus d'`auth_request` sur `/logout`) |
| Popup login/mdp navigateur sur tuile CrushFTP | 401 + `WWW-Authenticate: Basic` du backend | `proxy_hide_header WWW-Authenticate` sur le proxy transparent ; vÃ©rifier robotic SSO (cookie CrushAuth, ban IP) |
| `/proxy/slug` boucle 401 | Session absente ou **oauth2_listen SQLite â‰  :4180 core** | Aligner realm ar-systems sur `OAUTH2_CORE_LISTEN` ; logs `PROXY-DEBUG` FastAPI |
| `login.html` boucle 302 | CrushFTP renvoie 302 â†’ mÃªme login.html ; cookie `currentAuth-H-2` non transmis | `proxy_redirect` **avant** rÃ¨gle gÃ©nÃ©rique â†’ `new-ui/` ; map nginx `currentAuth*` ; entrÃ©e `/proxy/transfer/` â†’ `new-ui/` |
| Proxy resolve 403 | `internal_upstream` vide | Admin â†’ Ã©diter app â†’ URL interne |

---

## 2. Erreur en-tÃªte cookie > 4 Ko

### 2.1 SymptÃ´mes

- `400 Bad Request` â€” `Request Header Or Cookie Too Large` ;
- Ã‰chec logout oauth2-proxy ;
- CrushFTP / Java backend rejette la requÃªte proxifiÃ©e.

### 2.2 Cause

Les cookies SSO cumulÃ©s (`_kc_portal_ar` + autres) dÃ©passent la limite **~4 Ko** des en-tÃªtes HTTP (nginx default `large_client_header_buffers 4 8k` insuffisant en edge cases).

### 2.3 Correctifs

#### A. Filtrage cookies vers backends proxifiÃ©s

`nginx-portal-proxy.map.conf` â€” map `$portal_proxy_backend_cookie` :

- **Transmet uniquement** `CrushAuth` et `currentAuth` ;
- **Omet** les cookies oauth2-proxy et Keycloak.

Commentaire dans `proxy_portal_transparent.conf.j2` :

> Filtrage cookies : CrushAuth/currentAuth uniquement (pas les jetons SSO > 4 Ko)

#### B. Buffers Nginx portail

```nginx
large_client_header_buffers 8 32k;
```

Dans `nginx-portal.conf.j2`.

#### C. SLO front-channel (logout)

Ã‰viter `backend_logout_url` oauth2-proxy â€” logout via Keycloak front-channel (`GET /logout` â†’ `build_keycloak_front_channel_logout_url`). Voir document authentification.

#### D. Buffers oauth2-proxy locations

```nginx
proxy_buffer_size 128k;
proxy_buffers 8 128k;
```

Sur les locations `/oauth2/{realm}/` dans le fragment gÃ©nÃ©rÃ©.

---

## 3. RÃ©Ã©criture HTML et URLs (`sub_filter` vs approche actuelle)

### 3.1 Contexte historique

Pour un proxy sous `/proxy/{slug}/`, les backends gÃ©nÃ¨rent souvent :

- Des URLs absolues `/WebInterface/...` ;
- Des redirections `Location: /login` ;
- Des cookies avec `Path=/`.

Une approche classique consiste Ã  utiliser **`sub_filter`** Nginx pour rÃ©Ã©crire le HTML Ã  la volÃ©e (`/href="/` â†’ `/href="/proxy/transfer/`).

### 3.2 Approche retenue : pas de `sub_filter`

Le dÃ©pÃ´t **n'utilise pas** `sub_filter` dans la configuration finale. Raisons :

| InconvÃ©nient `sub_filter` | Alternative retenue |
|---------------------------|---------------------|
| Casse les rÃ©ponses compressÃ©es (gzip) | `proxy_set_header Accept-Encoding ""` sur proxy transparent |
| Fragile sur JSON/API binaires | Pass-through URI â€” backend reÃ§oit le chemin complet |
| Performance CPU | `proxy_redirect` regex pour les redirections HTTP |
| Double maintenance | `proxy_cookie_path / /proxy/$app_slug/` |

### 3.3 MÃ©canismes de rÃ©Ã©criture actuels

**Pass-through URI** (`proxy_portal_transparent.conf.j2`) :

```nginx
proxy_pass $backend_upstream$request_uri;
```

CrushFTP ReverseProxy Path = `/proxy/transfer/` â€” le backend connaÃ®t son prÃ©fixe.

**RÃ©Ã©criture redirections** :

```nginx
proxy_redirect ~^(?:https?://[^/]+)?/(?!proxy/)(.*)$ /proxy/$app_slug/$1;
```

**RÃ©Ã©criture cookies backend** :

```nginx
proxy_cookie_path / /proxy/$app_slug/;
```

**MIME forcÃ© pour assets statiques** (CrushFTP Content-Type incorrect) :

- Location dÃ©diÃ©e `\.(css|js|â€¦)$` avec `portal_proxy_fix_mime=true` ;
- `proxy_hide_header Content-Type` + `add_header Content-Type $portal_proxy_static_content_type`.

### 3.3 Si `sub_filter` Ã©tait nÃ©cessaire (non recommandÃ©)

```nginx
# Exemple NON dÃ©ployÃ© â€” rÃ©fÃ©rence uniquement
proxy_set_header Accept-Encoding "";
sub_filter_once off;
sub_filter 'href="/' 'href="/proxy/transfer/';
sub_filter_types text/html;
```

PrÃ©fÃ©rer la configuration native du backend (ReverseProxy Path) avant d'activer `sub_filter`.

### 3.4 CrushFTP : assets 500/404 sur `/WebInterface/...` (sans `/proxy/transfer/`)

**SymptÃ´mes console navigateur :**

- `Failed to load resource: 500` sur `https://portalâ€¦/WebInterface/new-ui/assets/â€¦`
- `Refused to apply style` / `Refused to execute script` â€” MIME `text/html` ou `application/json` au lieu de CSS/JS
- La page login s'affiche partiellement (HTML) mais sans styles ni scripts

**Cause :** CrushFTP gÃ©nÃ¨re des liens absolus `/WebInterface/â€¦` parce que le **ReverseProxy Path** n'est pas configurÃ© sur le serveur (`/proxy/transfer/`). Ces requÃªtes tombent sur FastAPI (`location /`) au lieu du bloc `location ~ ^/proxy/`.

**Cause (assets HTML / `Unexpected token '<'`) :** Nginx envoie un mauvais chemin au backend â€” le bloc `WebInterface/new-ui/` capturait un `proxy_rest` tronquÃ© lors du **strip prefix** (`/init-js/â€¦` au lieu de `/WebInterface/new-ui/init-js/â€¦`). CrushFTP rÃ©pond alors avec `login.html` (HTML) Ã  la place du JS. Par dÃ©faut, CrushFTP **retire** `/proxy/{slug}/` avant le backend (ReverseProxy Path cÃ´tÃ© serveur rarement configurÃ©).

**Correctif recommandÃ© (CrushFTP Admin) :** Reverse Proxy Path = `/proxy/transfer/` (voir [03-vault-applicatif.md](03-vault-applicatif.md)). Si configurÃ©, dÃ©sactiver le strip prefix dans l'admin portail (case Â« Envoyer Ã  la racine Â» â€” automatique pour CrushFTP sinon).

**Filet de sÃ©curitÃ© Nginx** (`nginx-portal.conf.j2`, activÃ© par dÃ©faut) :

```nginx
location ^~ /WebInterface/ {
    return 302 /proxy/transfer$request_uri;
}
```

**RÃ©Ã©criture HTML CrushFTP** (`sub_filter` sur `WebInterface/`) â€” rÃ©Ã©crit `="/assets/` vers `/proxy/{slug}/WebInterface/new-ui/assets/` (pas de `<base href="/proxy/{slug}/">` qui envoyait les assets vers `/proxy/{slug}/assets/`).

**`login.html?path=/assets/â€¦`** : Nginx redirige vers `/proxy/{slug}/WebInterface/new-ui/assets/â€¦` (fichier CSS/JS direct, plus de HTML login).

Variables Ansible : `sso_portal_crushftp_webinterface_redirect_enabled`, `sso_portal_crushftp_webinterface_slug`, `sso_portal_crushftp_html_rewrite`.

**Cause (page noire `/WebInterface/new-ui/`) :** `portal_proxy_fix_mime=true` sur le bloc new-ui catch-all masquait le `Content-Type` HTML (URI sans extension â†’ map vide â†’ page noire). Les assets `.css`/`.js` doivent passer par le bloc extensions **avant** le catch-all new-ui.

**Bruit sans lien :** les logs `background.js` / Bitwarden dans la console sont une extension navigateur, pas le portail.

---

## 4. `X-Forwarded-Proto` et Traefik / Wiki.js

### 4.1 ProblÃ¨me

Nginx termine TLS (`listen 443 ssl`). La connexion Nginx â†’ backend est souvent **HTTP** (port 80 ou 443 interne). Sans en-tÃªte explicite, Traefik/Wiki.js croit que le client est en **HTTP** et redirige vers HTTPS â†’ boucle.

### 4.2 RÃ¨gle absolue

Sur tout vhost `listen 443 ssl` qui proxifie vers un backend :

```nginx
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-Ssl on;
```

**Ne pas utiliser** `$scheme` si le contexte peut Ãªtre ambigu ; le portail force dÃ©sormais `https` dans `proxy_portal_forwarded.conf.j2`.

### 4.3 Backend HTTPS vers Traefik

Quand Traefik a une redirection globale port 80 â†’ 443, configurer :

```yaml
wikijs_backend_protocol: https
wikijs_backend_port: 443
```

Avec :

```nginx
proxy_ssl_verify off;
proxy_ssl_server_name on;
proxy_ssl_name $host;
```

### 4.4 Wiki.js configuration applicative

CÃ´tÃ© Wiki.js (hors Ansible portail) :

- `ssl.enabled: false` si Nginx gÃ¨re le TLS ;
- URL publique = `https://wikijs.ar-systems.fr` ;
- `trustProxy: true` dans `config.yml` pour honorer `X-Forwarded-*`.

Labels Traefik documentÃ©s : `roles/nginx_reverse_proxy_dmz/files/wikijs-traefik-labels.example.yml`.

---

## 5. Autres problÃ¨mes proxy documentÃ©s

### 5.1 `proxy_pass_request_headers off`

Le proxy transparent **dÃ©sactive** le forward automatique des en-tÃªtes client. Seuls les en-tÃªtes listÃ©s explicitement partent vers le backend â€” Ã©vite les fuites de cookies SSO.

### 5.2 `Connection: close`

CrushFTP (Java legacy) : HTTP/1.1 avec connexion fermÃ©e aprÃ¨s chaque requÃªte pour Ã©viter les connexions pendantes.

### 5.3 RÃ©solution DNS dynamique

```nginx
resolver 127.0.0.1 8.8.8.8 valid=30s;
```

Requis pour `proxy_pass $backend_upstream` (variable).

### 5.4 Erreur `nginx -t` â€” snippets manquants

Les snippets portail doivent exister **avant** le test :

- RÃ´le `sso_portal/tasks/nginx_snippets.yml` ;
- Import dans `nginx_reverse_proxy_dmz` avant `nginx -t`.

Fichiers requis :

- `proxy_portal_forwarded.conf`
- `proxy_portal_forwarded_backend.conf` (backends internes â€” sans override Host)
- `proxy_portal_transparent.conf`
- `proxy_portal_fastapi.conf`
- `proxy_backend_forwarded.conf` (vhosts classiques)

### 5.5 Logs utiles

| Log | Contenu |
|-----|---------|
| `/var/log/nginx/portal.error.log` | Erreurs auth_request, proxy |
| `/var/log/nginx/wikijs.error.log` | Wiki.js vhost classique |
| `journalctl -u sso-portal` | `PROXY-DEBUG:` rÃ©solution slug |
| `journalctl -u oauth2-proxy-portal-*` | Erreurs OIDC |

### 5.6 Commandes de diagnostic

```bash
# Test auth interne (depuis DMZ)
curl -sI http://127.0.0.1:8000/health

# Test resolve proxy (nÃ©cessite token rÃ©el + cookie SSO pour HTTP 200)
TOKEN=$(grep '^PORTAL_INTERNAL_TOKEN=' /opt/sso-portal/.env | cut -d= -f2-)
curl -sI -H "X-Portal-Internal-Token: ${TOKEN}" \
  -H "Cookie: _kc_portal_ar=VOTRE_COOKIE" \
  "http://127.0.0.1:8000/api/internal/resolve?slug=transfer"

# Config nginx active
nginx -T | grep -A5 "proxy_set_header X-Forwarded"

# VÃ©rifier snippet dÃ©ployÃ©
cat /etc/nginx/snippets/proxy_backend_forwarded.conf
```

---

## 6. Matrice rÃ©capitulative

| ProblÃ¨me | Indicateur | Correctif principal | Fichier clÃ© |
|----------|------------|---------------------|-------------|
| Boucle 301/308 | `curl` backend :80 â†’ 308 | Backend `https:443` + trust headers | `vhost_wikijs.conf.j2`, `vars/main.yml` |
| Cookie > 4 Ko | 400 header too large | Filtrage cookies proxy | `nginx-portal-proxy.map.conf` |
| HTML cassÃ© en proxy | CSS/JS 404 | Pass-through URI + `proxy_redirect` | `proxy_portal_transparent.conf.j2` |
| Backend pense HTTP | Redirection SSL | `X-Forwarded-Proto https` forcÃ© | `proxy_backend_forwarded.conf` |
| Logout Ã©choue | 400 au logout | SLO front-channel Keycloak | `main.py`, `realm_service.py` |
| `nginx -t` fail | snippet not found | `nginx_snippets.yml` avant vhost | `tasks/nginx_snippets.yml` |
| Host backend rejetÃ© | 502/403 cÃ´tÃ© app interne | `Host` = netloc interne, `X-Forwarded-Host` = portail | `proxy_portal_forwarded_backend.conf`, map `portal_upstream_host` |
| Redirect vers IP privÃ©e | Navigateur bloque ou quitte le proxy | `proxy_redirect` + `X-Internal-Origin` | `proxy_portal_transparent.conf.j2` |
| Cookies backend absents | Session perdue entre requÃªtes | `forward_cookies_mode` + `proxy_cookie_path` | `nginx-portal-proxy.map.conf`, admin app |
| Collision cookies SSO | Backend Java crash / 400 header | Mode `safe` (CrushAuth) ou `all` sans `_kc_*` | `nginx-portal-proxy.map.conf` |

---

## 6.1 Proxy transparent â€” Host, cookies et redirects (juin 2026)

### Host header

Par dÃ©faut (`preserve_host=false`), Nginx envoie au backend :

| Header | Valeur |
|--------|--------|
| `Host` | Netloc interne (`10.x.x.x:443`) |
| `X-Forwarded-Host` | `portal.ar-systems.fr` |
| `X-Forwarded-Prefix` | `/proxy/{slug}` |

Si l'application exige le hostname public, activer **Preserve Host** dans l'admin bastion.

**PiÃ¨ge corrigÃ© :** l'ancien snippet `proxy_portal_forwarded.conf` Ã©crasait `Host $backend_host` avec `Host $host`. Le proxy transparent inclut dÃ©sormais `proxy_portal_forwarded_backend.conf` (sans ligne `Host`).

### Cookies

Politique pilotÃ©e par `/api/internal/resolve` â†’ `X-Forward-Cookies-Mode` :

| Mode | Comportement |
|------|--------------|
| `none` | Aucun cookie vers le backend |
| `safe` | CrushAuth/currentAuth si prÃ©sents, sinon cookies sans jetons portail |
| `all` | Tous les cookies sauf `_kc_portal*`, `_oauth2*`, `portal_breakglass_token` |

RÃ©ponse backend : `proxy_cookie_path / /proxy/{slug}/` + `proxy_cookie_domain off`.

### Redirects Location

`proxy_redirect` rÃ©Ã©crit les `Location` absolus vers `https://portal.ar-systems.fr/proxy/{slug}/â€¦`. CrushFTP : rÃ¨gle login.html â†’ new-ui appliquÃ©e **avant** les rÃ¨gles gÃ©nÃ©riques.

### VÃ©rification

Les headers `X-Preserve-Host`, `X-Forward-Cookies-Mode`, etc. ne sont renvoyÃ©s **que sur HTTP 200** (session SSO valide + droits). Avec un token ou cookie invalide, vous obtenez **401/403 sans ces headers** â€” un `grep` vide est normal dans ce cas.

**Ne pas copier les `...` de la doc** : ce sont des placeholders, pas des valeurs rÃ©elles.

```bash
# 1) Code dÃ©ployÃ© ? (aprÃ¨s AWX linux_sso_portal.yml â€” un simple reload nginx ne suffit pas)
test -f /opt/sso-portal/app/proxy_transform.py && echo OK proxy_transform
grep -q portal_upstream_host /var/lib/sso-portal/exports/nginx-portal-proxy.map.conf && echo OK maps
test -f /etc/nginx/snippets/proxy_portal_forwarded_backend.conf && echo OK snippet

# 2) Token interne rÃ©el (alignÃ© nginx + .env)
TOKEN=$(grep '^PORTAL_INTERNAL_TOKEN=' /opt/sso-portal/.env | cut -d= -f2-)

# 3) Sans cookie SSO â†’ 401 attendu (pas de headers policy)
curl -sI -H "X-Portal-Internal-Token: ${TOKEN}" \
  "http://127.0.0.1:8000/api/internal/resolve?slug=transfer" | head -5

# 4) Avec cookie SSO navigateur (DevTools â†’ Application â†’ Cookies â†’ _kc_portal_ar)
#    Copier la valeur complÃ¨te, pas "..."
curl -sI -H "X-Portal-Internal-Token: ${TOKEN}" \
  -H "Cookie: _kc_portal_ar=VOTRE_VALEUR_ICI" \
  "http://127.0.0.1:8000/api/internal/resolve?slug=transfer" \
  | grep -iE '^(HTTP|x-backend|x-preserve|x-forward-cookies|x-public-base|x-internal-origin)'

# 5) Test Python local (sans SSO) â€” doit afficher les clÃ©s
sudo -u sso-portal PYTHONPATH=/opt/sso-portal /opt/sso-portal/venv/bin/python3 -c "
from app.proxy_transform import ProxyContext, resolve_response_headers
ctx = ProxyContext(
    slug='transfer', portal_domain='portal.ar-systems.fr',
    public_base='https://portal.ar-systems.fr/proxy/transfer',
    internal_upstream='https://10.0.0.1', internal_origin='https://10.0.0.1',
    strip_prefix=True, preserve_host=False, forward_cookies_mode='safe',
)
print(resolve_response_headers(ctx, remote_user='test'))
"

# Content-Type / redirect aprÃ¨s auth navigateur (cookie session complet)
curl -sI "https://portal.ar-systems.fr/proxy/transfer/WebInterface/new-ui/" \
  -H "Cookie: _kc_portal_ar=VOTRE_VALEUR_ICI" \
  | grep -iE '^(HTTP|location|content-type|set-cookie)'
```

Logique de rÃ©fÃ©rence testÃ©e en Python : `roles/sso_portal/files/portal/app/proxy_transform.py`.

---

## 7. Checklist post-dÃ©ploiement

- [ ] `nginx -t` OK sur `vmdmz-reverse01`
- [ ] `curl -sI https://portal.ar-systems.fr/` â†’ redirection Keycloak si non auth
- [ ] `curl -sI https://wikijs.ar-systems.fr/` â†’ `200 OK` (pas de boucle)
- [ ] Tuile CrushFTP â†’ robotic SSO â†’ interface WebInterface
- [ ] Logout portail â†’ retour accueil sans boucle
- [ ] `/breakglass` accessible LAN uniquement
- [ ] Snippet `proxy_backend_forwarded.conf` prÃ©sent sur disque

---

## 8. RÃ©fÃ©rences Ansible / code

| Chemin | Sujet |
|--------|-------|
| `roles/sso_portal/templates/nginx-portal.conf.j2` | Vhost portail |
| `roles/sso_portal/templates/snippets/proxy_portal_transparent.conf.j2` | Proxy transparent |
| `roles/sso_portal/templates/snippets/proxy_portal_forwarded.conf.j2` | Headers portail â†’ FastAPI |
| `roles/sso_portal/templates/snippets/proxy_portal_forwarded_backend.conf.j2` | Headers portail â†’ backends internes |
| `roles/sso_portal/files/nginx-portal-proxy.map.conf` | Maps Host/cookies proxy |
| `roles/sso_portal/files/portal/app/proxy_transform.py` | Contrat rÃ©Ã©criture (tests) |
| `roles/nginx_reverse_proxy_dmz/templates/snippets_proxy_backend_forwarded.conf` | Headers vhosts classiques |
| `roles/nginx_reverse_proxy_dmz/templates/vhost_wikijs.conf.j2` | Wiki.js |
| `roles/sso_portal/templates/vhost-app.conf.j2` | Template vhost gÃ©nÃ©rique |
| `roles/nginx_reverse_proxy_dmz/files/wikijs-traefik-labels.example.yml` | Labels Docker Traefik |

---

## 9. Documentation wiki

| Page | Sujet |
|------|-------|
| [01 â€” Architecture globale](01-architecture-globale.md) | Vue d'ensemble du portail |
| [02 â€” Authentification SSO](02-authentification-sso.md) | OIDC, realms |
| [03 â€” Vault applicatif](03-vault-applicatif.md) | Robotic SSO |
| [05 â€” DÃ©veloppement applicatif](05-developpement-applicatif.md) | Python, packages, mises Ã  jour |

