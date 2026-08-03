# Portail SSO AR-Systems — Dépannage Nginx et proxy

> **Sujet :** problèmes rencontrés en production, causes racines et correctifs appliqués dans `awx-playbook`.

> **Juillet 2026 — périmètre documentaire**  
> - **Sections 1.1–1.3, 1.4 (Wiki.js)** : DMZ infra (`nginx_reverse_proxy_dmz`) — **toujours valides**.  
> - **Sections 1.4 (portail), 2–4 (proxy `/proxy/`, CrushFTP subpath)** : **archivées** — templates retirés du dépôt (`e56fa58`).  
>   Reprise bastion : [SSO_PORTAL_BASTION_FEATURES_INVENTORY.md](../SSO_PORTAL_BASTION_FEATURES_INVENTORY.md).  
> - Dépannage portail catalogue/admin : [02-authentification-sso.md](02-authentification-sso.md), [SDD-002](../sdd/SDD-002-nginx-vhost-portail.md).

---

## 1. Boucles de redirection (`ERR_TOO_MANY_REDIRECTS`)

### 1.1 Symptômes

- Navigateur affiche « Trop de redirections » ;
- Logs Nginx : chaîne de **301** ou **308** avec corps de réponse très court (~17–18 octets) ;
- Affecte Wiki.js (`wikijs.ar-systems.fr`), parfois d'autres apps derrière Traefik.

### 1.2 Diagnostic : qui redirige ?

Depuis `vmdmz-reverse01` (ou tout hôte ayant accès au backend) :

```bash
# Test backend direct — HTTP
curl -sI -H "Host: wikijs.ar-systems.fr" http://10.0.31.112:80/

# Test backend direct — HTTPS
curl -sI -k -H "Host: wikijs.ar-systems.fr" https://10.0.31.112:443/

# Test via vhost public
curl -sI https://wikijs.ar-systems.fr/
```

| Résultat HTTP:80 | Interprétation |
|------------------|----------------|
| `308` / `301` → `https://wikijs...` | **Traefik** (ou backend) force HTTPS — coupable probable |
| `200 OK` | Backend OK en clair — chercher côté **Nginx DMZ** |

**Cas observé (juin 2026) :**

```
HTTP/1.1 308 Permanent Redirect
Location: https://wikijs.ar-systems.fr/
Content-Length: 18
```

Même avec `X-Forwarded-Proto: https` sur le port 80, Traefik redirige — la redirection globale `entrypoint web → websecure` ne peut pas être contournée par les seuls trust headers.

### 1.3 Correctifs appliqués

#### A. Backend HTTPS vers Traefik (Wiki.js)

Variables Ansible (`nginx_reverse_proxy_dmz`) :

```yaml
wikijs_backend_protocol: "https"
wikijs_backend_port: 443
```

Nginx DMZ se connecte à **Traefik websecure** au lieu du port 80.

#### B. Snippet trust headers partagé

Fichier : `/etc/nginx/snippets/proxy_backend_forwarded.conf`

```nginx
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto https;      # forcé — pas $scheme ambigu
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

Ce bloc ne s'applique **pas** aux connexions sortantes Nginx → backend.

#### D. Sonde Ansible

Le rôle `nginx_reverse_proxy_dmz` avertit si `http://backend:80/` renvoie une redirection alors que le backend configuré est HTTP.

### 1.4 Boucles côté portail SSO *(archivé — proxy `/proxy/` retiré)*

> Les scénarios `/proxy/slug`, `login.html` CrushFTP subpath et `portal_proxy_resolve` ne s'appliquent plus au déploiement actuel de `awx-playbook`. Conservés comme référence historique pour le dépôt applicatif.

| Scénario | Cause | Correctif |
|----------|-------|-----------|
| Login en boucle | `redirect_uri` Keycloak ≠ callback réel ; **rd= non encodé** (`/proxy/…` dans l'URL) ; refresh concurrent `invalid_grant` | Sign-in via FastAPI `/auth/sso-start` ; cache + verrou auth_request ; vider cookies `_kc_portal_*` |
| Transfer ↔ `/auth/login` (`ae=no-session:ck=72`) | Filtre CrushFTP `Cookie: CrushAuth=…` hérité par `auth_request` (FastAPI sans `bastion_session`) | 1) Rebuild **nginx + bastion-app** (≥ fix `proxy_pass_request_headers off` + capture `server{}`) 2) Apply (export avec `set $bastion_pass_cookie` au niveau server) 3) `grep -E 'pass_cookie|pass_request_headers|upstream_cookie'` 4) HAR : plus de `ck=72` |
| `/logout` boucle | 401 → sign_in | FastAPI détecte l'absence de session → `302 /` (plus d'`auth_request` sur `/logout`) |
| Popup login/mdp navigateur sur tuile CrushFTP | 401 + `WWW-Authenticate: Basic` du backend | `proxy_hide_header WWW-Authenticate` sur le proxy transparent ; vérifier robotic SSO (cookie CrushAuth, ban IP) |
| `/proxy/slug` boucle 401 | Session absente ou **oauth2_listen SQLite ≠ :4180 core** | Aligner realm ar-systems sur `OAUTH2_CORE_LISTEN` ; logs `PROXY-DEBUG` FastAPI |
| `login.html` boucle 302 | CrushFTP renvoie 302 → même login.html ; cookie `currentAuth-H-2` non transmis | `proxy_redirect` **avant** règle générique → `new-ui/` ; map nginx `currentAuth*` ; entrée `/proxy/transfer/` → `new-ui/` |
| Proxy resolve 403 | `internal_upstream` vide | Admin → éditer app → URL interne |

---

## 2. Erreur en-tête cookie > 4 Ko

### 2.1 Symptômes

- `400 Bad Request` — `Request Header Or Cookie Too Large` ;
- Échec logout oauth2-proxy ;
- CrushFTP / Java backend rejette la requête proxifiée.

### 2.2 Cause

Les cookies SSO cumulés (`_kc_portal_ar` + autres) dépassent la limite **~4 Ko** des en-têtes HTTP (nginx default `large_client_header_buffers 4 8k` insuffisant en edge cases).

### 2.3 Correctifs

#### A. Filtrage cookies vers backends proxifiés

`nginx-portal-proxy.map.conf` — map `$portal_proxy_backend_cookie` :

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

Éviter `backend_logout_url` oauth2-proxy — logout via Keycloak front-channel (`GET /logout` → `build_keycloak_front_channel_logout_url`). Voir document authentification.

#### D. Buffers oauth2-proxy locations

```nginx
proxy_buffer_size 128k;
proxy_buffers 8 128k;
```

Sur les locations `/oauth2/{realm}/` dans le fragment généré.

---

## 3. Réécriture HTML et URLs (`sub_filter` vs approche actuelle)

### 3.1 Contexte historique

Pour un proxy sous `/proxy/{slug}/`, les backends génèrent souvent :

- Des URLs absolues `/WebInterface/...` ;
- Des redirections `Location: /login` ;
- Des cookies avec `Path=/`.

Une approche classique consiste à utiliser **`sub_filter`** Nginx pour réécrire le HTML à la volée (`/href="/` → `/href="/proxy/transfer/`).

### 3.2 Approche retenue : pas de `sub_filter`

Le dépôt **n'utilise pas** `sub_filter` dans la configuration finale. Raisons :

| Inconvénient `sub_filter` | Alternative retenue |
|---------------------------|---------------------|
| Casse les réponses compressées (gzip) | `proxy_set_header Accept-Encoding ""` sur proxy transparent |
| Fragile sur JSON/API binaires | Pass-through URI — backend reçoit le chemin complet |
| Performance CPU | `proxy_redirect` regex pour les redirections HTTP |
| Double maintenance | `proxy_cookie_path / /proxy/$app_slug/` |

### 3.3 Mécanismes de réécriture actuels

**Pass-through URI** (`proxy_portal_transparent.conf.j2`) :

```nginx
proxy_pass $backend_upstream$request_uri;
```

CrushFTP ReverseProxy Path = `/proxy/transfer/` — le backend connaît son préfixe.

**Réécriture redirections** :

```nginx
proxy_redirect ~^(?:https?://[^/]+)?/(?!proxy/)(.*)$ /proxy/$app_slug/$1;
```

**Réécriture cookies backend** :

```nginx
proxy_cookie_path / /proxy/$app_slug/;
```

**MIME forcé pour assets statiques** (CrushFTP Content-Type incorrect) :

- Location dédiée `\.(css|js|…)$` avec `portal_proxy_fix_mime=true` ;
- `proxy_hide_header Content-Type` + `add_header Content-Type $portal_proxy_static_content_type`.

### 3.3 Si `sub_filter` était nécessaire (non recommandé)

```nginx
# Exemple NON déployé — référence uniquement
proxy_set_header Accept-Encoding "";
sub_filter_once off;
sub_filter 'href="/' 'href="/proxy/transfer/';
sub_filter_types text/html;
```

Préférer la configuration native du backend (ReverseProxy Path) avant d'activer `sub_filter`.

### 3.4 CrushFTP : assets 500/404 sur `/WebInterface/...` (sans `/proxy/transfer/`)

**Symptômes console navigateur :**

- `Failed to load resource: 500` sur `https://portal…/WebInterface/new-ui/assets/…`
- `Refused to apply style` / `Refused to execute script` — MIME `text/html` ou `application/json` au lieu de CSS/JS
- La page login s'affiche partiellement (HTML) mais sans styles ni scripts

**Cause :** CrushFTP génère des liens absolus `/WebInterface/…` parce que le **ReverseProxy Path** n'est pas configuré sur le serveur (`/proxy/transfer/`). Ces requêtes tombent sur FastAPI (`location /`) au lieu du bloc `location ~ ^/proxy/`.

**Cause (assets HTML / `Unexpected token '<'`) :** Nginx envoie un mauvais chemin au backend — le bloc `WebInterface/new-ui/` capturait un `proxy_rest` tronqué lors du **strip prefix** (`/init-js/…` au lieu de `/WebInterface/new-ui/init-js/…`). CrushFTP répond alors avec `login.html` (HTML) à la place du JS. Par défaut, CrushFTP **retire** `/proxy/{slug}/` avant le backend (ReverseProxy Path côté serveur rarement configuré).

**Correctif recommandé (CrushFTP Admin) :** Reverse Proxy Path = `/proxy/transfer/` (voir [03-vault-applicatif.md](03-vault-applicatif.md)). Si configuré, désactiver le strip prefix dans l'admin portail (case « Envoyer à la racine » — automatique pour CrushFTP sinon).

**Filet de sécurité Nginx** (`nginx-portal.conf.j2`, activé par défaut) :

```nginx
location ^~ /WebInterface/ {
    return 302 /proxy/transfer$request_uri;
}
```

**Réécriture HTML CrushFTP** (`sub_filter` sur `WebInterface/`) — réécrit `="/assets/` vers `/proxy/{slug}/WebInterface/new-ui/assets/` (pas de `<base href="/proxy/{slug}/">` qui envoyait les assets vers `/proxy/{slug}/assets/`).

**`login.html?path=/assets/…`** : Nginx redirige vers `/proxy/{slug}/WebInterface/new-ui/assets/…` (fichier CSS/JS direct, plus de HTML login).

Variables Ansible : `sso_portal_crushftp_webinterface_redirect_enabled`, `sso_portal_crushftp_webinterface_slug`, `sso_portal_crushftp_html_rewrite`.

**Cause (page noire `/WebInterface/new-ui/`) :** `portal_proxy_fix_mime=true` sur le bloc new-ui catch-all masquait le `Content-Type` HTML (URI sans extension → map vide → page noire). Les assets `.css`/`.js` doivent passer par le bloc extensions **avant** le catch-all new-ui.

**Bruit sans lien :** les logs `background.js` / Bitwarden dans la console sont une extension navigateur, pas le portail.

---

## 4. `X-Forwarded-Proto` et Traefik / Wiki.js

### 4.1 Problème

Nginx termine TLS (`listen 443 ssl`). La connexion Nginx → backend est souvent **HTTP** (port 80 ou 443 interne). Sans en-tête explicite, Traefik/Wiki.js croit que le client est en **HTTP** et redirige vers HTTPS → boucle.

### 4.2 Règle absolue

Sur tout vhost `listen 443 ssl` qui proxifie vers un backend :

```nginx
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-Ssl on;
```

**Ne pas utiliser** `$scheme` si le contexte peut être ambigu ; le portail force désormais `https` dans `proxy_portal_forwarded.conf.j2`.

### 4.3 Backend HTTPS vers Traefik

Quand Traefik a une redirection globale port 80 → 443, configurer :

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

Côté Wiki.js (hors Ansible portail) :

- `ssl.enabled: false` si Nginx gère le TLS ;
- URL publique = `https://wikijs.ar-systems.fr` ;
- `trustProxy: true` dans `config.yml` pour honorer `X-Forwarded-*`.

Labels Traefik documentés : `roles/nginx_reverse_proxy_dmz/files/wikijs-traefik-labels.example.yml`.

---

## 5. Autres problèmes proxy documentés

### 5.1 `proxy_pass_request_headers off`

Le proxy transparent **désactive** le forward automatique des en-têtes client. Seuls les en-têtes listés explicitement partent vers le backend — évite les fuites de cookies SSO.

### 5.2 `Connection: close`

CrushFTP (Java legacy) : HTTP/1.1 avec connexion fermée après chaque requête pour éviter les connexions pendantes.

### 5.3 Résolution DNS dynamique

```nginx
resolver 127.0.0.1 8.8.8.8 valid=30s;
```

Requis pour `proxy_pass $backend_upstream` (variable).

### 5.4 Erreur `nginx -t` — snippets manquants

Les snippets portail doivent exister **avant** le test :

- Rôle `sso_portal/tasks/nginx_snippets.yml` ;
- Import dans `nginx_reverse_proxy_dmz` avant `nginx -t`.

Fichiers requis :

- `proxy_portal_forwarded.conf`
- `proxy_portal_forwarded_backend.conf` (backends internes — sans override Host)
- `proxy_portal_transparent.conf`
- `proxy_portal_fastapi.conf`
- `proxy_backend_forwarded.conf` (vhosts classiques)

### 5.5 Logs utiles

| Log | Contenu |
|-----|---------|
| `/var/log/nginx/portal.error.log` | Erreurs auth_request, proxy |
| `/var/log/nginx/wikijs.error.log` | Wiki.js vhost classique |
| `journalctl -u sso-portal` | `PROXY-DEBUG:` résolution slug |
| `journalctl -u oauth2-proxy-portal-*` | Erreurs OIDC |

### 5.6 Commandes de diagnostic

```bash
# Test auth interne (depuis DMZ)
curl -sI http://127.0.0.1:8000/health

# Test resolve proxy (nécessite token réel + cookie SSO pour HTTP 200)
TOKEN=$(grep '^PORTAL_INTERNAL_TOKEN=' /opt/sso-portal/.env | cut -d= -f2-)
curl -sI -H "X-Portal-Internal-Token: ${TOKEN}" \
  -H "Cookie: _kc_portal_ar=VOTRE_COOKIE" \
  "http://127.0.0.1:8000/api/internal/resolve?slug=transfer"

# Config nginx active
nginx -T | grep -A5 "proxy_set_header X-Forwarded"

# Vérifier snippet déployé
cat /etc/nginx/snippets/proxy_backend_forwarded.conf
```

---

## 6. Matrice récapitulative

| Problème | Indicateur | Correctif principal | Fichier clé |
|----------|------------|---------------------|-------------|
| Boucle 301/308 | `curl` backend :80 → 308 | Backend `https:443` + trust headers | `vhost_wikijs.conf.j2`, `vars/main.yml` |
| Cookie > 4 Ko | 400 header too large | Filtrage cookies proxy | `nginx-portal-proxy.map.conf` |
| HTML cassé en proxy | CSS/JS 404 | Pass-through URI + `proxy_redirect` | `proxy_portal_transparent.conf.j2` |
| Backend pense HTTP | Redirection SSL | `X-Forwarded-Proto https` forcé | `proxy_backend_forwarded.conf` |
| Logout échoue | 400 au logout | SLO front-channel Keycloak | `main.py`, `realm_service.py` |
| `nginx -t` fail | snippet not found | `nginx_snippets.yml` avant vhost | `tasks/nginx_snippets.yml` |
| Host backend rejeté | 502/403 côté app interne | `Host` = netloc interne, `X-Forwarded-Host` = portail | `proxy_portal_forwarded_backend.conf`, map `portal_upstream_host` |
| Redirect vers IP privée | Navigateur bloque ou quitte le proxy | `proxy_redirect` + `X-Internal-Origin` | `proxy_portal_transparent.conf.j2` |
| Cookies backend absents | Session perdue entre requêtes | `forward_cookies_mode` + `proxy_cookie_path` | `nginx-portal-proxy.map.conf`, admin app |
| Collision cookies SSO | Backend Java crash / 400 header | Mode `safe` (CrushAuth) ou `all` sans `_kc_*` | `nginx-portal-proxy.map.conf` |

---

## 6.1 Proxy transparent — Host, cookies et redirects (juin 2026)

### Host header

Par défaut (`preserve_host=false`), Nginx envoie au backend :

| Header | Valeur |
|--------|--------|
| `Host` | Netloc interne (`10.x.x.x:443`) |
| `X-Forwarded-Host` | `portal.ar-systems.fr` |
| `X-Forwarded-Prefix` | `/proxy/{slug}` |

Si l'application exige le hostname public, activer **Preserve Host** dans l'admin bastion.

**Piège corrigé :** l'ancien snippet `proxy_portal_forwarded.conf` écrasait `Host $backend_host` avec `Host $host`. Le proxy transparent inclut désormais `proxy_portal_forwarded_backend.conf` (sans ligne `Host`).

### Cookies

Politique pilotée par `/api/internal/resolve` → `X-Forward-Cookies-Mode` :

| Mode | Comportement |
|------|--------------|
| `none` | Aucun cookie vers le backend |
| `safe` | CrushAuth/currentAuth si présents, sinon cookies sans jetons portail |
| `all` | Tous les cookies sauf `_kc_portal*`, `_oauth2*`, `portal_breakglass_token` |

Réponse backend : `proxy_cookie_path / /proxy/{slug}/` + `proxy_cookie_domain off`.

### Redirects Location

`proxy_redirect` réécrit les `Location` absolus vers `https://portal.ar-systems.fr/proxy/{slug}/…`. CrushFTP : règle login.html → new-ui appliquée **avant** les règles génériques.

### Vérification

Les headers `X-Preserve-Host`, `X-Forward-Cookies-Mode`, etc. ne sont renvoyés **que sur HTTP 200** (session SSO valide + droits). Avec un token ou cookie invalide, vous obtenez **401/403 sans ces headers** — un `grep` vide est normal dans ce cas.

**Ne pas copier les `...` de la doc** : ce sont des placeholders, pas des valeurs réelles.

```bash
# 1) Code déployé ? (après AWX linux_sso_portal.yml — un simple reload nginx ne suffit pas)
test -f /opt/sso-portal/app/proxy_transform.py && echo OK proxy_transform
grep -q portal_upstream_host /var/lib/sso-portal/exports/nginx-portal-proxy.map.conf && echo OK maps
test -f /etc/nginx/snippets/proxy_portal_forwarded_backend.conf && echo OK snippet

# 2) Token interne réel (aligné nginx + .env)
TOKEN=$(grep '^PORTAL_INTERNAL_TOKEN=' /opt/sso-portal/.env | cut -d= -f2-)

# 3) Sans cookie SSO → 401 attendu (pas de headers policy)
curl -sI -H "X-Portal-Internal-Token: ${TOKEN}" \
  "http://127.0.0.1:8000/api/internal/resolve?slug=transfer" | head -5

# 4) Avec cookie SSO navigateur (DevTools → Application → Cookies → _kc_portal_ar)
#    Copier la valeur complète, pas "..."
curl -sI -H "X-Portal-Internal-Token: ${TOKEN}" \
  -H "Cookie: _kc_portal_ar=VOTRE_VALEUR_ICI" \
  "http://127.0.0.1:8000/api/internal/resolve?slug=transfer" \
  | grep -iE '^(HTTP|x-backend|x-preserve|x-forward-cookies|x-public-base|x-internal-origin)'

# 5) Test Python local (sans SSO) — doit afficher les clés
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

# Content-Type / redirect après auth navigateur (cookie session complet)
curl -sI "https://portal.ar-systems.fr/proxy/transfer/WebInterface/new-ui/" \
  -H "Cookie: _kc_portal_ar=VOTRE_VALEUR_ICI" \
  | grep -iE '^(HTTP|location|content-type|set-cookie)'
```

Logique de référence testée en Python : `roles/sso_portal/files/portal/app/proxy_transform.py`.

---

## 7. Checklist post-déploiement

- [ ] `nginx -t` OK sur `vmdmz-reverse01`
- [ ] `curl -sI https://portal.ar-systems.fr/` → redirection Keycloak si non auth
- [ ] `curl -sI https://wikijs.ar-systems.fr/` → `200 OK` (pas de boucle)
- [ ] Tuile CrushFTP → robotic SSO → interface WebInterface
- [ ] Logout portail → retour accueil sans boucle
- [ ] `/breakglass` accessible LAN uniquement
- [ ] Snippet `proxy_backend_forwarded.conf` présent sur disque

---

## 8. Références Ansible / code

| Chemin | Sujet |
|--------|-------|
| `roles/sso_portal/templates/nginx-portal.conf.j2` | Vhost portail |
| `roles/sso_portal/templates/snippets/proxy_portal_transparent.conf.j2` | Proxy transparent |
| `roles/sso_portal/templates/snippets/proxy_portal_forwarded.conf.j2` | Headers portail → FastAPI |
| `roles/sso_portal/templates/snippets/proxy_portal_forwarded_backend.conf.j2` | Headers portail → backends internes |
| `roles/sso_portal/files/nginx-portal-proxy.map.conf` | Maps Host/cookies proxy |
| `roles/sso_portal/files/portal/app/proxy_transform.py` | Contrat réécriture (tests) |
| `roles/nginx_reverse_proxy_dmz/templates/snippets_proxy_backend_forwarded.conf` | Headers vhosts classiques |
| `roles/nginx_reverse_proxy_dmz/templates/vhost_wikijs.conf.j2` | Wiki.js |
| `roles/sso_portal/templates/vhost-app.conf.j2` | Template vhost générique |
| `roles/nginx_reverse_proxy_dmz/files/wikijs-traefik-labels.example.yml` | Labels Docker Traefik |

---

## 9. Documentation wiki

| Page | Sujet |
|------|-------|
| [01 — Architecture globale](01-architecture-globale.md) | Vue d'ensemble du portail |
| [02 — Authentification SSO](02-authentification-sso.md) | OIDC, realms |
| [03 — Vault applicatif](03-vault-applicatif.md) | Robotic SSO |
| [05 — Développement applicatif](05-developpement-applicatif.md) | Python, packages, mises à jour |
