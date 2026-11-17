# Pages d'erreur du bastion

Toute erreur servie par le bastion à un navigateur est une page aux couleurs du portail : jamais de « 502 Bad Gateway / nginx », de JSON `{"detail": …}` ou de page oauth2-proxy brute. Les clients non navigateur (ActiveSync, M2M, `/api/*`) reçoivent du texte ou du JSON.

## Deux familles de pages

| Famille | Source | Rendu | Quand |
|---|---|---|---|
| Pages FastAPI | `app/templates/errors/*.html` (`/errors/403`, `404`, `429`, `503`…) | Langue de l'utilisateur, Admin → Branding (nom, couleurs) | Erreurs de l'app, et 403/404/429/503 générés par nginx sur le portail quand bastion-app répond |
| Pages statiques | `app/web/static_error_pages.py` + `app/templates/errors/static_page.html` → `docker/nginx/errors/` | FR + EN, charte par défaut du portail (sombre, clair selon l'OS), CSS/SVG inline, sans nom de produit ni de société | Tout le reste : nginx les sert lui-même, même si bastion-app ou l'upstream de l'app est tombé |

Chaque code existe en trois variantes, `<code>.html` (navigateurs), `<code>.json` (`{"code", "message"}`, comme `app/api_errors.py`) et `<code>.txt` (EAS, M2M), plus `unknown-host.html`, le 403 neutre des hôtes inconnus.

Pour régénérer après une modification du catalogue ou du gabarit (le test `tests/test_branded_error_pages.py` échoue sinon) :

```bash
python scripts/generate_nginx_error_pages.py
```

## Inventaire des sources d'erreur

### bastion-app (FastAPI)

| Source | Avant | Maintenant |
|---|---|---|
| `HTTPException` 403/404/429/503, 500 non gérée | Gabarits `errors/*.html` (JSON pour `/api/*` et `Accept: application/json`) | Inchangé |
| 400/405/413/422 en HTML (`_html_client_error_response`) | `errors/400.html` affichait toujours « 400 » | Affiche le vrai code |
| 401 HTML | Redirection `/auth/login` | Inchangé |
| `CrossOriginWriteMiddleware` (CSRF cross-origin) | `{"detail":"Cross-origin request blocked"}` même pour un `<form>` cross-site | Page 403 pour une navigation, JSON sinon |
| `SecurityBanMiddleware` (ban 403, limite 429, pré-contrôle 503) | JSON pour tout le monde | Page 403/429/503 pour une navigation (même statut, même `Retry-After`), JSON pour API/XHR/fetch |
| Exception non gérée sous `/api/*` | `Internal Server Error` en texte (Starlette) | Inchangé, non HTML |
| `/internal/unknown-host` | 403 neutre | Inchangé, et repli statique neutre si bastion-app est tombé |

### bastion-nginx, portail (`vhost_sso_portal.conf.template`)

Le relais vers `/errors/*` de FastAPI n'a jamais fonctionné. Avec `proxy_intercept_errors on` hérité du serveur, la réponse 403/404/429/500 de FastAPI était ré-interceptée, et comme `recursive_error_pages` est à `off`, nginx renvoyait sa page par défaut. De plus, les `location` qui déclarent `error_page 401` (`/`, `/admin`, `/dashboard`, `/api/*`) n'héritent pas de la liste du serveur.

| Erreur | Cause typique | Avant (banc v0.11.8) | Maintenant |
|---|---|---|---|
| 403 | WAF CRS, `deny` (`/breakglass` hors LAN), callback oauth2-proxy | nginx brut | Page FastAPI, statique si bastion-app est tombé |
| 404 | `/internal/*`, fichiers cachés | nginx brut | Page FastAPI, avec repli statique |
| 429 | `limit_req` (login, API, navigation) | nginx brut | Page FastAPI (HTML), JSON statique sous `/api/*` |
| 500 | `auth_request` en échec (bastion-app tombé) | nginx brut | Page statique (HTML ou JSON) |
| 502 / 504 | bastion-app ou oauth2-proxy injoignable, ou trop lent | nginx brut | Page statique (HTML, ou JSON pour `/api/*`, `/health`) |
| 400 / 413 / 414 / 494 / 495 / 496 | En-tête Host invalide, corps > 32 Mo, URI ou cookies trop gros, certificat client | nginx brut | Page statique |
| oauth2-proxy 403/500 | CSRF / state du callback | Page oauth2-proxy brute | Page du portail (`proxy_intercept_errors on` sur `/oauth2/*`) |
| Hôte inconnu | catch-all | 403 neutre (FastAPI) | Inchangé, et repli neutre statique si bastion-app est tombé ou en cas de limitation |

Le portail passe à `proxy_intercept_errors off` : les réponses de FastAPI (pages, JSON, `Retry-After`) passent telles quelles. Seules les erreurs générées par nginx sont remplacées. Un 401 renvoyé par FastAPI lui-même (et non par `auth_request`) arrive donc au client au lieu d'être converti en 302 vers la connexion. En HTML, FastAPI redirige déjà lui-même vers `/auth/login`.

### bastion-nginx, bord TLS (`sync-acme-tls.sh`, :80 et :443)

400 (Host invalide), 494 (en-têtes > 8 Ko), 413 (> 2 Go) et 502/504 (:8080 injoignable) donnent une page statique. 497 (HTTP en clair sur :443) donne une redirection 301 vers l'URL HTTPS.

### Vhosts d'applications générés (`subdomain_proxy`, `public_proxy`, MTA-STS, infra-proxy Ansible)

| Location | Avant | Maintenant |
|---|---|---|
| `location /` (navigateur) | 502/504 upstream, 500 `auth_request`, 413 en nginx brut (avec la version) | Page HTML statique ; 401/403/503 → redirection portail inchangée |
| `@portal_redirect` (fetch/XHR) | `return 401` = page HTML nginx | 401 JSON `{"code":"unauthorized",…}` |
| ActiveSync / Autodiscover | 429, 500, 502 en HTML nginx | `text/plain` ; le 401 garde `WWW-Authenticate: Basic realm="ActiveSync"` ; le 401 de grommunio passe tel quel |
| Chemins M2M (`m2m_bypass_paths`) | 502 en HTML nginx | `text/plain` |
| Réponses de l'application elle-même | — | Inchangées (`proxy_intercept_errors off`) |

Les exports générés incluent les directives en ligne, sans nouvel `include`. Un export écrit par un bastion-app plus récent passe donc toujours `nginx -t` sur une image bastion-nginx plus ancienne : au pire, la page manquante redevient la page nginx par défaut.

### Hors périmètre

- `nginx/` (gabarits Jinja de l'ancien déploiement DMZ / AWX) : non modifié, la production passe par `docker/nginx/`.
- oauth2-proxy `custom_templates_dir` : non utilisé. Ses pages ne sont visibles qu'à travers nginx, qui les remplace. Avec `skip_provider_button = true`, la page de connexion d'oauth2-proxy n'est jamais affichée.
- Les corps des redirections 301/302 restent ceux de nginx : les navigateurs ne les affichent pas.
