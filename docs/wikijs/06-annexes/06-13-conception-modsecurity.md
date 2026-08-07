> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/conception-modsecurity-crs-nginx-bastion.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# Conception â€” ModSecurity v3 + OWASP CRS (nginx-bastion)

> Document de conception (Phase A livrÃ©e, Phase B Ã  venir).
> Origine : cadrage 2026-08-05 ; mises Ã  jour post-cutover reverse01 **2026-08-06**.
> Ops live : [`ops-modsecurity-crs.md`](ops-modsecurity-crs.md).
> Audit prÃ©-intÃ©gration : [`audit-preintegration-modsecurity-crs-nginx-bastion.md`](audit-preintegration-modsecurity-crs-nginx-bastion.md).

DÃ©cision moteur : **ModSecurity v3 (libmodsecurity) + OWASP CRS complet** (pas de rÃ¨gles
nginx natives lÃ©gÃ¨res, pas Coraza).

| Phase | Contenu | Statut |
|-------|---------|--------|
| **A** | Image CRS, rÃ¨gles statiques, 3 familles, DetectionOnly â†’ On | **LivrÃ©e** (#106 DetectionOnly, #107 On) â€” smoke prod OK 2026-08-06 |
| **B** | IHM `/admin/security/waf`, gÃ©nÃ©rateur, profils/seuils/exclusions, headers edge, IP deny via `SecurityBanRule` | **Ã€ implÃ©menter** (aprÃ¨s ce document) |

---

## 0. Topologie (post-cutover 2026-08-06)

`reverse01` est **dÃ©commissionnÃ©**. Traefik est **hors** du chemin ingress public bastion
(`bastion_require_traefik: false`).

```
Internet
   â”‚
   â–¼
Cloudflare (orange cloud â€” TLS edge CF, DDoS / WAF de base)
   â”‚  CF-Connecting-IP
   â–¼
nginx-bastion:443  (TLS ACME, ModSecurity/CRS, security-headers â€” #106/#107/#108)
   â”‚
   â–¼
:8080 interne
   â”œâ”€â”€ portal (vhost_sso_portal)
   â”œâ”€â”€ subdomain_proxy (auth_request)
   â””â”€â”€ public_proxy
   â”‚
   â–¼
oauth2-proxy / bastion-app / upstreams
```

**Historique Phase A** (avant cutover) : `Internet â†’ reverse01:443 â†’ Traefik â†’ nginx:8080`.

ConsÃ©quence : le WAF CRS ne vit que sur `nginx-bastion` (`docker/nginx/`).

`real_ip` est Ã©valuÃ© **avant** ModSecurity (`nginx.conf` : `cloudflare-ips.conf` +
`real_ip_header CF-Connecting-IP` puis `include conf.d/*.conf` oÃ¹ `modsecurity on` est
posÃ© par serveur). Les audits / futurs blocages IP voient lâ€™IP client, pas une IP Cloudflare.

---

## 1. Image / build (Phase A â€” livrÃ©)

Base : `owasp/modsecurity-crs:4.28.0-nginx-alpine-202607160307` (tag pinnÃ©, jamais `latest`).
Module `ngx_http_modsecurity_module` chargÃ© dans `nginx.conf`. CRS sous le layout image ;
conf bastion versionnÃ©e dans `docker/nginx/modsecurity/`.

---

## 2. Configuration ModSecurity (Phase A â€” livrÃ©)

Pas un unique `main.conf` global : **trois** rÃ¨gles files + **trois** engines (bascule /
rollback par famille) :

| Famille | Rules file | Engine |
|---------|------------|--------|
| portal | `main-portal.conf` | `engine-portal.conf` |
| subdomain | `main-subdomain.conf` | `engine-subdomain.conf` |
| public | `main-public.conf` | `engine-public.conf` |

ChaÃ®ne typique dâ€™un `main-*.conf` : `modsecurity.conf` â†’ `engine-*.conf` â†’ `crs-setup.conf`
â†’ rÃ¨gles CRS â†’ `includes/waf-basic.conf` (exclusions).

RÃ©glages clÃ©s (`modsecurity.conf` / `crs-setup.conf`) :

- Audit JSON, `RelevantOnly`, log `/var/log/nginx/apps/modsec_audit.log` (volume `nginx-logs`)
- `SecRequestBodyAccess On`, `SecResponseBodyAccess Off`
- Paranoia level **1**, seuils anomalie inbound **5** / outbound **4**
- Engine : **`SecRuleEngine On`** sur les 3 familles (2026-08-06)

---

## 3. PortÃ©e vhosts (Phase A â€” livrÃ©)

`modsecurity on` + `modsecurity_rules_file` sur portal, subdomain_proxy, public_proxy.

`modsecurity off` sur locations internes / santÃ© (health, hops cookie, auth internes,
oauth2/static, etc.) â€” voir smoke dans [`ops-modsecurity-crs.md`](ops-modsecurity-crs.md).

---

## 4. Exclusions

Fichier : `docker/nginx/includes/waf-basic.conf` (vide tant quâ€™aucun FP confirmÃ©).

RÃ¨gle : exclusion **ciblÃ©e** (`SecRuleRemoveById` / `SecRuleUpdateTargetById`), jamais
dÃ©sactivation dâ€™une catÃ©gorie CRS entiÃ¨re ni `SecRuleEngine Off` global pour Â« faire taire Â»
un FP.

Candidats historiques (prioritÃ© revue Ã  lâ€™audit) : cookies SSO / CrushAuth, uploads admin,
JSON admin volumineux. `analyze-login-form` : body = `{url, tls_verify}` (HTML fetch cÃ´tÃ©
serveur) â†’ risque FP plus bas que supposÃ© initialement, Ã  surveiller sans prioritÃ© maximale.

---

## 5. Audit, Host blacklist, anti-bruteforce

- **Audit ModSec** : flux distinct de lâ€™audit applicatif ; ingestion SIEM future (hors Phase B
  stricte).
- **Blacklist par Host** (`discovered_hosts`) : reste **nginx / 403 applicatif**, pas une
  rÃ¨gle CRS par Host (outil inadaptÃ©).
- **Anti-bruteforce applicatif** : couche FastAPI indÃ©pendante du CRS (contenu requÃªte).

---

## 6. DÃ©ploiement progressif â€” plan compressÃ©

Plan initial : DetectionOnly 1â€“2 semaines â†’ exclusions â†’ On famille par famille
(`public_proxy` en dernier).

**RÃ©el 2026-08-06** : cutover &lt; 7 j â†’ #107 bascule **On** sur les 3 familles (risque
acceptÃ©). Smoke post-dÃ©ploiement **OK** (Vincent, 2026-08-06). Rollback ops : une famille â†’
`DetectionOnly` (doc ops).

---

## 7. Livrables Phase A (rÃ©fÃ©rence)

Image CRS, engines / mains par famille, `waf-basic.conf`, activation vhosts + `off` santÃ©,
volume + logrotate audit, tests `nginx -t` / wiring, [`ops-modsecurity-crs.md`](ops-modsecurity-crs.md).

---

## 8. DÃ©cisions actÃ©es

1. Image officielle OWASP CRS pinnÃ©e â€” acceptÃ©e.
2. PortÃ©e 3 familles dÃ¨s le dÃ©part â€” livrÃ©e.
3. Seuils IHM future : dÃ©faut 5, bornÃ©s 3â€“10 (Â§9.3).
4. Host blacklist â‰  IP blacklist (Â§9.6).
5. FenÃªtre DetectionOnly compressÃ©e + On immÃ©diat â€” acceptÃ© au cutover.
6. Headers de sÃ©curitÃ© : edge = **nginx-bastion** post-cutover (#108) â€” pÃ©rimÃ¨tre Phase B (Â§9.4).

---

## 9. Phase B â€” IHM de pilotage (Ã  construire)

PrÃ©requis : Phase A stable en `On` (**atteint**). Ne pas reconstruire le CRS de base
(fichiers `engine-*.conf` / rÃ¨gles image) depuis lâ€™IHM au-delÃ  des exports gÃ©nÃ©rÃ©s ci-dessous.

### 9.1 Architecture

MÃªme pattern que `public_proxy` / `subdomain_proxy` :

```
/admin/security/waf  (UI, style /admin/security/banning)
        â”‚
        â–¼
app/bastion/nginx_waf_export.py
        â”‚
        â–¼
exports/ (ou docker/nginx/modsecurity/) :
  crs-setup-generated.conf
  bastion-exclusions-generated.conf
  waf-ip-deny.conf          â† deny/allow dÃ©rivÃ©s de SecurityBanRule / bans actifs
        â”‚
        â–¼
scripts/apply-infra-docker.sh â†’ nginx -t â†’ reload
```

ModÃ¨les (famille `SecurityBanRule`) : `WafProfile`, `WafExclusion`, Ã©ventuellement
`WafRuleCategoryToggle` (toujours soumis aux verrouillages Â§9.2).

Audit : `security.waf.mode_changed`, `security.waf.exclusion_added`,
`security.waf.threshold_changed`, etc.

### 9.2 Verrouillages

| ParamÃ¨tre | Modifiable IHM ? | Si ModSecurity = On |
|-----------|------------------|---------------------|
| Mode (Off / DetectionOnly / On) | Oui | â€” |
| CatÃ©gories CRS (SQLi, XSS, â€¦) | **Non** | Toujours actives ; seule exclusion URI/host + rÃ¨gle prÃ©cise |
| Protocol Enforcement | Non | Toujours on |
| Request Body Inspection | Non | Toujours on |
| Response Body Inspection | Oui | DÃ©faut off |
| Unicode Mapping | Non | Toujours on |
| Audit (prÃ©sence / format) | PrÃ©sence non ; niveau oui | RelevantOnly + JSON |
| Rule engine / version CRS image | Non | DÃ©ploiement image |
| Seuil anomalie inbound | Oui, bornÃ© 3â€“10 | DÃ©faut **5** |
| Headers HSTS / XFO / nosniff / Referrer / Permissions | Pas de dÃ©sactivation unitaire silencieuse | Toujours prÃ©sents (#108) ; expert seulement si un jour nÃ©cessaire |
| CSP / COOP / COEP / CORP | Oui **aprÃ¨s** dÃ©finition du contenu | Pas encore posÃ©s au cutover â€” sujet ouvert |

### 9.3 Profils prÃ©dÃ©finis

| | DÃ©veloppement | PrÃ©production | Production |
|---|---|---|---|
| Mode | DetectionOnly | On | On |
| CRS | Oui | Oui | Oui |
| Seuil anomalie | 10 | 7 | **5** |
| Rate limiting | Non | Oui | Oui |
| Headers edge (HSTS/â€¦) | PrÃ©sents (nginx-bastion :443) | PrÃ©sents | PrÃ©sents |
| Audit | Tous | RelevantOnly | RelevantOnly |
| DÃ©sactivation rÃ¨gles | Large (non exposÃ©) | CiblÃ©e | CiblÃ©e |

Profil Â« custom Â» autorisÃ©, toujours sous verrouillages Â§9.2.

### 9.4 En-tÃªtes de sÃ©curitÃ© (edge = nginx-bastion)

Principe F-09 Â« edge owns headers Â» : **conservÃ©** ; lâ€™edge est dÃ©sormais `nginx-bastion:443`
(`includes/security-headers.conf` via `sync-acme-tls.sh`, une fois â€” pas sur `:8080`).

Phase B peut **piloter** (sans dÃ©sactivation silencieuse unitaire) ces headers ; CSP/COOP/
COEP/CORP restent Ã  dÃ©finir avec ops avant contrÃ´le IHM.

### 9.5 Rate limiting

Piloter les zones existantes `portal_login` / `portal_api` (seuils, burst) â€” **pas** de
nouvelles zones en parallÃ¨le. Rate limit subdomain/public_proxy = hors scope (lacune connue,
tÃ¢che sÃ©parÃ©e).

### 9.6 Blacklist IP â€” tranchÃ© (2026-08-06)

**DÃ©cision** : pas de second moteur de ban IP parallÃ¨le au module anti-bruteforce.

- Lâ€™IHM WAF / gÃ©nÃ©rateur nginx expose une **table deny IP/CIDR** au niveau nginx
  (`deny` / `allow`, pas des rÃ¨gles CRS par IP).
- Source de vÃ©ritÃ© = module banning existant : politiques `SecurityBanRule` + bans actifs
  `SecurityBan` (`target_type=ip`). Le gÃ©nÃ©rateur WAF **exporte** ces IP vers nginx ; pas de
  table SQLite Â« WAF-only Â» dupliquÃ©e.
- ComplÃ©ment de couches : FastAPI applique le ban au niveau app ; nginx peut **Ã©galement**
  refuser plus tÃ´t (dÃ©fense en profondeur), sans UX ni stockage dupliquÃ©s.
- Distinct du blacklist **par Host** (`discovered_hosts`).

### 9.7 Workflow reload

Identique Ã  `apply-infra-docker.sh` : gÃ©nÃ©rer â†’ `nginx -t` â†’ reload ; pas de restart complet ;
rollback si `nginx -t` Ã©choue.

---

## 10. Points ouverts (post Phase A)

1. ~~Phase A vs A+B~~ â€” **tranchÃ©** : A livrÃ©e ; B = prompt sÃ©parÃ©.
2. Contenu CSP / COOP / COEP / CORP â€” Ã  dÃ©finir avant contrÃ´le IHM.
3. ~~Blacklist IP WAF vs anti-bruteforce~~ â€” **tranchÃ©** (Â§9.6).
4. ~~DurÃ©e DetectionOnly~~ â€” compressÃ©e / close (smoke On OK).

---

## 11. Notes dâ€™audit (2026-08-05) â€” encore pertinentes

- Stub `waf-basic.conf` rÃ©utilisÃ© comme exclusions (pas un second fichier mort).
- `real_ip` avant `conf.d` : confirmÃ© ; post-cutover header = `CF-Connecting-IP`.
- Templates `nginx/vhosts/*.j2` = legacy ; live = `docker/nginx/`.
- Logrotate ModSec ajoutÃ© en Phase A (ne pas reproduire lâ€™absence de rotation des autres logs).
- Pattern gÃ©nÃ©rateurs Python â†’ exports â†’ sync â†’ `nginx -t` â†’ reload = base Phase B.

---

## RÃ©fÃ©rences code (Phase A)

| Ã‰lÃ©ment | Chemin |
|---------|--------|
| Dockerfile nginx | `docker/nginx/Dockerfile` |
| Engines / mains / crs-setup | `docker/nginx/modsecurity/` |
| Exclusions | `docker/nginx/includes/waf-basic.conf` |
| real_ip CF | `docker/nginx/includes/cloudflare-ips.conf`, `nginx.conf` |
| Headers edge | `docker/nginx/includes/security-headers.conf`, `sync-acme-tls.sh` |
| Ban IP existant | `app/models.py` (`SecurityBanRule`, `SecurityBan`), `app/security/banning/` |
| Ops | `docs/ops-modsecurity-crs.md` |

