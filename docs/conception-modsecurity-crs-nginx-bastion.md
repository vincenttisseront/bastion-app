# Conception — ModSecurity v3 + OWASP CRS (nginx-bastion)

> Document de conception (Phase A livrée, Phase B livrée).
> Origine : cadrage 2026-08-05 ; mises à jour post-cutover reverse01 **2026-08-06**.
> Ops live : [`ops-modsecurity-crs.md`](ops-modsecurity-crs.md).
> Audit pré-intégration : [`audit-preintegration-modsecurity-crs-nginx-bastion.md`](audit-preintegration-modsecurity-crs-nginx-bastion.md).

> **État prod au 2026-08-28** (ne pas confondre avec le §2 / §6 historiques) :
>
> | Famille | Connecteur | `SecRuleEngine` | Source |
> |---------|------------|-----------------|--------|
> | **portal** | `on` (export IHM) | **On** (blocage) | réactivation runbook 22/08 |
> | **subdomain_proxy** | **off** | Off | urgence 06/08, non rejouée |
> | **public_proxy** | **off** | Off | urgence 06/08, non rejouée |
>
> L’état intermédiaire « portal seul en On » est **volontaire** (runbook du 22/08 :
> première réactivation portal uniquement). **État cible inchangé** : les 3 familles en `On`.
> Chemin de remise : smoke §1 → `modsecurity on` + `DetectionOnly` par famille → dépouillement
> → `On` (public d’abord, subdomain ensuite). Voir [`ops-modsecurity-crs.md`](ops-modsecurity-crs.md)
> et le runbook subdomain/public (en préparation).

Décision moteur : **ModSecurity v3 (libmodsecurity) + OWASP CRS complet** (pas de règles
nginx natives légères, pas Coraza).

| Phase | Contenu | Statut |
|-------|---------|--------|
| **A** | Image CRS, règles statiques, 3 familles, DetectionOnly → On | **Livrée** (#106 DetectionOnly, #107 On) — smoke prod OK 2026-08-06 |
| **B** | IHM `/admin/security/waf`, générateur, profils/seuils/exclusions, headers edge, IP deny via `SecurityBanRule` | **Livrée** (réactivation IHM portal ; subdomain/public hors IHM) |

---

## 0. Topologie (post-cutover 2026-08-06)

`reverse01` est **décommissionné**. Traefik est **hors** du chemin ingress public bastion
(`bastion_require_traefik: false`).

```
Internet
   │
   ▼
Cloudflare (orange cloud — TLS edge CF, DDoS / WAF de base)
   │  CF-Connecting-IP
   ▼
nginx-bastion:443  (TLS ACME, ModSecurity/CRS, security-headers — #106/#107/#108)
   │
   ▼
:8080 interne
   ├── portal (vhost_sso_portal)
   ├── subdomain_proxy (auth_request)
   └── public_proxy
   │
   ▼
oauth2-proxy / bastion-app / upstreams
```

**Historique Phase A** (avant cutover) : `Internet → reverse01:443 → Traefik → nginx:8080`.

Conséquence : le WAF CRS ne vit que sur `nginx-bastion` (`docker/nginx/`).

`real_ip` est évalué **avant** ModSecurity (`nginx.conf` : `cloudflare-ips.conf` +
`real_ip_header CF-Connecting-IP` puis `include conf.d/*.conf` où `modsecurity on` est
posé par serveur). Les audits / futurs blocages IP voient l’IP client, pas une IP Cloudflare.

---

## 1. Image / build (Phase A — livré)

Base : `owasp/modsecurity-crs:4.28.0-nginx-alpine-202607160307` (tag pinné, jamais `latest`).
Module `ngx_http_modsecurity_module` chargé dans `nginx.conf`. CRS sous le layout image ;
conf bastion versionnée dans `docker/nginx/modsecurity/`.

---

## 2. Configuration ModSecurity (Phase A — livré)

Pas un unique `main.conf` global : **trois** règles files + **trois** engines (bascule /
rollback par famille) :

| Famille | Rules file | Engine |
|---------|------------|--------|
| portal | `main-portal.conf` | `engine-portal.conf` |
| subdomain | `main-subdomain.conf` | `engine-subdomain.conf` |
| public | `main-public.conf` | `engine-public.conf` |

Chaîne typique d’un `main-*.conf` : `modsecurity.conf` → `engine-*.conf` → `crs-setup.conf`
→ règles CRS → `includes/waf-basic.conf` (exclusions).

Réglages clés (`modsecurity.conf` / `crs-setup.conf`) :

- Audit JSON, `RelevantOnly`, log `/var/log/nginx/apps/modsec_audit.log` (volume `nginx-logs`)
- `SecRequestBodyAccess On`, `SecResponseBodyAccess Off`
- Paranoia level **1**, seuils anomalie inbound **5** / outbound **4**
- Engine : **`SecRuleEngine On`** sur les 3 familles (**2026-08-06**, pré-urgence — voir encart état prod 28/08)

---

## 3. Portée vhosts (Phase A — livré)

`modsecurity on` + `modsecurity_rules_file` sur portal, subdomain_proxy, public_proxy.

`modsecurity off` sur locations internes / santé (health, hops cookie, auth internes,
oauth2/static, etc.) — voir smoke dans [`ops-modsecurity-crs.md`](ops-modsecurity-crs.md).

---

## 4. Exclusions

Fichier : `docker/nginx/includes/waf-basic.conf` (vide tant qu’aucun FP confirmé).

Règle : exclusion **ciblée** (`SecRuleRemoveById` / `SecRuleUpdateTargetById`), jamais
désactivation d’une catégorie CRS entière ni `SecRuleEngine Off` global pour « faire taire »
un FP.

Candidats historiques (priorité revue à l’audit) : cookies SSO / CrushAuth, uploads admin,
JSON admin volumineux. `analyze-login-form` : body = `{url, tls_verify}` (HTML fetch côté
serveur) → risque FP plus bas que supposé initialement, à surveiller sans priorité maximale.

---

## 5. Audit, Host blacklist, anti-bruteforce

- **Audit ModSec** : flux distinct de l’audit applicatif ; ingestion SIEM future (hors Phase B
  stricte).
- **Blacklist par Host** (`discovered_hosts`) : reste **nginx / 403 applicatif**, pas une
  règle CRS par Host (outil inadapté).
- **Anti-bruteforce applicatif** : couche FastAPI indépendante du CRS (contenu requête).

---

## 6. Déploiement progressif — plan compressé

Plan initial : DetectionOnly 1–2 semaines → exclusions → On famille par famille
(`public_proxy` en dernier).

**Réel 2026-08-06** : cutover &lt; 7 j → #107 bascule **On** sur les 3 familles (risque
accepté). Smoke post-déploiement **OK** (Vincent, 2026-08-06). Rollback ops : une famille →
`DetectionOnly` (doc ops).

---

## 7. Livrables Phase A (référence)

Image CRS, engines / mains par famille, `waf-basic.conf`, activation vhosts + `off` santé,
volume + logrotate audit, tests `nginx -t` / wiring, [`ops-modsecurity-crs.md`](ops-modsecurity-crs.md).

---

## 8. Décisions actées

1. Image officielle OWASP CRS pinnée — acceptée.
2. Portée 3 familles dès le départ — livrée.
3. Seuils IHM future : défaut 5, bornés 3–10 (§9.3).
4. Host blacklist ≠ IP blacklist (§9.6).
5. Fenêtre DetectionOnly compressée + On immédiat — accepté au cutover.
6. Headers de sécurité : edge = **nginx-bastion** post-cutover (#108) — périmètre Phase B (§9.4).

---

## 9. Phase B — IHM de pilotage (à construire)

Prérequis : Phase A stable en `On` (**atteint**). Ne pas reconstruire le CRS de base
(fichiers `engine-*.conf` / règles image) depuis l’IHM au-delà des exports générés ci-dessous.

### 9.1 Architecture

Même pattern que `public_proxy` / `subdomain_proxy` :

```
/admin/security/waf  (UI, style /admin/security/banning)
        │
        ▼
app/bastion/nginx_waf_export.py
        │
        ▼
exports/ (ou docker/nginx/modsecurity/) :
  crs-setup-generated.conf
  bastion-exclusions-generated.conf
  waf-ip-deny.conf          ← deny/allow dérivés de SecurityBanRule / bans actifs
        │
        ▼
scripts/apply-infra-docker.sh → nginx -t → reload
```

**Navigation (2026-09)** : barre WAF en deux groupes — **Analyse** (Bilan : lecture +
graphiques + réponse incident) et **Configuration** (profil, exclusions, exports,
réactivation). Évite de mélanger réglages moteur et tableaux de menaces.

Modèles (famille `SecurityBanRule`) : `WafProfile`, `WafExclusion`, éventuellement
`WafRuleCategoryToggle` (toujours soumis aux verrouillages §9.2).

Audit : `security.waf.mode_changed`, `security.waf.exclusion_added`,
`security.waf.threshold_changed`, etc.

### 9.2 Verrouillages

| Paramètre | Modifiable IHM ? | Si ModSecurity = On |
|-----------|------------------|---------------------|
| Mode (Off / DetectionOnly / On) | Oui | — |
| Catégories CRS (SQLi, XSS, …) | **Non** | Toujours actives ; seule exclusion URI/host + règle précise |
| Protocol Enforcement | Non | Toujours on |
| Request Body Inspection | Non | Toujours on |
| Response Body Inspection | Oui | Défaut off |
| Unicode Mapping | Non | Toujours on |
| Audit (présence / format) | Présence non ; niveau oui | RelevantOnly + JSON |
| Rule engine / version CRS image | Non | Déploiement image |
| Seuil anomalie inbound | Oui, borné 3–10 | Défaut **5** |
| Headers HSTS / XFO / nosniff / Referrer / Permissions | Pas de désactivation unitaire silencieuse | Toujours présents (#108) ; expert seulement si un jour nécessaire |
| CSP / COOP / COEP / CORP | Oui **après** définition du contenu | Pas encore posés au cutover — sujet ouvert |

### 9.3 Profils prédéfinis

| | Développement | Préproduction | Production |
|---|---|---|---|
| Mode | DetectionOnly | On | On |
| CRS | Oui | Oui | Oui |
| Seuil anomalie | 10 | 7 | **5** |
| Rate limiting | Non | Oui | Oui |
| Headers edge (HSTS/…) | Présents (nginx-bastion :443) | Présents | Présents |
| Audit | Tous | RelevantOnly | RelevantOnly |
| Désactivation règles | Large (non exposé) | Ciblée | Ciblée |

Profil « custom » autorisé, toujours sous verrouillages §9.2.

### 9.4 En-têtes de sécurité (edge = nginx-bastion)

Principe F-09 « edge owns headers » : **conservé** ; l’edge est désormais `nginx-bastion:443`
(`includes/security-headers.conf` via `sync-acme-tls.sh`, une fois — pas sur `:8080`).

Phase B peut **piloter** (sans désactivation silencieuse unitaire) ces headers ; CSP/COOP/
COEP/CORP restent à définir avec ops avant contrôle IHM.

### 9.5 Rate limiting

Piloter les zones existantes `portal_login` / `portal_api` (seuils, burst) — **pas** de
nouvelles zones en parallèle. Rate limit subdomain/public_proxy = hors scope (lacune connue,
tâche séparée).

### 9.6 Blacklist IP — tranché (2026-08-06)

**Décision** : pas de second moteur de ban IP parallèle au module anti-bruteforce.

- L’IHM WAF / générateur nginx expose une **table deny IP/CIDR** au niveau nginx
  (`deny` / `allow`, pas des règles CRS par IP).
- Source de vérité = module banning existant : politiques `SecurityBanRule` + bans actifs
  `SecurityBan` (`target_type=ip`). Le générateur WAF **exporte** ces IP vers nginx ; pas de
  table SQLite « WAF-only » dupliquée.
- Complément de couches : FastAPI applique le ban au niveau app ; nginx peut **également**
  refuser plus tôt (défense en profondeur), sans UX ni stockage dupliqués.
- Distinct du blacklist **par Host** (`discovered_hosts`).

### 9.7 Workflow reload

Identique à `apply-infra-docker.sh` : générer → `nginx -t` → reload ; pas de restart complet ;
rollback si `nginx -t` échoue.

### 9.8 Réactivation IHM (2026-08-21)

Portal seulement : bouton **Réactiver** (`waf_reactivation.py`) arme
`waf-engine-arm.json` + switch `modsecurity on` + DetectionOnly, puis smoke HTTP
(`/_portal_nginx_ok`, `/api/health`, `/auth/login`). Échec → rollback Off automatique.
Sans armement, le sync force `SecRuleEngine Off`. Voir
[`runbook-reactivation-crs-modsecurity.md`](runbook-reactivation-crs-modsecurity.md).

---

## 10. Points ouverts (post Phase A)

1. ~~Phase A vs A+B~~ — **tranché** : A livrée ; B = prompt séparé.
2. Contenu CSP / COOP / COEP / CORP — à définir avant contrôle IHM.
3. ~~Blacklist IP WAF vs anti-bruteforce~~ — **tranché** (§9.6).
4. ~~Durée DetectionOnly~~ — compressée / close (smoke On OK).
5. Réactivation subdomain / public via IHM — **ouvert** (portal livré).
6. Passage DetectionOnly → On guidé IHM avec smoke — **ouvert** (On manuel après armement).

---

## 11. Notes d’audit (2026-08-05) — encore pertinentes

- Stub `waf-basic.conf` réutilisé comme exclusions (pas un second fichier mort).
- `real_ip` avant `conf.d` : confirmé ; post-cutover header = `CF-Connecting-IP`.
- Templates `nginx/vhosts/*.j2` = legacy ; live = `docker/nginx/`.
- Logrotate ModSec ajouté en Phase A (ne pas reproduire l’absence de rotation des autres logs).
- Pattern générateurs Python → exports → sync → `nginx -t` → reload = base Phase B.

---

## Références code (Phase A)

| Élément | Chemin |
|---------|--------|
| Dockerfile nginx | `docker/nginx/Dockerfile` |
| Engines / mains / crs-setup | `docker/nginx/modsecurity/` |
| Exclusions | `docker/nginx/includes/waf-basic.conf` |
| real_ip CF | `docker/nginx/includes/cloudflare-ips.conf`, `nginx.conf` |
| Headers edge | `docker/nginx/includes/security-headers.conf`, `sync-acme-tls.sh` |
| Ban IP existant | `app/models.py` (`SecurityBanRule`, `SecurityBan`), `app/security/banning/` |
| Réactivation IHM | `app/bastion/waf_reactivation.py`, `docs/runbook-reactivation-crs-modsecurity.md` |
| Ops | `docs/ops-modsecurity-crs.md` |
