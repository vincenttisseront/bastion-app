> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/ops-modsecurity-crs.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# Ops â€” ModSecurity v3 + OWASP CRS (nginx-bastion)

**Statut (2026-08-06 soir)** : **EMERGENCY Off** sur les 3 familles
(`modsecurity off` + `SecRuleEngine Off`). Cause : HTTP **500** sur tout chemin ModSec
(`/auth/login`, `/`, â€¦) alors que `/api/health` (`modsecurity off`) restait 200.
`crs-setup-generated` a Ã©tÃ© Ã©cartÃ© (#113) â€” le 500 persistait avec CRS + engine On.
Re-activer uniquement aprÃ¨s root cause (`error.log` nginx / debug ModSec).

| Famille | Fichier | Engine | Date |
|---------|---------|--------|------|
| portal | `engine-portal.conf` | **Off** | 2026-08-06 emergency |
| subdomain_proxy | `engine-subdomain.conf` | **Off** | 2026-08-06 emergency |
| public_proxy | `engine-public.conf` | **Off** | 2026-08-06 emergency |

Exclusions custom : aucune (`waf-basic.conf` vide) tant quâ€™aucun faux positif nâ€™est
confirmÃ© en prod. Ajouter uniquement des `SecRuleRemoveById` /
`SecRuleUpdateTargetById` ciblÃ©s â€” jamais dÃ©sactiver une catÃ©gorie CRS entiÃ¨re.

PrÃ©requis audit : [`audit-preintegration-modsecurity-crs-nginx-bastion.md`](audit-preintegration-modsecurity-crs-nginx-bastion.md).
Conception (Phase A livrÃ©e / Phase B) :
[`conception-modsecurity-crs-nginx-bastion.md`](conception-modsecurity-crs-nginx-bastion.md).
Image : `owasp/modsecurity-crs:4.28.0-nginx-alpine-202607160307` (nginx **1.30.4**, Ã©cart
acceptÃ© vs ancien `nginx:1.27-alpine`).

## Emplacements clÃ©s

| Ã‰lÃ©ment | Chemin |
|---------|--------|
| Rules files par famille | `docker/nginx/modsecurity/main-{portal,subdomain,public}.conf` |
| Bascule engine | `docker/nginx/modsecurity/engine-{portal,subdomain,public}.conf` |
| Core ModSec | `docker/nginx/modsecurity/modsecurity.conf` |
| CRS setup (PL1, seuils 5/4) | `docker/nginx/modsecurity/crs-setup.conf` |
| Exclusions custom | `docker/nginx/includes/waf-basic.conf` |
| Audit log | `/var/log/nginx/apps/modsec_audit.log` (volume Compose `nginx-logs`) |
| Rotation | `docker/nginx/logrotate.d/modsecurity` (crond dans lâ€™entrypoint) |

## Smoke post-deploy (bloquant avant / aprÃ¨s `On`)

Sur docker01, aprÃ¨s rebuild/reload `bastion-nginx` :

1. Login SSO â†’ dashboard
2. Un flux `subdomain_proxy` (ex. CrushFTP)
3. Un flux `public_proxy`
4. `POST /admin/apps/analyze-login-form` avec une URL lÃ©gitime
5. Locations `modsecurity off` : **aucune** ligne correspondante dans
   `/var/log/nginx/apps/modsec_audit.log` (health, hops cookie, auth internes,
   oauth2/static, `/.bastion/session-cookies`, `/healthz` public)

```bash
docker exec bastion-nginx nginx -t
docker exec bastion-nginx tail -n 100 /var/log/nginx/apps/modsec_audit.log
```

Si faux positif : exclusion ciblÃ©e dans `waf-basic.conf`, rebuild/reload, re-smoke â€”
**ne pas** repasser toute une famille en `DetectionOnly` sauf rollback dâ€™urgence.

## Lire `modsec_audit.log`

Sur lâ€™hÃ´te (volume data) :

```bash
sudo tail -f /tools/portal/data/nginx-logs/modsec_audit.log
# ou chemin SSO_PORTAL_DATA_DIR/.../nginx-logs/modsec_audit.log
```

Dans le conteneur :

```bash
docker exec bastion-nginx tail -n 50 /var/log/nginx/apps/modsec_audit.log
```

Format : **JSON** (`SecAuditLogFormat JSON`). Filtrer une URI :

```bash
docker exec bastion-nginx grep '"uri":"/apps"' /var/log/nginx/apps/modsec_audit.log | tail
```

## Rollback immÃ©diat (une famille)

Remettre **un seul** `engine-*.conf` en `SecRuleEngine DetectionOnly`, rebuild/reload :

```bash
docker exec bastion-nginx nginx -t && docker exec bastion-nginx nginx -s reload
```

Ordre de re-activation aprÃ¨s exclusion : portal â†’ subdomain â†’ public_proxy.

Ne pas utiliser un unique `SecRuleEngine` global dans `modsecurity.conf` (volontairement
absent) : cela empÃªcherait la bascule / le rollback progressifs.

## Ajouter une exclusion dans `waf-basic.conf`

Fichier inclus **aprÃ¨s** les rÃ¨gles CRS (syntaxe ModSecurity uniquement â€” ne pas
`include` nginx ce fichier).

Exemples :

```
# DÃ©sactiver une rÃ¨gle CRS prÃ©cise
SecRuleRemoveById 942100

# Retirer une cible dâ€™argument sensible dâ€™une rÃ¨gle
SecRuleUpdateTargetById 942100 "!ARGS:password"
```

Puis rebuild ou monter le fichier + `nginx -s reload` selon le mode de dÃ©ploiement.

## IHM Phase B â€” `/admin/security/waf`

Pilotage des **overlays gÃ©nÃ©rÃ©s** uniquement (ne remplace pas `engine-*.conf`,
`crs-setup.conf` paranoia, ni `waf-basic.conf` manuel) :

| Export | RÃ´le |
|--------|------|
| `exports/modsecurity/crs-setup-generated.conf` | Seuil anomalie (id **1000900110**) â€” **non chargÃ©** par `main-*.conf` (seuils = static `crs-setup.conf` id 900110). Filet anti-500 si export stale `901110`. |
| `exports/modsecurity/engine-mode-generated.conf` | `SecRuleEngine` profil (inclus en dernier) |
| `exports/modsecurity/bastion-exclusions-generated.conf` | Exclusions UI aprÃ¨s `waf-basic.conf` |
| `exports/waf-ip-deny.conf` | `deny` IP promues depuis `SecurityBan` |
| `exports/nginx-portal-rate-limits.conf` | Zones `portal_login` / `portal_api` |
| `exports/modsecurity/waf-effective-status.json` | Statut lu par lâ€™IHM |

### Utilisation

1. Admin â†’ **WAF** : choisir profil (Production / PrÃ©production / DÃ©veloppement / Custom),
   mode, seuil (3â€“10), min. occurrences IP deny (dÃ©faut **3**).
2. Ajouter exclusions (raison + ID rÃ¨gle CRS + host ou URI) â€” dÃ©sactivation soft (historique).
3. **Appliquer** : gÃ©nÃ¨re les exports â†’ `nginx -t` (docker exec si dispo) â†’ en Ã©chec,
   restauration des `*.prev` (pas de reload de conf cassÃ©e). Sinon le watcher nginx
   (`watch-exports-reload`) synchronise et reload.

### Incident â€” HTTP 500 partout sauf `/api/health`

**Chronologie 2026-08-06 :**
1. Overlay `id:901110` (collision CRS) â€” fix #111/#112/#113 (Include retirÃ©).
2. AprÃ¨s #113 : stub gÃ©nÃ©rÃ© OK, **pas** dâ€™Include `crs-setup-generated`, export dÃ©jÃ 
   `1000900110` â€” **`/auth/login` toujours 500**. Donc pas (seulement) lâ€™overlay seuil.
3. Mitigation : **`modsecurity off`** serveur + `SecRuleEngine Off` + ne plus Inclure
   `engine-mode-generated` (le profil WAF DB `mode=on` forÃ§ait On en dernier).

**Contournement immÃ©diat (sans rebuild)** :

```bash
docker exec bastion-nginx sh -c '
  sed -i "s/modsecurity on;/modsecurity off;/g" /etc/nginx/conf.d/vhost_sso_portal.conf
  for f in /etc/nginx/conf.d/nginx-subdomain-apps.conf /etc/nginx/conf.d/nginx-public-proxy-apps.conf /etc/nginx/conf.d/nginx-acme-tls.conf; do
    [ -f "$f" ] && sed -i "s/modsecurity on;/modsecurity off;/g" "$f"
  done
  nginx -t && nginx -s reload
'
docker exec bastion-nginx wget -S -O /dev/null \
  --header="Host: portal.ar-systems.fr" http://127.0.0.1:8080/auth/login 2>&1 | head
```

Diag utile si 500 revient aprÃ¨s re-enable :

```bash
docker exec bastion-nginx tail -n 80 /var/log/nginx/error.log
docker exec bastion-nginx ls -la /tmp/modsecurity /var/log/nginx/apps/modsec_audit.log
```

### Rollback via IHM

Profil WAF â†’ mode **Off** (ou DetectionOnly), **Enregistrer**, puis **Appliquer**.
Ne pas repasser en **On** tant que le smoke `/auth/login` nâ€™est pas vert avec ModSec on.

### Promotion IP deny

Un ban `SecurityBan` (`target_type=ip`) nâ€™apparaÃ®t dans nginx que sâ€™il est **actif** et
(**permanent** OU historique `count >= ip_deny_min_occurrences`). Un seul Ã©chec de login
ne rÃ©gÃ©nÃ¨re pas la liste deny.

## Notes dâ€™exploitation

- **`/healthz` subdomain_proxy** : absent de lâ€™export Python (prÃ©sent seulement dans le
  j2 DMZ legacy). Ne pas ajouter une sonde sans `modsecurity off;` dÃ©diÃ©.
- **Headers sÃ©curitÃ©** (HSTS/XFO/â€¦) : edge TLS nginx-bastion `:443` (`security-headers.conf`)
  â€” lecture seule dans lâ€™IHM WAF pour lâ€™instant.
- **Rate limiting** portal : zones `portal_login` / `portal_api` pilotables via IHM (taux) ;
  burst location encore dans le template portal (hors gÃ©nÃ©ration).
- **nginx 1.30+** : le portal dÃ©clare des `set $bastion_* ""` pour les variables utilisÃ©es
  par les maps subdomain / `log_format app` (sinon `nginx -t` Ã©choue tant quâ€™aucun vhost
  subdomain nâ€™est chargÃ©).

