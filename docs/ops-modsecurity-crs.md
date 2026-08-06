# Ops — ModSecurity v3 + OWASP CRS (nginx-bastion)

**Statut cutover reverse01 (2026-08-06)** : les trois familles sont en
**`SecRuleEngine On`**.

| Famille | Fichier | Engine | Date |
|---------|---------|--------|------|
| portal | `engine-portal.conf` | **On** | 2026-08-06 |
| subdomain_proxy | `engine-subdomain.conf` | **On** | 2026-08-06 |
| public_proxy | `engine-public.conf` | **On** | 2026-08-06 |

Exclusions custom : aucune (`waf-basic.conf` vide) tant qu’aucun faux positif n’est
confirmé en prod. Ajouter uniquement des `SecRuleRemoveById` /
`SecRuleUpdateTargetById` ciblés — jamais désactiver une catégorie CRS entière.

Prérequis audit : [`audit-preintegration-modsecurity-crs-nginx-bastion.md`](audit-preintegration-modsecurity-crs-nginx-bastion.md).
Conception (Phase A livrée / Phase B) :
[`conception-modsecurity-crs-nginx-bastion.md`](conception-modsecurity-crs-nginx-bastion.md).
Image : `owasp/modsecurity-crs:4.28.0-nginx-alpine-202607160307` (nginx **1.30.4**, écart
accepté vs ancien `nginx:1.27-alpine`).

## Emplacements clés

| Élément | Chemin |
|---------|--------|
| Rules files par famille | `docker/nginx/modsecurity/main-{portal,subdomain,public}.conf` |
| Bascule engine | `docker/nginx/modsecurity/engine-{portal,subdomain,public}.conf` |
| Core ModSec | `docker/nginx/modsecurity/modsecurity.conf` |
| CRS setup (PL1, seuils 5/4) | `docker/nginx/modsecurity/crs-setup.conf` |
| Exclusions custom | `docker/nginx/includes/waf-basic.conf` |
| Audit log | `/var/log/nginx/apps/modsec_audit.log` (volume Compose `nginx-logs`) |
| Rotation | `docker/nginx/logrotate.d/modsecurity` (crond dans l’entrypoint) |

## Smoke post-deploy (bloquant avant / après `On`)

Sur docker01, après rebuild/reload `bastion-nginx` :

1. Login SSO → dashboard
2. Un flux `subdomain_proxy` (ex. CrushFTP)
3. Un flux `public_proxy`
4. `POST /admin/apps/analyze-login-form` avec une URL légitime
5. Locations `modsecurity off` : **aucune** ligne correspondante dans
   `/var/log/nginx/apps/modsec_audit.log` (health, hops cookie, auth internes,
   oauth2/static, `/.bastion/session-cookies`, `/healthz` public)

```bash
docker exec bastion-nginx nginx -t
docker exec bastion-nginx tail -n 100 /var/log/nginx/apps/modsec_audit.log
```

Si faux positif : exclusion ciblée dans `waf-basic.conf`, rebuild/reload, re-smoke —
**ne pas** repasser toute une famille en `DetectionOnly` sauf rollback d’urgence.

## Lire `modsec_audit.log`

Sur l’hôte (volume data) :

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

## Rollback immédiat (une famille)

Remettre **un seul** `engine-*.conf` en `SecRuleEngine DetectionOnly`, rebuild/reload :

```bash
docker exec bastion-nginx nginx -t && docker exec bastion-nginx nginx -s reload
```

Ordre de re-activation après exclusion : portal → subdomain → public_proxy.

Ne pas utiliser un unique `SecRuleEngine` global dans `modsecurity.conf` (volontairement
absent) : cela empêcherait la bascule / le rollback progressifs.

## Ajouter une exclusion dans `waf-basic.conf`

Fichier inclus **après** les règles CRS (syntaxe ModSecurity uniquement — ne pas
`include` nginx ce fichier).

Exemples :

```
# Désactiver une règle CRS précise
SecRuleRemoveById 942100

# Retirer une cible d’argument sensible d’une règle
SecRuleUpdateTargetById 942100 "!ARGS:password"
```

Puis rebuild ou monter le fichier + `nginx -s reload` selon le mode de déploiement.

## IHM Phase B — `/admin/security/waf`

Pilotage des **overlays générés** uniquement (ne remplace pas `engine-*.conf`,
`crs-setup.conf` paranoia, ni `waf-basic.conf` manuel) :

| Export | Rôle |
|--------|------|
| `exports/modsecurity/crs-setup-generated.conf` | Seuil anomalie (id **1000900110**) — **non chargé** par `main-*.conf` (seuils = static `crs-setup.conf` id 900110). Filet anti-500 si export stale `901110`. |
| `exports/modsecurity/engine-mode-generated.conf` | `SecRuleEngine` profil (inclus en dernier) |
| `exports/modsecurity/bastion-exclusions-generated.conf` | Exclusions UI après `waf-basic.conf` |
| `exports/waf-ip-deny.conf` | `deny` IP promues depuis `SecurityBan` |
| `exports/nginx-portal-rate-limits.conf` | Zones `portal_login` / `portal_api` |
| `exports/modsecurity/waf-effective-status.json` | Statut lu par l’IHM |

### Utilisation

1. Admin → **WAF** : choisir profil (Production / Préproduction / Développement / Custom),
   mode, seuil (3–10), min. occurrences IP deny (défaut **3**).
2. Ajouter exclusions (raison + ID règle CRS + host ou URI) — désactivation soft (historique).
3. **Appliquer** : génère les exports → `nginx -t` (docker exec si dispo) → en échec,
   restauration des `*.prev` (pas de reload de conf cassée). Sinon le watcher nginx
   (`watch-exports-reload`) synchronise et reload.

### Incident — HTTP 500 partout sauf `/api/health`

Cause connue : overlay `crs-setup-generated.conf` avec **`id:901110`** (collision CRS
`REQUEST-901-*`). `/api/health` reste 200 car `modsecurity off`. Les smokes AWX qui ne
testent que `/api/health` restent verts.

**Mitigation code (2026-08-06)** : `main-*.conf` **n’inclut plus**
`crs-setup-generated.conf`. Seuils = `crs-setup.conf` (900110). Rebuild **nginx** obligatoire.

**Fix immédiat volume** (si ancien image encore en Include) :

```bash
grep -n 'id:' /tools/portal/data/exports/modsecurity/crs-setup-generated.conf
sed -i 's/id:901110,/id:1000900110,/g' /tools/portal/data/exports/modsecurity/crs-setup-generated.conf
# ou vider / supprimer le SecAction du fichier généré dans le conteneur
docker exec bastion-nginx nginx -t && docker exec bastion-nginx nginx -s reload
```

Vérifier un chemin ModSec (pas health) :

```bash
docker exec bastion-nginx wget -S -O /dev/null http://127.0.0.1:8080/auth/login 2>&1 | head
# attendu: HTTP/1.1 200 (pas 500)
```

### Rollback via IHM

Repasser le mode en **DetectionOnly** (ou Off), **Enregistrer**, puis **Appliquer**.

### Promotion IP deny

Un ban `SecurityBan` (`target_type=ip`) n’apparaît dans nginx que s’il est **actif** et
(**permanent** OU historique `count >= ip_deny_min_occurrences`). Un seul échec de login
ne régénère pas la liste deny.

## Notes d’exploitation

- **`/healthz` subdomain_proxy** : absent de l’export Python (présent seulement dans le
  j2 DMZ legacy). Ne pas ajouter une sonde sans `modsecurity off;` dédié.
- **Headers sécurité** (HSTS/XFO/…) : edge TLS nginx-bastion `:443` (`security-headers.conf`)
  — lecture seule dans l’IHM WAF pour l’instant.
- **Rate limiting** portal : zones `portal_login` / `portal_api` pilotables via IHM (taux) ;
  burst location encore dans le template portal (hors génération).
- **nginx 1.30+** : le portal déclare des `set $bastion_* ""` pour les variables utilisées
  par les maps subdomain / `log_format app` (sinon `nginx -t` échoue tant qu’aucun vhost
  subdomain n’est chargé).
