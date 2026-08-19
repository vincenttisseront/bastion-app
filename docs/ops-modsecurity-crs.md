# Ops — ModSecurity v3 + OWASP CRS (nginx-bastion)

**Statut (2026-08-06 soir)** : **EMERGENCY Off** sur les 3 familles
(`modsecurity off` + `SecRuleEngine Off`). Cause : HTTP **500** sur tout chemin ModSec
(`/auth/login`, `/`, …) alors que `/api/health` (`modsecurity off`) restait 200.
`crs-setup-generated` a été écarté (#113) — le 500 persistait avec CRS + engine On.
Re-activer uniquement après root cause (`error.log` nginx / debug ModSec).

| Famille | Fichier | Engine | Date |
|---------|---------|--------|------|
| portal | `engine-portal.conf` | **Off** | 2026-08-06 emergency |
| subdomain_proxy | `engine-subdomain.conf` | **Off** | 2026-08-06 emergency |
| public_proxy | `engine-public.conf` | **Off** | 2026-08-06 emergency |

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
| Audit log (conteneur) | `/var/log/nginx/apps/modsec_audit.log` |
| Audit log (hôte, bind mount) | `{SSO_PORTAL_DATA_DIR}/nginx-logs/modsec_audit.log` (prod : `/tools/portal/data/nginx-logs/…`) |
| Rotation prod | `/etc/logrotate.d/bastion-nginx-logs` (hôte — voir [`ops-retention-donnees-froides-tools.md`](ops-retention-donnees-froides-tools.md)) |
| Rotation conteneur (secours) | `docker/nginx/logrotate.d/modsecurity` (crond entrypoint — même inode audit via volume) |

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

**Hôte** (bind mount `SSO_PORTAL_DATA_DIR/nginx-logs` — prod : `/tools/portal/data/nginx-logs/`) :

```bash
sudo tail -f /tools/portal/data/nginx-logs/modsec_audit.log
```

**Conteneur** (même inode, chemin interne) :

```bash
docker exec bastion-nginx tail -n 50 /var/log/nginx/apps/modsec_audit.log
```

> `/var/log/nginx/apps/modsec_audit.log` n'existe **pas** sur l'hôte hors de ce volume.

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

**Chronologie 2026-08-06 :**
1. Overlay `id:901110` (collision CRS) — fix #111/#112/#113 (Include retiré).
2. Après #113 : stub généré OK, **pas** d’Include `crs-setup-generated`, export déjà
   `1000900110` — **`/auth/login` toujours 500**. Donc pas (seulement) l’overlay seuil.
3. Mitigation : **`modsecurity off`** serveur + `SecRuleEngine Off` + ne plus Inclure
   `engine-mode-generated` (le profil WAF DB `mode=on` forçait On en dernier).

**Contournement immédiat (sans rebuild)** :

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

Diag utile si 500 revient après re-enable :

```bash
docker exec bastion-nginx tail -n 80 /var/log/nginx/error.log
docker exec bastion-nginx ls -la /tmp/modsecurity /var/log/nginx/apps/modsec_audit.log
```

### Rollback via IHM

Profil WAF → mode **Off** (ou DetectionOnly), **Enregistrer**, puis **Appliquer**.
Ne pas repasser en **On** tant que le smoke `/auth/login` n’est pas vert avec ModSec on.

### Promotion IP deny

Un ban `SecurityBan` (`target_type=ip`) n’apparaît dans nginx que s’il est **actif** et
(**permanent** OU historique `count >= ip_deny_min_occurrences`). Un seul échec de login
ne régénère pas la liste deny.

### Lire le statut WAF dans l'IHM

La page **Admin → WAF** expose **trois lectures distinctes** (lot 2 Phase B) :

| Lecture | Source | Signification |
|---------|--------|---------------|
| **Souhaité (DB)** | `WafProfile` + exclusions SQLite | Ce que l'admin a enregistré — effet immédiat en base uniquement pour le profil. |
| **Généré (export)** | `exports/modsecurity/waf-effective-status.json` | Dernier snapshot écrit par **Appliquer** (`nginx_waf_export.py`). |
| **Réellement actif (nginx)** | Snapshot JSON `nginx-logs/nginx-waf-snapshot.json` produit par **bastion-nginx** | État effectif : `nginx -T` + fichiers ModSecurity réellement chargés. **Pas** de lecture repo ni `docker.sock` côté app. |
| **Repo (intention)** *(dev)* | `BASTION_NGINX_CONF_ROOT` si défini | Checkout git local uniquement — jamais confondu avec l'état live. |

**Lot 2.1 (2026-08-19)** : `bastion-nginx` écrit le snapshot dans le volume partagé
`nginx-logs/` (à chaque démarrage, reload exports, et toutes les 5 min via crond).
`bastion-app` le lit en lecture seule (`BASTION_NGINX_WAF_SNAPSHOT_PATH`). Au-delà de
15 min sans snapshot frais, l'IHM signale « état non vérifié récemment ».

**Diagnostic déploiement** :

| Composant | Chemin conteneur app | Chemin hôte (prod) | Monté dans bastion-app ? |
|-----------|---------------------|--------------------|-------------------------|
| Données / exports | `/var/lib/sso-portal/exports` | `/tools/portal/data/exports` | oui (rw) |
| Snapshot WAF | `/var/lib/sso-portal/nginx-logs/nginx-waf-snapshot.json` | `…/data/nginx-logs/…` | oui (ro) |
| Conf nginx build | — | `/tools/portal/docker/nginx` | **non** (absent de l'image app) |
| Conf nginx live | — | baked dans image `bastion-nginx` | **non** (lu via snapshot) |

**Limite historique (lot 2)** : avant 2.1, l'IHM parse le repo — échec en prod car
`docker/nginx` n'est pas dans l'image `bastion-app`.

Ces trois couches **peuvent diverger** :

- **Mode / seuil CRS** : depuis l'urgence 2026-08-06, engine-*.conf = SecRuleEngine Off et
  engine-mode-generated.conf / crs-setup-generated.conf ne sont **pas** inclus dans
  main-*.conf. L'IHM affiche alors un bandeau rouge si le souhaité DB ≠ moteur nginx, et
  des marqueurs « non appliqué en nginx » sur mode et seuil.
- **Rate limits / IP deny / exclusions UI** : poussés par **Appliquer** ; le badge
  **En attente** / **Appliqué** compare DB vs export champ par champ.
- **Dernier Appliquer** : depuis le lot 2, `waf-effective-status.json` enregistre
  `last_apply_at`, `last_apply_by`, `last_apply_nginx_t_ok` et `last_apply_nginx_t_detail`
  (uniquement après un Appliquer WAF réussi). Les exports antérieurs n'ont que la date
  de dernière écriture du fichier (`export_file_mtime`).

Le bandeau disparaît automatiquement lorsque le moteur nginx rejoint le mode enregistré
(réactivation ops — voir runbook, pas via un simple Appliquer IHM tant que les includes
Phase A ne sont pas rétablis).

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
