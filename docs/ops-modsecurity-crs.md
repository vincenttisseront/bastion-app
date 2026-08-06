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

## Notes d’exploitation

- **`/healthz` subdomain_proxy** : absent de l’export Python (présent seulement dans le
  j2 DMZ legacy). Ne pas ajouter une sonde sans `modsecurity off;` dédié.
- **Headers sécurité** (HSTS/XFO/…) : propriété de l’edge TLS (F-09) — hors scope
  ModSecurity ; ne pas les reposer sur `:8080`.
- **Rate limiting** portal (`portal_login` / `portal_api`) : inchangé.
- **nginx 1.30+** : le portal déclare des `set $bastion_* ""` pour les variables utilisées
  par les maps subdomain / `log_format app` (sinon `nginx -t` échoue tant qu’aucun vhost
  subdomain n’est chargé).
