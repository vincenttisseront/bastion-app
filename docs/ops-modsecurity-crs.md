# Ops — ModSecurity v3 + OWASP CRS (nginx-bastion)

Phase A livrée en **`SecRuleEngine DetectionOnly`** sur les trois familles de vhosts
(portal, subdomain_proxy, public_proxy). Aucun blocage réel tant que les fichiers
`engine-*.conf` restent en `DetectionOnly`.

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

Les locations avec `modsecurity off;` (health, auth internes, hops cookie, oauth2/static,
`/.bastion/session-cookies`, `/healthz` public) **ne doivent pas** produire d’entrées
d’audit correspondantes.

## Bascule DetectionOnly → On (par famille)

1. Observer 1–2 semaines en DetectionOnly ; noter les faux positifs.
2. Ajouter les exclusions ciblées dans `waf-basic.conf` (voir ci-dessous).
3. Éditer **un seul** fichier engine, par ex. portal :

```text
# docker/nginx/modsecurity/engine-portal.conf
SecRuleEngine On
```

4. Rebuild / redeploy `bastion-nginx`, puis `nginx -t` + reload (entrypoint fait `nginx -t`).
5. Répéter pour `engine-subdomain.conf` puis `engine-public.conf` — **jamais** les trois
   d’un coup en premier déploiement.

Ne pas utiliser un unique `SecRuleEngine` global dans `modsecurity.conf` (volontairement
absent) : cela empêcherait la bascule progressive.

## Rollback immédiat

**Option A — désactiver ModSecurity sur une famille** (snippet / template) :

- Portal : commenter `modsecurity on;` + `modsecurity_rules_file` dans
  `docker/nginx/templates/vhost_sso_portal.conf.template`, rebuild, reload.
- Subdomain / public : retirer ou commenter l’`include` du snippet
  `modsecurity-subdomain.conf` / `modsecurity-public.conf` dans les générateurs
  (ou vider temporairement le snippet en `modsecurity off;` au niveau server), apply-infra
  pour régénérer les exports, reload.

**Option B — rester inspecté mais non bloquant** : remettre `SecRuleEngine DetectionOnly`
dans le `engine-*.conf` concerné, rebuild/reload.

```bash
docker exec bastion-nginx nginx -t && docker exec bastion-nginx nginx -s reload
```

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
- **Headers sécurité** (HSTS/CSP/…) : toujours propriété de reverse01 (F-09) — hors scope
  ModSecurity.
- **Rate limiting** portal (`portal_login` / `portal_api`) : inchangé.
- **nginx 1.30+** : le portal déclare des `set $bastion_* ""` pour les variables utilisées
  par les maps subdomain / `log_format app` (sinon `nginx -t` échoue tant qu’aucun vhost
  subdomain n’est chargé).
- Smoke DetectionOnly attendu : login SSO → dashboard ; un flux subdomain (CrushFTP) ;
  un flux public_proxy ; `POST /admin/apps/analyze-login-form` ; health/hops sans ligne
  audit.
