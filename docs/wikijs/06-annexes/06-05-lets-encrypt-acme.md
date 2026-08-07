> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/lets-encrypt-acme-nginx-bastion.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# Let's Encrypt / ACME sur nginx-bastion (Docker)

> Cutover reverse01 â†’ edge public nginx-bastion (2026-08-06). Challenge DNS-01
> Cloudflare (`dns_cf`) pour **tous** les FQDN bastion.

## PrÃ©requis CF DNS (gate ops)

Avant tout reconcile **staging ou prod** :

1. Zone Cloudflare `ar-systems.fr` active (DNS gÃ©rÃ© cÃ´tÃ© CF).
2. Token API avec **Zone.DNS Edit** dans `.env.acme` (`CF_Token=â€¦`).
3. `ACME_DNS_API=dns_cf` (dÃ©faut compose / runtime).

Confirmer explicitement **Â« CF DNS OK Â»** avant le premier issue rÃ©el. Sans Ã§a,
acme.sh Ã©choue au challenge TXT.

## Topologie

```
Internet â†’ Cloudflare (orange)
         â†’ bastion-nginx:80  â†’ 301 HTTPS
         â†’ bastion-nginx:443 (certs ACME + security-headers)
         â†’ :8080 (portal / subdomain SSO / public_proxy)
acme-companion
  lit exports/acme-domains.json (portal + subdomain + public_proxy + infra)
  Ã©crit data/certs/<fqdn>/{fullchain,privkey}.pem
  (pas de docker.sock â€” reload via watcher mtime PEM / acme-domains.json)
```

Compose publie `"80:80"` / `"443:443"` ; `:8080` est `127.0.0.1:8080` seulement.

## DÃ©cisions

| Sujet | Choix |
|---|---|
| Client | acme.sh sidecar (`neilpang/acme.sh`) |
| Challenge | DNS-01 (`dns_cf` / Cloudflare) |
| PÃ©rimÃ¨tre | portal + subdomain_proxy + public_proxy + infra |
| TLS listen | `0.0.0.0:443` (+ `:80` â†’ 301 HTTPS) |
| Reload | watcher nginx (mtime exports + pem) â€” **pas** de docker.sock |
| Secrets | `.env.acme` (gitignored), modÃ¨le `.env.acme.example` |
| Edge | **nginx Docker** (Traefik hors ingress public) |

## Fichiers

| PiÃ¨ce | RÃ´le |
|---|---|
| `app/bastion/acme_domains_export.py` | `exports/acme-domains.json` (toutes familles) |
| `docker/acme/reconcile-certs.sh` | issue / placeholder / prune |
| `docker/acme/entrypoint-acme.sh` | cron + reconcile pÃ©riodique |
| `docker/nginx/sync-acme-tls.sh` | vhosts `:443 ssl` (+ headers) ; `:80` â†’ 301 |
| `docker/nginx/sync-public-proxy-tls.sh` | wrapper compat â†’ `sync-acme-tls.sh` |
| `docker-compose.yml` â†’ `acme-companion` | service |

## ProcÃ©dure staging â†’ prod

### 1. Staging (Let's Encrypt test)

```bash
# .env.acme ou Admin â†’ ACME
ACME_CA=letsencrypt_test
```

Puis Admin â†’ **RÃ©concilier** (ou toucher `certs/.reconcile_request`).

Valider **au moins 1 FQDN par famille** prÃ©sente dans `acme-domains.json`
(portal, subdomain_proxy, public_proxy) :

```bash
docker exec bastion-acme sh -c 'openssl x509 -noout -dates -in /certs/<fqdn>/fullchain.pem'
docker exec bastion-nginx nginx -t
```

Ã‰metteur attendu : staging Let's Encrypt (pas ZeroSSL).

### 2. Prod

Quand staging est OK et CF DNS confirmÃ© :

```bash
ACME_CA=letsencrypt
```

RÃ©concilier Ã  nouveau. VÃ©rifier dates / issuer, puis smoke HTTPS.

### Cause frÃ©quente : ZeroSSL au lieu de Let's Encrypt

Les images `neilpang/acme.sh` rÃ©centes utilisent **ZeroSSL** par dÃ©faut.
Le reconcile force `--server letsencrypt` / `letsencrypt_test` et `--set-default-ca`.
AprÃ¨s mise Ã  jour des scripts : redÃ©marrer `bastion-acme`, puis **RÃ©concilier**.

## Mise en service (UI)

1. Admin â†’ **ACME** : activer, coller `CF_Token`, CA staging puis prod.
2. **Enregistrer** â†’ Ã©crit `exports/acme-runtime.env` (+ `acme-domains.json`).
3. **RÃ©concilier maintenant** â†’ Ã©crit `certs/.reconcile_request` ; le sidecar poll ~5 s.
4. Panneau **Logs Let's Encrypt (live)** : queue `certs/acme-reconcile.log` + statut via `GET /api/admin/acme/status`.
5. Tableau domaines : statut cert (OK / renew â‰¤30j / placeholder / absent), Ã©chÃ©ance, Ã©metteur.

### DNS â€” faut-il crÃ©er des records ?

**Non pour le challenge.** DNS-01 Cloudflare : acme.sh crÃ©e/supprime les TXT
`_acme-challenge.<fqdn>` via lâ€™API. Aucun TXT manuel.

Toujours nÃ©cessaires hors ACME : A/AAAA/CNAME publics (orange CF) vers docker01
oÃ¹ bastion-nginx Ã©coute 443.

## Watcher reload

Le conteneur nginx surveille le mtime des PEM et de `acme-domains.json`, rÃ©gÃ©nÃ¨re
via `sync-acme-tls.sh`, puis `nginx -t` + reload â€” **sans** socket Docker vers le
sidecar.

## Headers sÃ©curitÃ© (edge unique)

`sync-acme-tls.sh` inclut `includes/security-headers.conf` **une fois** dans chaque
`server { listen 443 â€¦ }` (pas sur `:8080`). Preuve ops :

```bash
curl -sI https://portal.ar-systems.fr | grep -iE 'strict-transport|x-frame|x-content|referrer-policy|permissions-policy'
# Chaque header doit apparaÃ®tre une seule fois (pas de valeurs virgule-doublÃ©es).
```

RÃ©pÃ©ter pour 1 subdomain + 1 public_proxy.

## Correspondance conception â†’ code

| Conception | Statut |
|---|---|
| Export `acme-domains.json` multi-famille | OK |
| Sidecar acme-companion | OK |
| reconcile + prune | OK |
| nginx :443 + volume certs :ro | OK |
| HTTP :80 â†’ 301 HTTPS | OK |
| Reload sans docker.sock | OK (watcher) |
| `.env.acme.example` | OK |
| Admin â†’ ACME UI | OK |
| Staging (`letsencrypt_test`) â†’ prod | DocumentÃ© ci-dessus |
| Traefik labels / catch-all | RetirÃ© (nginx edge) |

