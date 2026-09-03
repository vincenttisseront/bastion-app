> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d'origine :** docs/lets-encrypt-acme-nginx-bastion.md — garder les deux synchronisés (voir docs/wikijs/MAINTENANCE.md).

---
# Let's Encrypt / ACME sur nginx-bastion (Docker)

> Cutover reverse01 → edge public nginx-bastion (2026-08-06). Challenge DNS-01
> Cloudflare (`dns_cf`) pour **tous** les FQDN bastion.

## Prérequis CF DNS (gate ops)

Avant tout reconcile **staging ou prod** :

1. Zone Cloudflare `ar-systems.fr` active (DNS géré côté CF).
2. Token API avec **Zone.DNS Edit** dans `.env.acme` (`CF_Token=…`).
3. `ACME_DNS_API=dns_cf` (défaut compose / runtime).

Confirmer explicitement **« CF DNS OK »** avant le premier issue réel. Sans ça,
acme.sh échoue au challenge TXT.

## Topologie

```
Internet → Cloudflare (orange)
         → bastion-nginx:80  → 301 HTTPS
         → bastion-nginx:443 (certs ACME + security-headers)
         → :8080 (portal / subdomain SSO / public_proxy)
acme-companion
  lit exports/acme-domains.json (portal + subdomain + public_proxy + infra)
  écrit data/certs/<fqdn>/{fullchain,privkey}.pem
  (pas de docker.sock — reload via watcher mtime PEM / acme-domains.json)
```

Compose publie `"80:80"` / `"443:443"` ; `:8080` est `127.0.0.1:8080` seulement.

## Décisions

| Sujet | Choix |
|---|---|
| Client | acme.sh sidecar (`neilpang/acme.sh`) |
| Challenge | DNS-01 (`dns_cf` / Cloudflare) |
| Périmètre | portal + subdomain_proxy + public_proxy + infra |
| TLS listen | `0.0.0.0:443` (+ `:80` → 301 HTTPS) |
| Reload | watcher nginx (mtime exports + pem) — **pas** de docker.sock |
| Secrets | `.env.acme` (gitignored), modèle `.env.acme.example` |
| Edge | **nginx Docker** (Traefik hors ingress public) |

## Fichiers

| Pièce | Rôle |
|---|---|
| `app/bastion/acme_domains_export.py` | `exports/acme-domains.json` (toutes familles) |
| `docker/acme/reconcile-certs.sh` | issue / placeholder / prune |
| `docker/acme/entrypoint-acme.sh` | cron + reconcile périodique |
| `docker/nginx/sync-acme-tls.sh` | vhosts `:443 ssl` (+ headers) ; `:80` → 301 |
| `docker/nginx/sync-public-proxy-tls.sh` | wrapper compat → `sync-acme-tls.sh` |
| `docker-compose.yml` → `acme-companion` | service |

## Procédure staging → prod

### 1. Staging (Let's Encrypt test)

```bash
# .env.acme ou Admin → ACME
ACME_CA=letsencrypt_test
```

Puis Admin → **Réconcilier** (ou toucher `certs/.reconcile_request`).

Valider **au moins 1 FQDN par famille** présente dans `acme-domains.json`
(portal, subdomain_proxy, public_proxy) :

```bash
docker exec bastion-acme sh -c 'openssl x509 -noout -dates -in /certs/<fqdn>/fullchain.pem'
docker exec bastion-nginx nginx -t
```

Émetteur attendu : staging Let's Encrypt (pas ZeroSSL).

### 2. Prod

Quand staging est OK et CF DNS confirmé :

```bash
ACME_CA=letsencrypt
```

Réconcilier à nouveau. Vérifier dates / issuer, puis smoke HTTPS.

### Cause fréquente : ZeroSSL au lieu de Let's Encrypt

Les images `neilpang/acme.sh` récentes utilisent **ZeroSSL** par défaut.
Le reconcile force `--server letsencrypt` / `letsencrypt_test` et `--set-default-ca`.
Après mise à jour des scripts : redémarrer `bastion-acme`, puis **Réconcilier**.

## Mise en service (UI)

1. Admin → **ACME** : activer, coller `CF_Token`, CA staging puis prod.
2. **Enregistrer** → écrit `exports/acme-runtime.env` (+ `acme-domains.json`).
3. **Réconcilier maintenant** → écrit `certs/.reconcile_request` ; le sidecar poll ~5 s.
4. Panneau **Logs Let's Encrypt (live)** : queue `certs/acme-reconcile.log` + statut via `GET /api/admin/acme/status`.
5. Tableau domaines : statut cert (OK / renew ≤30j / placeholder / absent), échéance, émetteur.

### DNS — faut-il créer des records ?

**Non pour le challenge.** DNS-01 Cloudflare : acme.sh crée/supprime les TXT
`_acme-challenge.<fqdn>` via l’API. Aucun TXT manuel.

Toujours nécessaires hors ACME : A/AAAA/CNAME publics (orange CF) vers docker01
où bastion-nginx écoute 443.

## Watcher reload

Le conteneur nginx surveille le mtime des PEM et de `acme-domains.json`, régénère
via `sync-acme-tls.sh`, puis `nginx -t` + reload — **sans** socket Docker vers le
sidecar.

## Headers sécurité (edge unique)

`sync-acme-tls.sh` inclut `includes/security-headers.conf` **une fois** dans chaque
`server { listen 443 … }` (pas sur `:8080`). Pour `family=portal`, CSP via
`security-headers-portal-csp.conf`. Preuve ops :

```bash
curl -sI https://portal.ar-systems.fr | grep -iE 'strict-transport|x-frame|x-content|referrer-policy|permissions-policy|content-security-policy'
# Chaque header doit apparaître une seule fois (pas de valeurs virgule-doublées).
# content-security-policy attendu uniquement sur le FQDN portal.
```

Répéter pour 1 subdomain + 1 public_proxy (sans CSP).

## Correspondance conception → code

| Conception | Statut |
|---|---|
| Export `acme-domains.json` multi-famille | OK |
| Sidecar acme-companion | OK |
| reconcile + prune | OK |
| nginx :443 + volume certs :ro | OK |
| HTTP :80 → 301 HTTPS | OK |
| Reload sans docker.sock | OK (watcher) |
| `.env.acme.example` | OK |
| Admin → ACME UI | OK |
| Staging (`letsencrypt_test`) → prod | Documenté ci-dessus |
| Traefik labels / catch-all | Retiré (nginx edge) |
