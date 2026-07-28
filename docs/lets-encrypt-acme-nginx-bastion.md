# Let's Encrypt / ACME sur nginx-bastion (Docker)

> Implémentation initiale 2026-07-28 — itération `public_proxy` + DNS-01 Cloudflare.

## Topologie

```
Internet → bastion-nginx:80 → 301 HTTPS
         → bastion-nginx:443 (certs ACME)
    → :8080 (portal / subdomain SSO / public_proxy)
acme-companion
  lit exports/acme-domains.json (tous les FQDN bastion)
  écrit data/certs/<fqdn>/{fullchain,privkey}.pem
```

Scope ACME : **portail + subdomain_proxy + public_proxy** (tous les flux front bastion).

## Décisions

| Sujet | Choix |
|---|---|
| Client | acme.sh sidecar (`neilpang/acme.sh`) |
| Challenge | DNS-01 (`dns_cf` / Cloudflare) |
| Périmètre | Tous les FQDN bastion (portal + subdomain + public_proxy) |
| TLS listen | `0.0.0.0:443` (+ `:80` → 301 HTTPS) |
| Reload | watcher nginx (mtime exports + pem) — **pas** de docker.sock |
| Secrets | `.env.acme` (gitignored), modèle `.env.acme.example` |
| Edge | **nginx Docker** (Traefik coupé) |

## Fichiers

| Pièce | Rôle |
|---|---|
| `app/bastion/acme_domains_export.py` | `exports/acme-domains.json` |
| `docker/acme/reconcile-certs.sh` | issue / placeholder / prune |
| `docker/acme/entrypoint-acme.sh` | cron + reconcile périodique |
| `docker/nginx/sync-public-proxy-tls.sh` | vhosts `:8443 ssl` |
| `docker-compose.yml` → `acme-companion` | service |

## Mise en service (UI)

1. Admin → **ACME** : activer, coller `CF_Token`, CA prod ou staging.
2. **Enregistrer** → écrit `exports/acme-runtime.env` (+ `acme-domains.json`).
3. **Réconcilier maintenant** → écrit `certs/.reconcile_request` ; le sidecar poll ~5 s.
4. Panneau **Logs Let's Encrypt (live)** : queue `certs/acme-reconcile.log` + statut via `GET /api/admin/acme/status`.
5. Tableau domaines : statut cert (OK / renew ≤30j / placeholder / absent), échéance, émetteur.

### DNS — faut-il créer des records ?

**Non pour le challenge.** DNS-01 Cloudflare (`dns_cf`) : acme.sh crée/supprime les TXT `_acme-challenge.<fqdn>` via l’API (token **Zone.DNS Edit**). Aucun TXT manuel.

Toujours nécessaires hors ACME : A/AAAA/CNAME publics qui pointent le trafic HTTPS vers le bastion (reverse01 / Traefik).

Sans token CF : placeholders self-signed (navigateur refuse).

### Cause fréquente : ZeroSSL au lieu de Let's Encrypt

Les images `neilpang/acme.sh` récentes utilisent **ZeroSSL** par défaut (EAB + email).
Le reconcile force `--server letsencrypt` / `letsencrypt_test` et `--set-default-ca`.
Après mise à jour des scripts : redémarrer `bastion-acme`, puis **Réconcilier**.

## Hors scope / DNS

Les FQDN publics (A/AAAA/CNAME) doivent pointer vers **docker01** (ou reverse01 en passthrough TCP/SNI vers docker01:443).
Sans cert ACME prêt, nginx sert un certificat default snakeoil (navigateur « Non sécurisé ») jusqu’à reconcile OK.

## Correspondance conception → code

| Conception | Statut |
|---|---|
| Export `acme-domains.json` | OK |
| Sidecar acme-companion | OK |
| reconcile + prune | OK |
| nginx :443 + volume certs :ro | OK |
| HTTP :80 → 301 HTTPS | OK |
| Reload sans docker.sock | OK (watcher) |
| `.env.acme.example` | OK |
| Admin → ACME UI | OK (`/admin/acme`, SQLite `acme_settings`) |
| Live logs + `/api/admin/acme/status` | OK |
| Runtime env export | OK (`exports/acme-runtime.env`) |
| Traefik labels / catch-all | Retiré (nginx edge) |
| Migration portal / subdomain | Non (volontaire) |
