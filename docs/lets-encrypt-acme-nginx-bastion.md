# Let's Encrypt / ACME sur nginx-bastion (Docker)

> Implémentation initiale 2026-07-28 — itération `public_proxy` + DNS-01 Cloudflare.

## Topologie

```
Internet → reverse01 (optionnel / transition)
         → Traefik ou SNI → bastion-nginx:8443 (certs ACME)
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
| TLS listen | `0.0.0.0:8443` (conf générée si certs présents) |
| Reload | watcher nginx (mtime exports + pem) — **pas** de docker.sock |
| Secrets | `.env.acme` (gitignored), modèle `.env.acme.example` |

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

## Hors scope (infra sœur)

Pour que le navigateur public voie le cert LE du bastion :

- reverse01 : passthrough **TCP/SNI** vers docker01:8443 pour ces FQDN, **ou**
- Traefik : routeur TCP TLS passthrough vers `bastion-nginx:8443`

Sans cela, le chemin actuel `reverse01 HTTPS → Traefik (cert défaut catch-all) → :8080` ne présente **pas** les certs ACME Docker. Corriger aussi le DNS (`teleport` → reverse01) si on reste sur le wildcard LE edge.

## Correspondance conception → code

| Conception | Statut |
|---|---|
| Export `acme-domains.json` | OK |
| Sidecar acme-companion | OK |
| reconcile + prune | OK |
| nginx :8443 + volume certs :ro | OK |
| Reload sans docker.sock | OK (watcher) |
| `.env.acme.example` | OK |
| Admin → ACME UI | OK (`/admin/acme`, SQLite `acme_settings`) |
| Live logs + `/api/admin/acme/status` | OK |
| Runtime env export | OK (`exports/acme-runtime.env`) |
| reverse01 / Traefik TCP | Hors scope |
| Migration portal / subdomain | Non (volontaire) |
