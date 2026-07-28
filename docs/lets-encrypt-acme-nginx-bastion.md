# Let's Encrypt / ACME sur nginx-bastion (Docker)

> Implémentation initiale 2026-07-28 — itération `public_proxy` + DNS-01 Cloudflare.

## Topologie

```
Internet → reverse01 (TLS LE historique, hors scope)
         → Traefik (HTTP :443 → bastion-nginx:8080 pour portal / discovery)
         → bastion-nginx
              :8080  HTTP (inchangé — Traefik / reverse01)
              :8443  TLS public_proxy (certs du volume data/certs)
acme-companion (neilpang/acme.sh)
  lit exports/acme-domains.json
  écrit data/certs/<fqdn>/{fullchain,privkey}.pem
```

Portal + `subdomain_proxy` : **pas** migrés — restent sur certbot reverse01 / Traefik CF.

## Décisions

| Sujet | Choix |
|---|---|
| Client | acme.sh sidecar (`neilpang/acme.sh`) |
| Challenge | DNS-01 (`dns_cf` / Cloudflare) |
| Périmètre v1 | `public_proxy` uniquement |
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
3. **Réconcilier maintenant** → sentinel + best-effort `docker exec bastion-acme`.
4. Tableau : statut cert (OK / renew ≤30j / placeholder / absent), échéance, émetteur.

Sans token CF : placeholders self-signed (navigateur refuse).

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
| Runtime env export | OK (`exports/acme-runtime.env`) |
| reverse01 / Traefik TCP | Hors scope |
| Migration portal / subdomain | Non (volontaire) |
