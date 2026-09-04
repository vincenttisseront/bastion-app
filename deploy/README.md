# Bastion Pro — guide de déploiement (externe)

Pack **image-only** : pas de sources applicatives, pas de `docker build`.
Vous tirez les images depuis Docker Hub et configurez votre domaine / IdP.

## Contenu de ce dossier

| Fichier | Rôle |
|---------|------|
| `docker-compose.yml` | **Source de vérité du déploiement** (pull only) |
| `.env.example` | Variables applicatives (à copier en `.env`) |
| `.env.acme.example` | Token DNS pour Let’s Encrypt (optionnel) |
| `docker/oauth2-core/` | Stub oauth2-proxy (à personnaliser, puis régénéré via Admin) |
| `docker/postgres/` | Entrypoint sync mot de passe hot-store |
| `docker/acme/` | Scripts ACME companion |
| `scripts/` | `apply-infra-docker.sh` (+ dispatch) pour Admin → Apply côté hôte |
| `data/` | Volumes hôte (vides au départ) |

Pas d’Ansible obligatoire : `docker compose pull && up -d` suffit.
AWX, s’il est utilisé, ne fait que poser ce dossier et écrire `.env` depuis le Vault.

## Images

| Service | Image Docker Hub |
|---------|------------------|
| App | `vincenttisseront/bastion-pro-app:latest` |
| Migrations | `vincenttisseront/bastion-pro-migrate:latest` |
| Nginx edge + WAF | `vincenttisseront/bastion-pro-nginx:latest` |
| oauth2-proxy | `quay.io/oauth2-proxy/oauth2-proxy:v7.7.1` |
| Postgres (optionnel) | `postgres:16-alpine` (digest épinglé) |
| ACME | `neilpang/acme.sh:3.1.4` (digest épinglé) |

Repos Hub **privés** : `docker login` avant le pull.

Alias legacy (même digests) : `vincenttisseront/bastion-pro:{app,migrate,nginx}`.

Surcharge / pin SHA dans `.env` :

```bash
BASTION_APP_IMAGE=vincenttisseront/bastion-pro-app:6b2be94
BASTION_MIGRATE_IMAGE=vincenttisseront/bastion-pro-migrate:6b2be94
BASTION_NGINX_IMAGE=vincenttisseront/bastion-pro-nginx:6b2be94
```

## Prérequis

- Docker Engine + Compose v2
- Un **FQDN** portail (ex. `portal.example.com`) pointant vers l’hôte
- Un **IdP OIDC** (Keycloak, Entra ID, …) : issuer, client_id, client_secret, redirect URI
- (Recommandé) API DNS pour ACME DNS-01 (ex. Cloudflare Zone.DNS Edit)
- Ports hôtes **80** et **443** libres (edge nginx)

## Installation rapide

```bash
cd deploy

# 1. Réseau Docker partagé (subnet fixe attendu par la stack)
docker network create --subnet=10.5.0.0/16 vpcbr 2>/dev/null || true

# 2. Secrets
cp .env.example .env
# Éditer au minimum :
#   PORTAL_DOMAIN=portal.votredomaine.tld
#   SSO_PORTAL_DEFAULT_REALM_SLUG=default   # slug du realm core OIDC
#   VAULT_PORTAL_INTERNAL_TOKEN=…           # long aléatoire
#   BREAKGLASS_JWT_SECRET=…
#   SESSION_HOP_SECRET=…
#   PORTAL_SECRET_ENCRYPTION_KEY=…          # Fernet
#   VAULT_PORTAL_VAULT_FERNET_KEY=…         # Fernet (peut être la même ou distincte)

cp .env.acme.example .env.acme   # si ACME Cloudflare
# Éditer docker/oauth2-core/oauth2-proxy.cfg (issuer, client_*, cookie_*, domaines)

mkdir -p data/sso-portal data/sso-portal-files/private/files

# 3. Pull + start
docker login   # si le repo Hub est privé
docker compose pull
docker compose up -d

# 4. Santé
curl -fsS http://127.0.0.1:8000/api/health
curl -fsS http://127.0.0.1:8080/_portal_nginx_ok
```

## Premier boot admin

1. Ouvrir `https://portal.votredomaine.tld` (certificat : ACME ou provisoire).
2. **Break-glass** (`/auth/setup`, LAN) pour le premier compte admin.
3. Le parcours redirige vers **Admin → Setup** (`/admin/setup-wizard`) :
   - FQDN portail + slug realm → **stockés en base** (`portal_settings`) et exportés dans `exports/bastion-site.env` (nginx les lit au sync/reload).
   - Realm OIDC (issuer / secrets) → **Realms** (déjà en base).
4. **Test OIDC**, puis **Apply** infrastructure.
5. Secrets Docker restants dans `.env` uniquement : `VAULT_PORTAL_INTERNAL_TOKEN`, clé SQLCipher, chemins volumes.

Ne pas éditer à la main les fichiers sous `data/sso-portal/exports/` — ce sont des miroirs générés.

## OIDC — redirect URI attendue

```text
https://<PORTAL_DOMAIN>/oauth2/<SSO_PORTAL_DEFAULT_REALM_SLUG>/callback
```

Exemple : `https://portal.example.com/oauth2/default/callback`

## Architecture

```text
Internet
   │
   ▼
bastion-nginx :80 → 301 HTTPS
bastion-nginx :443 (certs ACME / SNI)
   │
   ├─ Host = portal.*  → oauth2-proxy-core → bastion-app
   ├─ Host = app SSO   → auth_request + upstream
   └─ Host = app public → proxy / robotic SSO

bastion-app          SQLite/SQLCipher + exports
acme-companion       DNS-01 → data/sso-portal/certs/
postgres (optionnel) hot store sessions/audit
```

## Ce qui n’est PAS dans ce pack

- Code source / Dockerfiles (build interne uniquement)
- Ansible / inventaires / IPs internes
- Rapports d’audit, docs Confluence, tests
- Données runtime (`portal.db`, exports réels, clés) — jamais livrés

## Anonymisation

Les images et ce pack utilisent des **valeurs génériques** (`portal.example.com`, realm `default`).
Aucun secret de production, FQDN client ou topologie DMZ ne doit figurer ici.
Si vous forkez le dépôt source pour développer, ne redistribuez **que** ce dossier `deploy/` + les tags Hub.

## Dépannage

| Sympton | Piste |
|---------|--------|
| `bastion-nginx` restart / `nginx -t` fail | Voir logs ; souvent exports ModSec / map hosts — Apply WAF / infra |
| oauth2 500 au callback | `cookie_secret`, PKCE, redirect URI exacte, domaines cookie |
| Pull denied | `docker login` sur le repo privé Hub |
| Certificat manquant | `.env.acme` + Admin → ACME → reconcile ; DNS zone OK |
| Accès apps logs vides | Volume `nginx-logs` partagé nginx ↔ app |

## Support images

Tags stables : `app`, `migrate`, `nginx`.  
Tags immuables : `app-<gitsha>`, etc. Préférez un SHA en production.
