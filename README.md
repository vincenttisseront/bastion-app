# bastion-app

**Bastion applicatif** — portail SSO et reverse-proxy sécurisé pour exposer des applications internes derrière une authentification unique (OIDC), un catalogue d’apps, un vault de credentials et une administration centralisée.

## Déploiement externe (recommandé)

Sans builder depuis les sources : pack **`deploy/`** + images Docker Hub.

→ Guide complet : **[deploy/README.md](deploy/README.md)**

```bash
cd deploy
cp .env.example .env          # secrets + PORTAL_DOMAIN
cp .env.acme.example .env.acme  # optionnel
docker network create --subnet=10.5.0.0/16 vpcbr 2>/dev/null || true
mkdir -p data/sso-portal data/sso-portal-files
docker login                  # repos privés
docker compose pull
docker compose up -d
```

| Image | Rôle |
|-------|------|
| `vincenttisseront/bastion-pro-app` | runtime FastAPI |
| `vincenttisseront/bastion-pro-migrate` | Alembic / bootstrap |
| `vincenttisseront/bastion-pro-nginx` | edge TLS + ModSecurity |

Tags : `latest` ou pin git SHA (`:6b2be94`). Après le premier boot : **Admin → Setup** (FQDN en base) → Realms → Apply.

---

Ce dépôt (développement / AWX) contient aussi :

- l’application **FastAPI** (portail, admin, API)
- le **nginx** Docker (TLS edge, routage Host / sous-domaines)
- **oauth2-proxy** (sessions OIDC)
- le sidecar **ACME** (Let’s Encrypt DNS-01)
- le rôle **Ansible** (même procédé Hub par défaut)

---

## À quoi ça sert

| Besoin | Réponse bastion-app |
|--------|---------------------|
| Point d’entrée unique HTTPS | Un FQDN portail + FQDN par application (sous-domaine ou proxy public) |
| SSO entreprise | OIDC via oauth2-proxy (Keycloak, Azure AD, etc.) — config realm en base |
| Apps legacy sans OIDC | Vault chiffré + « robotic SSO » (formulaire / basic / cookies) |
| Catalogue et droits | Apps, groupes RBAC, grants, sessions visibles côté admin |
| Secours admin | Break-glass (JWT cookie) indépendant du SSO |
| Découverte de domaines | Hosts inconnus → 403 neutre + file Admin → Domaines (sans fuite portail) |
| Certificats | Let’s Encrypt DNS-01 (ex. Cloudflare) sur nginx `:443` |

**Principe :** le *core* portail (`/`, `/apps`, `/admin`, `/api/health`, break-glass, SSO) ne doit pas être cassé par une app ou un proxy métier.

---

## Architecture (vue d’ensemble)

```
Clients
   │
   ▼
bastion-nginx :80  → 301 HTTPS
bastion-nginx :443 (certs ACME, SNI par FQDN)
   │
   ├─ Host = portal.*     → oauth2-proxy-core → bastion-app
   ├─ Host = app (SSO)    → oauth2 + hop session → upstream
   └─ Host = app (public) → proxy / robotic → upstream

bastion-app (FastAPI)     SQLite/SQLCipher + exports nginx
acme-companion            DNS-01 → data/certs/<fqdn>/
```

Réseau Docker partagé (ex. `vpcbr`) entre bastion-app, nginx, oauth2-proxy et éventuellement d’autres services (IdP).

Sans reverse-proxy amont : nginx publie **80/443** sur l’hôte. Avec un edge amont, pointer le trafic TLS (ou le passthrough SNI) vers cet hôte.

---

## Prérequis

- Python **3.10+** (dev local)
- Docker + Docker Compose (stack complète)
- Un **IdP OIDC** (issuer, client_id, client_secret, redirect URI)
- Pour ACME DNS-01 : token API DNS (ex. Cloudflare Zone.DNS Edit)
- Ansible (optionnel, déploiement distant)

---

## Démarrage local (API seule)

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:     .venv\Scripts\activate

pip install -e ".[dev]"
cp .env.example .env   # renseigner les secrets (voir ci-dessous)
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Santé : `GET http://127.0.0.1:8000/api/health` → `{"status":"ok"}`

Tests : `pytest`

---

## Stack Docker (dev — build local)

Pour développer depuis les sources (pas le chemin prod) :

```bash
cp .env.example .env
docker network create --subnet=10.5.0.0/16 vpcbr 2>/dev/null || true
mkdir -p data/sso-portal data/sso-portal-files
docker compose up -d --build
```

En production / distribution : utiliser **`deploy/`** (pull Hub, sans `--build`).

### Configurer le SSO (source de vérité = base)

1. Break-glass / **Admin → Setup** (`/admin/setup-wizard`) pour le FQDN
2. **Admin → Realms** : issuer, client_id, client_secret, cookie_secret, redirect_uri, PKCE
3. **Test OIDC** puis **Apply infrastructure**
4. Ne pas éditer à la main `exports/` ni le cfg oauth2 comme source durable

### Certificats Let’s Encrypt

1. **Admin → ACME** : token DNS, CA staging puis prod
2. **Réconcilier** — DNS-01 automatique (pas de TXT manuels)

### Applications

**Admin → Apps** puis Apply infra (exports nginx + reload).

---

## Déploiement Ansible (AWX)

Playbook : `ansible/linux_sso_portal_docker.yml`  
Rôle : `ansible/roles/bastion_app_docker`

**La source de vérité reste `deploy/docker-compose.yml`.**  
AWX (`bastion_deploy_mode: hub`) automatise le guide
[`deploy/README.md`](deploy/README.md) : poser le pack, écrire `.env`
depuis le Vault, puis `docker compose pull && up -d`. Pas de build.

```bash
ansible-playbook ansible/linux_sso_portal_docker.yml \
  -i your-inventory.ini \
  --limit your-docker-host \
  --tags docker
```

Extra-vars utiles :

| Variable | Défaut | Rôle |
|----------|--------|------|
| `bastion_deploy_mode` | `hub` | `hub` = pull images ; `source` = build local (dev) |
| `bastion_hub_image_tag` | `latest` | tag Hub (`latest` ou SHA) |
| `vault_dockerhub_username` / `vault_dockerhub_token` | — | login Hub (repos privés) |

Mode legacy build : `bastion_deploy_mode=source` (+ auth `dhi.io` si DHI).

Détails : [ansible/README.md](ansible/README.md).

---

## Structure du dépôt

```
app/                 # FastAPI (portail, admin, drivers, vault, ACME, …)
deploy/              # Pack image-only (compose + README) — chemin prod / externe
docker/nginx/        # Image nginx + sync exports / ACME TLS
docker/acme/         # Sidecar Let’s Encrypt DNS-01
docker/oauth2-core/  # Miroir généré oauth2-proxy (non source de vérité)
ansible/             # Playbook AWX (hub pull par défaut)
scripts/             # apply-infra-docker, smokes, utilitaires
docs/                # Architecture, SDD, ops
tests/               # Pytest
migrations/          # Alembic
```

---

## Sécurité (rappels)

- Chiffrer les secrets applicatifs (Fernet / `PORTAL_SECRET_ENCRYPTION_KEY`)
- SQLite production : SQLCipher recommandé (`VAULT_PORTAL_DB_ENCRYPTION_KEY`)
- Ne jamais committer `.env`, `.env.acme`, `portal.db`, clés sous `data/`
- Break-glass et hop session : secrets HMAC dédiés, distincts
- `RFC1918_BYPASS_ENABLED=false` en production derrière un reverse-proxy
- Les fichiers sous `exports/` sont **générés** — la config OIDC vit en base (`RealmConfig`)

---

## Documentation

| Document | Contenu |
|----------|---------|
| [docs/wikijs/](docs/wikijs/README.md) | **Pages Wiki.js** (utilisateur, fonctionnel, architecture, admin, config) |
| [docs/wikijs/MAINTENANCE.md](docs/wikijs/MAINTENANCE.md) | Tenir la doc à jour à chaque release |
| [docs/README.md](docs/README.md) | Index docs/ (wiki + annexes techniques) |
| [docs/bastion-architecture.md](docs/bastion-architecture.md) | Vision et couches (exemples d’env historiques possibles) |
| [docs/lets-encrypt-acme-nginx-bastion.md](docs/lets-encrypt-acme-nginx-bastion.md) | ACME / nginx TLS |
| [docs/oauth2-cookie-secret-policy.md](docs/oauth2-cookie-secret-policy.md) | Secrets oauth2-proxy |
| [ansible/README.md](ansible/README.md) | Déploiement Ansible |

Avant d’ouvrir le dépôt au public, passez en revue `docs/` et `ansible/` pour retirer noms d’hôtes, domaines et secrets d’exemple trop spécifiques.

---

## Licence

À définir (ajouter un fichier `LICENSE` avant publication publique).
