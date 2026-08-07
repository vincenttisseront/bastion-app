# bastion-app

**Bastion applicatif** — portail SSO et reverse-proxy sécurisé pour exposer des applications internes derrière une authentification unique (OIDC), un catalogue d’apps, un vault de credentials et une administration centralisée.

Ce dépôt contient :

- l’application **FastAPI** (portail, admin, API)
- le **nginx** Docker (TLS edge, routage Host / sous-domaines)
- **oauth2-proxy** (sessions OIDC)
- le sidecar **ACME** (Let’s Encrypt DNS-01)
- le rôle **Ansible** de déploiement

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

## Stack Docker (recommandé)

### 1. Préparer l’environnement

```bash
cp .env.example .env
# PORTAL_DOMAIN=portal.example.com
# SSO_PORTAL_DEFAULT_REALM_SLUG=default
# secrets : VAULT_PORTAL_INTERNAL_TOKEN, BREAKGLASS_JWT_SECRET,
#           SESSION_HOP_SECRET, PORTAL_SECRET_ENCRYPTION_KEY, …

# Réseau Docker externe (adapter le subnet à votre infra)
docker network create --subnet=10.5.0.0/16 vpcbr   # si absent

# Données persistantes (hôte)
mkdir -p data/sso-portal data/sso-portal-files
```

Variables utiles (compose) :

| Variable | Rôle |
|----------|------|
| `SSO_PORTAL_DATA_DIR` | Données (SQLite, exports, certs, clés) |
| `PORTAL_DOMAIN` | FQDN du portail |
| `ACME_ENV_FILE` | Fichier env ACME optionnel (ex. `.env.acme`) |

Modèle ACME : `.env.acme.example` → `.env.acme` (gitignored).

### 2. Lancer

```bash
docker compose up -d --build
```

Services principaux : `bastion-app`, `bastion-app-migrate`, `oauth2-proxy-core`, `nginx` (`bastion-nginx`), `acme-companion`.

Nginx écoute **80** (redirect) et **443** (TLS). Le routage HTTP interne reste sur `:8080` dans le conteneur.

### 3. Configurer le SSO (source de vérité = base)

Ne pas éditer à la main les fichiers générés sous `exports/` ou `docker/oauth2-core/` comme configuration durable.

1. Ouvrir le portail (break-glass / setup initial si besoin)
2. **Admin → Realms** : issuer, client_id, client_secret, cookie_secret, redirect_uri, PKCE
3. **Test OIDC** puis **Apply infrastructure** (`python -m app.admin.infrastructure apply` ou bouton/API)
4. Le script `scripts/apply-infra-docker.sh` synchronise l’export vers oauth2-proxy et recharge nginx

### 4. Certificats Let’s Encrypt

1. **Admin → ACME** : activer, coller le token DNS, CA prod ou staging
2. **Enregistrer** puis **Réconcilier**
3. Suivre les logs live sur la page ACME (`certs/acme-reconcile.log`)

DNS-01 : le sidecar crée/supprime les TXT `_acme-challenge.*` via l’API — **pas de TXT manuels**. Les enregistrements A/AAAA/CNAME publics vers l’hôte nginx restent à votre charge.

### 5. Applications

**Admin → Apps** : créer une app avec un mode d’accès, par exemple :

- `subdomain_proxy` — FQDN dédié + SSO
- `public_proxy` — FQDN public (éventuellement robotic SSO)
- lien / proxy path selon le catalogue

Après modification : Apply infra (exports nginx + reload).

---

## Déploiement Ansible

Playbook : `ansible/linux_sso_portal_docker.yml`  
Rôle : `ansible/roles/bastion_app_docker`

Exemple (inventaire et secrets à fournir) :

```bash
ansible-playbook ansible/linux_sso_portal_docker.yml \
  -i your-inventory.ini \
  --limit your-docker-host \
  --tags docker
```

Le rôle installe typiquement la stack sous un répertoire hôte configurable (défaut documenté dans `ansible/roles/bastion_app_docker/defaults/main.yml`), construit les images, migre la DB, applique l’infra et lance des smokes.

Tags utiles : `docker`, `smoke`, `discovery`, `edge` (edge TLS amont optionnel).

Détails et variables : [ansible/README.md](ansible/README.md) — **à adapter** : retirez / remplacez toute valeur d’environnement spécifique avant publication publique de forks internes.

---

## Structure du dépôt

```
app/                 # FastAPI (portail, admin, drivers, vault, ACME, …)
docker/nginx/        # Image nginx + sync exports / ACME TLS
docker/acme/         # Sidecar Let’s Encrypt DNS-01
docker/oauth2-core/  # Miroir généré oauth2-proxy (non source de vérité)
ansible/             # Playbook + rôle de déploiement
scripts/             # apply-infra-docker, smokes, utilitaires
docs/                # Architecture, SDD, ops (peut contenir des exemples d’env)
tests/               # Pytest (+ e2e éventuels)
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
