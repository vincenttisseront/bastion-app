# 05.03 — Déploiement Docker

## Prérequis

- Docker + Compose
- Réseau partagé (ex. `vpcbr`)
- `.env` renseigné
- Répertoires data : `data/sso-portal`, etc.

## Démarrage

```bash
cp .env.example .env
# renseigner secrets + PORTAL_DOMAIN

docker network create --subnet=10.5.0.0/16 vpcbr   # si besoin
mkdir -p data/sso-portal data/sso-portal-files

docker compose up -d --build
```

Services typiques : `bastion-app`, migrate, `oauth2-proxy-core`, `bastion-nginx`,
`acme-companion`.

## Image applicative (DHI)

- **Runtime** : `dhi.io/python:3.12-debian13` (cible Compose `target: runtime`) — pas de shell, UID **65532**
- **Builder / migrate** : `dhi.io/python:3.12-debian13-dev` (shell + apt pour le one-shot migrate)
- Healthcheck : `python -c urllib…` (pas de `curl` dans le runtime)
- Au premier déploiement après migration depuis UID 1000, le job `bastion-app-migrate` re-`chown` les volumes data vers **65532**

### Auth `dhi.io` (obligatoire)

Les pulls anonymes renvoient **401**. Sur l’hôte de build (`vmdmz-docker01`) :

```bash
# PAT Docker Hub (read-only) recommandé : https://hub.docker.com/settings/security
echo "$DOCKER_PAT" | docker login dhi.io -u "$DOCKER_ID" --password-stdin
docker compose build bastion-app bastion-app-migrate
```

AWX / Ansible : renseigner Vault

| Variable | Rôle |
|----------|------|
| `vault_dhi_registry_username` | Docker ID (ou nom d’org pour OAT) |
| `vault_dhi_registry_token` | PAT / OAT lecture seule |

Le rôle `bastion_app_docker` exécute `docker login dhi.io` avant `compose build`.

Contournement temporaire (sans DHI) : Extra Var `bastion_app_use_dhi=false` → bases `python:3.12-slim`.

## Post-démarrage

1. Health : `GET /api/health`
2. Configurer realm + Test OIDC
3. Apply infra
4. Créer apps + grants
5. Vérifier ACME / TLS

## Ansible (optionnel)

Rôle de déploiement distant : voir `ansible/README.md` du dépôt.
Coordination DMZ : `docs/awx-playbook-dmz-coordination.md`.

## Mises à jour

1. Tirer le code / image
2. Migrations (`bastion-app-migrate` ou procédure doc `docs/migrations.md`)
3. Recréer / recreate services nécessaires
4. Apply infra si exports / templates nginx changent

Suite : [05.04 IP & dépannage](./05-04-ip-client-troubleshooting.md)
