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
