# Déploiement Bastion Pro

Repo GitHub + images Docker Hub **publics**.  
Fichier central : **`docker-compose.yml`** dans ce dossier.

```bash
cp .env.example .env          # PORTAL_DOMAIN + secrets
# cp .env.acme.example .env.acme   # optionnel Let's Encrypt

docker network create --subnet=10.5.0.0/16 vpcbr 2>/dev/null || true
mkdir -p data/sso-portal data/sso-portal-files/private/files

docker compose pull
docker compose up -d

curl -fsS http://127.0.0.1:8000/api/health
curl -fsS http://127.0.0.1:8080/_portal_nginx_ok
```

## Contenu

| Fichier | Rôle |
|---------|------|
| `docker-compose.yml` | Stack (pull only) |
| `.env.example` | Secrets / domaine |
| `.env.acme.example` | DNS-01 (optionnel) |
| `docker/` | oauth2 stub, postgres entrypoint, ACME |
| `scripts/` | `apply-infra-docker.sh` après Admin → Apply |
| `data/` | volumes hôte |

## Images

`vincenttisseront/bastion-pro-{app,migrate,nginx}:latest` (ou pin SHA dans `.env`).

## Premier boot

1. `https://<PORTAL_DOMAIN>`  
2. Break-glass `/auth/setup` (LAN)  
3. Admin → Setup → Realms → Test OIDC → **Apply**  
4. Redirect IdP : `https://<PORTAL_DOMAIN>/oauth2/<slug>/callback`

Après Apply : `bash scripts/apply-infra-docker.sh` (ou watcher systemd si vous l’installez).

Ne pas éditer `data/sso-portal/exports/` à la main — miroirs générés ; OIDC en base.

## Ansible

Optionnel. Voir `../ansible/README.md` — wrapper Vault + compose, pas un second mode.
