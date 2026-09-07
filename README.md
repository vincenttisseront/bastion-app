# bastion-app

Portail SSO et reverse-proxy pour exposer des applications internes derrière OIDC.

**Dépôt et images Docker Hub publics.** Le déploiement, c’est un `docker-compose.yml`.

---

## Déployer

```bash
git clone https://github.com/vincenttisseront/bastion-app.git
cd bastion-app/deploy

cp .env.example .env
# Éditer PORTAL_DOMAIN + secrets (voir commentaires dans .env.example)

docker network create --subnet=10.5.0.0/16 vpcbr 2>/dev/null || true
mkdir -p data/sso-portal data/sso-portal-files/private/files

docker compose pull
docker compose up -d
```

Vérifier :

```bash
curl -fsS http://127.0.0.1:8000/api/health
curl -fsS http://127.0.0.1:8080/_portal_nginx_ok
```

Puis : break-glass → **Admin → Setup** → **Realms** → Test OIDC → **Apply**.

Guide complet : **[deploy/README.md](deploy/README.md)**.

| Image | Docker Hub | GitHub (GHCR) |
|-------|------------|---------------|
| App | `vincenttisseront/bastion-pro-app` | `ghcr.io/vincenttisseront/bastion-pro-app` |
| Migrations | `vincenttisseront/bastion-pro-migrate` | `ghcr.io/vincenttisseront/bastion-pro-migrate` |
| Nginx | `vincenttisseront/bastion-pro-nginx` | `ghcr.io/vincenttisseront/bastion-pro-nginx` |

Tags alignés Hub ↔ GitHub Releases : `:v0.8.0`, `:latest`, et SHA court (`:b6c09da`…).  
Release : https://github.com/vincenttisseront/bastion-app/releases

Pin optionnel dans `.env` : `BASTION_APP_IMAGE=…:v0.8.0` (idem migrate / nginx).

Mettre à jour : `docker compose pull && docker compose up -d`.

---

## Ansible (optionnel)

Automatise la même chose (Vault → `.env` + compose). **Pas requis** pour déployer.

```bash
ansible-playbook ansible/linux_sso_portal_docker.yml -i inventory --tags docker
```

Voir [ansible/README.md](ansible/README.md).

---

## Développement

```bash
pip install -e ".[dev]"
cp .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Build local : `docker compose up -d --build` à la racine du dépôt (hors chemin prod).

---

## Licence

À définir (`LICENSE` avant publication si besoin).
