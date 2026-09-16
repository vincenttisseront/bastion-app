# bastion-app

SSO portal and reverse proxy to expose internal applications behind OIDC.

**Public repository and Docker Hub images.** Deployment is a `docker-compose.yml`.

---

## Deploy

```bash
git clone https://github.com/vincenttisseront/bastion-app.git
cd bastion-app/deploy

cp .env.example .env
# Edit PORTAL_DOMAIN + secrets (see comments in .env.example)

docker network create --subnet=10.5.0.0/16 vpcbr 2>/dev/null || true
mkdir -p data/sso-portal data/sso-portal-files/private/files

docker compose pull
docker compose up -d
```

Verify:

```bash
curl -fsS http://127.0.0.1:8000/api/health
curl -fsS http://127.0.0.1:8080/_portal_nginx_ok
```

Then: break-glass → **Admin → Setup** → **Realms** → Test OIDC → **Apply**.

Full guide: **[deploy/README.md](deploy/README.md)** (French).

| Image | Docker Hub | GitHub (GHCR) |
|-------|------------|---------------|
| App | `vincenttisseront/bastion-pro-app` | `ghcr.io/vincenttisseront/bastion-pro-app` |
| Migrations | `vincenttisseront/bastion-pro-migrate` | `ghcr.io/vincenttisseront/bastion-pro-migrate` |
| Nginx | `vincenttisseront/bastion-pro-nginx` | `ghcr.io/vincenttisseront/bastion-pro-nginx` |

Tags aligned Hub ↔ GitHub Releases: `:v0.9.0`, `:latest`, and short SHA (`:b6c09da`…).  
Releases: https://github.com/vincenttisseront/bastion-app/releases

Optional pin in `.env`: `BASTION_APP_IMAGE=…:v0.9.0` (same for migrate / nginx).

Update: `docker compose pull && docker compose up -d`.

### Language

The admin and portal UI support **French** (default) and **English**. Change language on the **login** page or under **profile preferences**. Preference is stored in the `portal_locale` cookie.

---

## Ansible (optional)

Automates the same flow (Vault → `.env` + compose). **Not required** to deploy.

```bash
ansible-playbook ansible/linux_sso_portal_docker.yml -i inventory --tags docker
```

See [ansible/README.md](ansible/README.md).

---

## Development

```bash
pip install -e ".[dev]"
cp .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Local build: `docker compose up -d --build` at the repository root (not the production path).

---

## Licence

To be defined (`LICENSE` before publication if needed).
