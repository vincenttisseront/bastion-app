# Database migrations (Alembic)

bastion-app uses [Alembic](https://alembic.sqlalchemy.org/) for schema changes.
Manual `ALTER TABLE` in production is deprecated — use migrations instead.

## Prerequisites

```bash
pip install -e ".[dev]"
# alembic is a runtime dependency (pyproject.toml)
```

`DATABASE_URL` is read from `.env` via `app.sso_settings` (same as the FastAPI app).

## One-shot legacy repair (brownfield prod)

If upgrading from the awx-playbook portal v1 SQLite schema, run once before or
alongside the first Alembic deploy:

```bash
cd /opt/sso-portal
sudo -u sso-portal venv/bin/python3 scripts/fix_audit_logs_schema.py
```

This script is idempotent and preserves existing `audit_logs` rows.

## OIDC realm admin (chiffrement des secrets)

`PORTAL_SECRET_ENCRYPTION_KEY` doit être définie sur le serveur (clé Fernet) avant de
créer ou modifier un realm OIDC :

```bash
/opt/sso-portal/venv/bin/python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Ajouter la valeur dans le fichier d'environnement du service `sso-portal`, puis
`systemctl restart sso-portal`.

## Apply migrations

```bash
cd /opt/sso-portal
alembic upgrade head
```

AWX `linux_nginx_dmz.yml` runs this automatically after each app deploy.

## Create a new migration after model changes

1. Edit SQLAlchemy models in `app/models.py`
2. Generate:

```bash
alembic revision --autogenerate -m "describe change"
```

3. **Review** the generated script — autogenerate may miss renames or SQLite quirks
4. Test locally: `alembic upgrade head`
5. Commit `migrations/versions/*.py`

## Break-glass password reset (operations)

```bash
sudo -u sso-portal venv/bin/python3 scripts/reset_breakglass_password.py --username admin
```

Legacy portal v1 stored break-glass in `settings.breakglass_password_hash` (user
`admin` only). bastion-app migrates that hash automatically on first login attempt.
