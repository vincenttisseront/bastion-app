> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/migrations.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# Database migrations (Alembic)

bastion-app uses [Alembic](https://alembic.sqlalchemy.org/) for schema changes.
Manual `ALTER TABLE` in production is deprecated â€” use migrations instead.

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

`PORTAL_SECRET_ENCRYPTION_KEY` doit Ãªtre dÃ©finie sur le serveur (clÃ© Fernet) avant de
crÃ©er ou modifier un realm OIDC :

```bash
/opt/sso-portal/venv/bin/python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Ajouter la valeur dans `/opt/sso-portal/.env` (ou rÃ©utiliser `VAULT_PORTAL_VAULT_FERNET_KEY`
si dÃ©jÃ  provisionnÃ©e par Ansible), puis `systemctl restart sso-portal`.

### Erreur `NOT NULL constraint failed: realm_configs.keycloak_realm`

Base v1 encore prÃ©sente : la colonne legacy `keycloak_realm` (NOT NULL) nâ€™est plus
mappÃ©e par le modÃ¨le OIDC. Appliquer les migrations :

```bash
cd /opt/sso-portal
sudo -u sso-portal venv/bin/alembic upgrade head
```

La rÃ©vision `005_realm_legacy_drop` supprime `keycloak_realm`, `keycloak_base_url` et
`oauth2_proxy_url`. Si la migration nâ€™est pas encore dÃ©ployÃ©e, contournement SQLite 3.35+ :

```bash
sqlite3 /var/lib/sso-portal/portal.db "ALTER TABLE realm_configs DROP COLUMN keycloak_realm;"
```

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

3. **Review** the generated script â€” autogenerate may miss renames or SQLite quirks
4. Test locally: `alembic upgrade head`
5. Commit `migrations/versions/*.py`

## Break-glass password reset (operations)

```bash
sudo -u sso-portal venv/bin/python3 scripts/reset_breakglass_password.py --username admin
```

Legacy portal v1 stored break-glass in `settings.breakglass_password_hash` (user
`admin` only). bastion-app migrates that hash automatically on first login attempt.

## Optional PostgreSQL hot store

`DATABASE_URL` stays SQLite (config + SQLCipher). High-volume tables can be
offloaded to the compose `postgres` service:

1. Start `postgres` (no host ports; data under `{PORTAL_DATA_DIR}/pgdata`).
2. Admin â†’ SÃ©curitÃ© â†’ **Stockage chaud** â€” save DSN (password Fernet-encrypted
   in `portal_settings`), test, prepare schema, migrate, enable.
3. Disable to roll back reads/writes to SQLite (data already migrated stays on PG
   until the next migrate).

Alembic continues to evolve the **SQLite** schema only. Hot tables on Postgres are
created via `HotBase`/`create_all` from the ORM models (see `app/db/hot_store.py`).

