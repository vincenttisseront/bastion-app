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

Ajouter la valeur dans `/opt/sso-portal/.env` (ou réutiliser `VAULT_PORTAL_VAULT_FERNET_KEY`
si déjà provisionnée par Ansible), puis `systemctl restart sso-portal`.

### Erreur `NOT NULL constraint failed: realm_configs.keycloak_realm`

Base v1 encore présente : la colonne legacy `keycloak_realm` (NOT NULL) n’est plus
mappée par le modèle OIDC. Appliquer les migrations :

```bash
cd /opt/sso-portal
sudo -u sso-portal venv/bin/alembic upgrade head
```

La révision `005_realm_legacy_drop` supprime `keycloak_realm`, `keycloak_base_url` et
`oauth2_proxy_url`. Si la migration n’est pas encore déployée, contournement SQLite 3.35+ :

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

3. **Review** the generated script — autogenerate may miss renames or SQLite quirks
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

1. Set `HOT_STORE_PG_PASSWORD` in `.env` (and optional user/db). Start `postgres`
   (no host ports; data under `{PORTAL_DATA_DIR}/pgdata`). The bastion entrypoint
   syncs that password on every start via the local socket — no prior admin
   password is required even if the volume was already initialized.
2. Admin → Général → **Configuration** → onglet **Stockage chaud** — save host, port,
   database, user and TLS mode, test, prepare schema, migrate, enable.
3. Disable to roll back reads/writes to SQLite (data already migrated stays on PG
   until the next migrate).

When authentication fails with `password authentication failed for user
"bastion_hot"`, the Configuration panel now names the password actually in use
— the environment variable or the value stored in the database — with a keyed
fingerprint of each, so a divergence is visible without revealing either. Its
**Réaligner le rôle PostgreSQL** button reuses the apply-infra signal: the host
script ends with `docker compose up -d`, which recreates the postgres container
and lets the entrypoint re-apply the password. It grants nothing new and no
secret leaves the application; it cannot help when `.env` itself holds the
wrong value.

From a shell, run `scripts/reset-hot-store-password.sh --check`: it prints a
fingerprint of the value held by `.env`, by the app container and by the
postgres container, which is enough to tell a stale container from a variable
that never reached the app. `--keep` realigns both ends on the current value,
`--generate` on a fresh one. The trap it exists for: the entrypoint only
re-applies the password when the container is **created**, and `docker compose
restart` does not re-read `.env` — so a manual fix can look right and change
nothing. Use `up -d --force-recreate`.

Under AWX the variable comes from `vault_hot_store_pg_password` (aliases
`hot_store_pg_password`, `HOT_STORE_PG_PASSWORD`). Leave all three empty and
`portal.env.j2` simply omits the line: compose then falls back to
`bastion_hot_change_me` for the role while the app keeps using the stored blob,
which authenticates against nothing. The preflight fails the deploy when
`pgdata` exists without a password rather than shipping that pair, since the
symptom only surfaces later, at the next container creation.

The application connects with `HOT_STORE_PG_PASSWORD` from the environment — the
same value the entrypoint applies to the role — so both ends derive from one
source. The password field in the admin form only feeds role provisioning; the
Fernet blob in `portal_settings` is a fallback for deployments predating the
variable. Setting the two to different values used to fail silently until the
next postgres restart, then broke every hot table at once.

Break-glass login survives a hot store outage: session rows, binding anchors,
rate events and audit logs all live there, so the path degrades instead of
returning 500. A login issued while the registry is unreachable gets a
30-minute token rather than 8 hours, because no row means no way to revoke it.

The pages that read hot tables degrade too, so the repair path stays walkable
end to end — dashboard, Configuration, Journaux and Sessions render with the
unreadable figures marked unavailable rather than shown as zero, which would
claim an empty audit trail or no open session. `hot_read()` in
`app/db/hot_store.py` is the one place that does this, and it is for displayed
values only: anything acting on a count — drain, trim, migrate — must still let
the error surface.

Alembic continues to evolve the **SQLite** schema only. Hot tables on Postgres are
created via `HotBase`/`create_all` from the ORM models (see `app/db/hot_store.py`).
