# Phase 6 — Déploiement Ansible (`linux_sso_portal`)

## Décisions actées (2026-07-17)

| Point | Décision |
|-------|----------|
| oauth2 multi-realm | **apply-infrastructure.sh** (exports DB) pour realms secondaires ; `oauth2-proxy-core` non régénéré à chaque deploy (`sso_portal_manage_oauth2_core: false`) |
| Version smoke | `phase: "5"` / `APP_VERSION 0.5.0` (`sso_portal_expected_health_phase`) |
| `bastion_app_git_ref` | `v0.5.0` (défaut) |
| Hôte | Même `vmdmz-reverse01` (groupe inventaire `[sso_portal]`) |
| Rotation Fernet | Hors scope Phase 6 |

## Usage

```bash
# Syntaxe
ansible-playbook ansible/linux_sso_portal.yml \
  -i ansible/inventory/inventory_sso_portal.ini.example --syntax-check

# Dry-run (host réel + Vault)
ansible-playbook ansible/linux_sso_portal.yml \
  -i ansible/inventory/inventory_sso_portal.ini --check --diff

# Run réel
ansible-playbook ansible/linux_sso_portal.yml \
  -i ansible/inventory/inventory_sso_portal.ini
```

Secrets AWX (jamais en logs grâce à `no_log` sur le rendu `.env`) :
- `vault_portal_internal_token`
- `vault_sso_portal_oidc_client_secret`
- `vault_portal_vault_fernet_key`

## Rollback manuel (pas d'auto-rollback smoke)

1. Restaurer `portal.db.bak-*`
2. Repoint symlink : `ln -sfn /opt/sso-portal-release/<ancienne-ref> /opt/sso-portal`
3. `systemctl restart sso-portal`
4. En dernier recours : re-jouer l'ancien chemin `linux_nginx_dmz.yml` (avant étape 6 du plan de bascule)

## Hors repo bastion-app (checklist §5–9)

- Création Job Template AWX `linux_sso_portal`
- Dry-run / premier run prod
- Retrait scope applicatif de `awx-playbook/linux_nginx_dmz.yml`
