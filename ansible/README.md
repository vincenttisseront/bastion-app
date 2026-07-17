## Phase 7 — Docker (`linux_sso_portal_docker.yml`)

**Topologie split + Traefik (comme Keycloak) :**

```
clients → vmdmz-reverse01:443 (nginx edge)
            → https://172.24.0.110 (Traefik, Host: portal.ar-systems.fr)
              → nginx-bastion:8080 (réseau Docker vpcbr)
                → bastion-app / oauth2-proxy (bastion_net)
```

| Rôle | Host | IP / chemin |
|------|------|-------------|
| Edge TLS | `vmdmz-reverse01` | `172.24.0.108` |
| Traefik + stack bastion | `vmdmz-docker01` | `172.24.0.110` — config **`/tools/portal`** |

- Compose / `.env` / oauth2-core : `/tools/portal`
- Data (SQLite, exports) : `/tools/portal/data` → monté `/var/lib/sso-portal` dans les conteneurs

- **Pas** de publish host `:8080` en prod — entrée = Traefik (`labels` + réseau `vpcbr`)
- Smoke local sans Traefik : `docker compose -f docker-compose.yml -f docker-compose.publish.yml up -d`
- Étape awx-playbook : vhost `portal.*` → `https://172.24.0.110` + `Host: portal.ar-systems.fr`
  (`vhost_portal_bastion.conf.j2`, `portal_bastion_edge_enabled: true` dans `linux_nginx_dmz.yml`)

```bash
ansible-playbook ansible/linux_sso_portal_docker.yml \
  -i ansible/inventory/inventory_sso_portal.ini.example --syntax-check

bash scripts/smoke-docker-local.sh
```

---

# Phase 6 — Déploiement Ansible (`linux_sso_portal`)

## Décisions actées (2026-07-17)

| Point | Décision |
|-------|----------|
| oauth2 multi-realm | **apply-infrastructure.sh** (exports DB) pour realms secondaires ; `oauth2-proxy-core` non régénéré à chaque deploy (`sso_portal_manage_oauth2_core: false`) |
| Version smoke | `phase: "5"` / `APP_VERSION 0.5.0` (`sso_portal_expected_health_phase`) |
| `bastion_app_git_ref` | `v0.6.0` (défaut) |
| Hôte | `vmdmz-reverse01` — AWX : `[nginx_dmz]` ; local : `[sso_portal]` |
| JT AWX portail | Projet **awx-playbook** → `linux_sso_portal.yml` (clone bastion-app @ tag) |
| JT AWX infra DMZ | `linux_nginx_dmz.yml` — **sans** deploy portail (`bastion_app_*_enabled: false`) |
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
