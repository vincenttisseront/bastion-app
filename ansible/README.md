# Ansible / AWX (optionnel)

Le déploiement produit est **[`deploy/docker-compose.yml`](../deploy/README.md)**  
(images Hub publiques). Ce répertoire automatise la même chose si vous utilisez AWX.

```bash
ansible-playbook ansible/linux_sso_portal_docker.yml \
  -i inventory.ini --limit docker-host --tags docker
```

| Tag | Effet |
|-----|--------|
| `docker` | Sync `deploy/` + `.env` Vault + `compose pull && up -d` |
| `smoke` | Health checks (discovery Host optionnel : `bastion_discovery_smoke=true`) |
| `preflight` / `edge` | Optionnels |

| Extra-var | Défaut |
|-----------|--------|
| `bastion_deploy_mode` | `hub` |
| `bastion_hub_image_tag` | `latest` |
| `portal_domain` | **obligatoire en prod** (inventaire) — pas `example.com` |
| `base_domain` / `sso_portal_default_realm_slug` | idem |

Sans `portal_domain` réel, le playbook refuse d’écrire `.env` (cookies SSO / break-glass cassés).

Pas de `docker login` (images publiques). Mode `source` = build local legacy uniquement.
