## Phase 7+ — Bastion (Docker Hub images + edge)

**Entry point AWX : projet `bastion-app`**

```
clients → edge TLS
            → bastion-nginx:443/80
                  ├─ portal.* → bastion-app / oauth2
                  ├─ apps subdomain_proxy / public_proxy
                  └─ infra proxies (exports)
```

### Mode de déploiement (défaut = Hub = docker compose)

Le déploiement produit **est** le pack [`deploy/`](../deploy/README.md) :
`docker compose pull && docker compose up -d`.

| `bastion_deploy_mode` | Comportement |
|-----------------------|--------------|
| **`hub`** (défaut) | AWX = wrapper mince : copie `deploy/`, écrit `.env` (Vault), `compose pull` + `up -d`, health. Optionnel : watcher systemd pour Admin → Apply |
| **`source`** | Legacy (`deploy_source.yml`) : tar + `docker compose build` (DHI) — hors chemin prod |

Extra-vars Hub :

```yaml
bastion_deploy_mode: hub
bastion_hub_image_tag: latest   # ou SHA git publié sur Hub
vault_dockerhub_username: "…"
vault_dockerhub_token: "…"      # PAT read
```

Images : `vincenttisseront/bastion-pro-{app,migrate,nginx}`.

`--tags docker` uniquement. SMOKE séparé : `--tags smoke`.

| Rôle | Host | IP / chemin |
|------|------|-------------|
| Edge TLS catch-all | `vmdmz-reverse01` | `172.24.0.108` — rôle `bastion_edge_dmz` |
| Stack bastion | `vmdmz-docker01` | `172.24.0.110` — `/tools/portal` |

- Compose / `.env` / oauth2-core : `/tools/portal`
- Data (SQLite, exports) : `/tools/portal/data` → `/var/lib/sso-portal`
- **Pas** de publish host `:8080` en prod — entrée = Traefik (`labels` + `vpcbr`)
- Smoke local sans Traefik : `docker compose -f docker-compose.yml -f docker-compose.publish.yml up -d`
- **IP client** : reverse01 pose `X-Portal-Client-IP $remote_addr` ; Traefik
  `forwardedHeaders.trustedIPs=172.24.0.108/32` (voir `docs/ops-client-ip-chain.md`)

```bash
# AWX (prod) — SEUL entry point
#   Project    = bastion-app
#   Playbook   = ansible/linux_sso_portal_docker.yml
#   Inventaire = inventaire AWX existant
#   Limit      = hôte choisi (ex. vmdmz-docker01 pour la stack ;
#                vmdmz-reverse01 pour --tags edge)
#   Job tags   = docker  |  edge  |  smoke  |  validate_purge
#   Extra-vars :
#     vault_portal_* / …
#     bastion_edge_catchall_enabled: true   # uniquement sur le JT / run edge
#
# hosts: all par défaut — c’est le Limit AWX qui sélectionne l’hôte.
# Ne pas exiger les groupes sso_portal_docker / nginx_dmz.

# Local syntax check
ansible-playbook ansible/linux_sso_portal_docker.yml \
  -i ansible/inventory/inventory_sso_portal.ini.example --syntax-check

bash scripts/smoke-docker-local.sh
```

### Cutover edge (flag)

1. Déployer docker (`--tags docker`) — Hub pull (pas de rebuild nginx sur l’hôte).
2. Catch-all Traefik → bastion-nginx (découverte Domaines) — **automatique** au deploy :
   - labels `bastion-catchall` sur `bastion-nginx` (compose)
   - fichier `/tools/keycloak/traefik-config/bastion-catchall.yml` (rôle, tag `discovery`)
   - smoke : Host inconnu → HTTP 503 stub (pas 404 Traefik)
3. Extra-var `bastion_edge_catchall_enabled: true` puis `--tags edge` :
   - installe `vhost_bastion_edge_catchall.conf` sur reverse01
   - désactive les vhosts legacy (`vhost_portal*`, `vhost_keycloak*`, … → `.disabled`)
4. Smoke portal + Keycloak login + `https://<fqdn-inconnu>/` → Admin → Domaines.
5. **awx-playbook** : ne plus redéployer les vhosts applicatifs via `linux_nginx_dmz.yml`
   (sinon ils écrasent le catch-all). Ticket de coordination côté DMZ.

### Nouvelle app `public_proxy` / `subdomain_proxy`

Admin → Apps + infrastructure apply. DNS A/CNAME → reverse01 (passe-plat) suffit si
Traefik catch-all envoie le Host à bastion-nginx. **Plus de ticket DMZ par FQDN.**

### Domaines découverts (approval)

bastion-nginx enregistre les `Host:` inconnus (hors map connue) →
**Admin → Domaines**. Approuver = crée une app `public_proxy` (upstream saisi) +
régénère `nginx-known-hosts.map` / `nginx-public-proxy-apps.conf`. Puis Apply infra.
Prérequis : Traefik catch-all vers bastion-nginx (`docker/traefik/bastion-catchall.example.yml`).
reverse01 n’est pas la source de découverte (passe-plat temporaire).

### Rôles

| Rôle | Hôte | Rôle |
|------|------|------|
| `bastion_app_docker` | docker01 | Compose, migrate, infra proxy exports, apply-infra |
| `bastion_edge_dmz` | reverse01 | TLS catch-all (opt-in) |
| `modsec_wazuh_normalizer` | docker01 | ModSec audit → NDJSON Wazuh (systemd hôte) |
| `bastion_app_docker_phase7` | — | Alias historique → `bastion_app_docker` |

### ModSecurity → Wazuh (hôte docker01)

Lit `/tools/portal/data/nginx-logs/modsec_audit.log` (volume nginx), écrit
`modsec_wazuh.jsonl`, configure l’agent Wazuh local. **Pas** dans le conteneur.

```bash
# AWX
#   Project  = bastion-app
#   Playbook = ansible/linux_sso_portal_docker.yml
#   Limit    = vmdmz-docker01
#   Job tags = modsec_wazuh
#   Extra-vars (optionnel) : modsec_wazuh_configure_agent: true

ansible-playbook ansible/linux_sso_portal_docker.yml \
  -i ansible/inventory/inventory_sso_portal.ini.example \
  --tags modsec_wazuh --syntax-check

# Validation sur l'hôte après deploy
systemctl status modsec-wazuh-normalizer
tail -n 3 /tools/portal/data/nginx-logs/modsec_wazuh.jsonl
grep -A3 modsec_wazuh /var/ossec/etc/ossec.conf
```

Hors périmètre : rebuild nginx, règles manager Wazuh, hôte `vmtools-wazuhlogsfw01`.

Le playbook applique notamment :
- `.env` avec `RFC1918_BYPASS_ENABLED=false`
- build `nginx` + `bastion-app` depuis le checkout Git du projet
- `exports/nginx-infra-proxy-apps.conf` (Keycloak, …)
- `bastion-app-migrate` + `infrastructure apply` + `apply-infra-docker.sh`

---

# Phase 6 — Déploiement Ansible bare-metal (`linux_sso_portal`) — legacy

## Décisions actées (2026-07-17)

| Point | Décision |
|-------|----------|
| oauth2 multi-realm | **apply-infrastructure.sh** (exports DB) pour realms secondaires ; `oauth2-proxy-core` non régénéré à chaque deploy (`sso_portal_manage_oauth2_core: false`) |
| Version smoke | `phase: "5"` / `APP_VERSION 0.5.0` (`sso_portal_expected_health_phase`) |
| `bastion_app_git_ref` | `v0.6.0` (défaut) |
| Hôte | `vmdmz-reverse01` — AWX : `[nginx_dmz]` ; local : `[sso_portal]` |
| JT AWX portail Docker | **bastion-app** → `linux_sso_portal_docker.yml` (ci-dessus) |
| JT AWX infra DMZ | `linux_nginx_dmz.yml` — **sans** vhosts applicatifs bastion après cutover edge |

## Usage (bare-metal historique)

```bash
ansible-playbook ansible/linux_sso_portal.yml \
  -i ansible/inventory/inventory_sso_portal.ini.example --syntax-check
```

## Rollback edge catch-all

1. Sur reverse01 : `mv /etc/nginx/conf.d/vhost_*.conf.disabled` → sans `.disabled` (vhosts legacy)
2. Retirer ou renommer `vhost_bastion_edge_catchall.conf`
3. `nginx -t && systemctl reload nginx`
4. Relancer `linux_nginx_dmz.yml` si besoin de réaligner l’infra non-bastion
