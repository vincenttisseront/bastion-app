# Coordination awx-playbook — retrait vhosts applicatifs DMZ

Après cutover **bastion indépendant** (projet AWX = `bastion-app`) :

## Ce que fait bastion-app

| Composant | Playbook / rôle |
|-----------|-----------------|
| Stack Docker docker01 | `linux_sso_portal_docker.yml` `--tags docker` |
| Edge TLS catch-all reverse01 | même playbook `--tags edge` + `bastion_edge_catchall_enabled=true` |
| Routage Host | bastion-nginx (`default_server` portal + exports subdomain/public/infra) |

## Ce que `linux_nginx_dmz.yml` ne doit plus faire

Une fois le catch-all validé en prod, **ne plus déployer** (ou garder désactivés) :

- `vhost_portal*.conf` / `vhost_*_bastion*.conf`
- `vhost_keycloak*.conf` (proxifié via `bastion_infra_proxy_vhosts` → bastion-nginx)
- `vhost_wikijs*.conf`, `vhost_grafana*.conf` (idem, activer dans defaults bastion)
- `vhost_transfer*.conf` si transfer est passé en `subdomain_proxy` bastion

Sinon un run DMZ **réécrit** les confs et casse le catch-all / crée des conflits
`server_name`.

## Checklist ops

1. [ ] JT AWX Project=`bastion-app`, Playbook=`ansible/linux_sso_portal_docker.yml`
2. [ ] Deploy docker OK (nginx `default_server`, infra Keycloak export)
3. [ ] Traefik file provider : `docker/traefik/bastion-catchall.example.yml` (adapté) ; labels Host Keycloak retirés
4. [ ] `bastion_edge_catchall_enabled=true` + `--tags edge` + smoke portal + Keycloak
5. [ ] Extra-vars / group_vars `linux_nginx_dmz` : flags bastion/portal **false** ou templates retirés
6. [ ] Documenter rollback (réactiver `*.conf.disabled` sur reverse01)

## Hors scope bastion-app

WAF générique, certificats Let's Encrypt multi-SAN, et tout vhost **non** basculé
restent temporairement dans awx-playbook jusqu’à migration complète des FQDN.
