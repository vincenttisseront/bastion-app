# Chaîne IP client — portal bastion (ops + nginx-bastion)

## Symptôme (2026-07-26)

`breakglass.login_denied_non_lan` avec :

| Champ | Valeur observée | Signification |
|-------|-----------------|---------------|
| `peer` | `10.5.0.8` | Hop docker nginx-bastion → FastAPI (**correct**) |
| `x_real_ip` / `x_forwarded_for` | `172.24.0.108` | IP de **reverse01**, pas le client |
| `resolved` | `null` | Fail-safe app : refuse plutôt que traiter reverse01 comme client |

## Topologie réelle (Phase 7)

```
client → reverse01:443 (172.24.0.108)
      → Traefik docker01 (vpcbr 10.5.0.0/16)
      → nginx-bastion:8080   ← real_ip ici
      → bastion-app          ← client_ip_from_request (peer = nginx-bastion only)
```

Ce n’est **pas** `reverse01 → 127.0.0.1:PORT_NGINX_BASTION`.

## Les deux correctifs sont obligatoires

| Couche | Repo | Rôle |
|--------|------|------|
| Edge + Traefik | **awx-playbook** | Transmettre la vraie IP client dans XFF / `X-Portal-Client-IP` |
| nginx-bastion | **bastion-app** | `real_ip` depuis Traefik/reverse01, puis `X-Real-IP $portal_client_real_ip` vers FastAPI |
| App | **bastion-app** | Faire confiance **uniquement** au peer docker (10.5/16) ; ignorer reverse01 comme client |

Aucun seul ne suffit.

## Checklist ops (awx-playbook)

1. **reverse01** — `vhost_portal_bastion.conf.j2` :
   - `proxy_set_header X-Real-IP $remote_addr;`
   - `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`
   - `proxy_set_header X-Portal-Client-IP $remote_addr;` (overwrite, jamais pass-through)
2. **Traefik** (`docker_keycloak` compose) :
   - `--entrypoints.websecure.forwardedHeaders.trustedIPs=172.24.0.108/32`
   - idem pour `web` si utilisé
3. Redeploy Traefik **puis** reverse01 **puis** stack portal.
4. Test réel break-glass depuis une IP LAN (`172.24.x` workstation ≠ `.108`) :
   - audit : `resolved` = IP workstation, pas `null`
   - login break-glass OK

## nginx-bastion (ce repo) — déjà en place

- `set_real_ip_from 172.24.0.108` + `10.5.0.0/16` (peer = Traefik) + bridges/loopback
- `real_ip_header X-Forwarded-For;` + `real_ip_recursive on;`
- Map `portal_client_real_ip` : `$remote_addr` après real_ip, fallback `X-Portal-Client-IP` si hop infra
- Vers FastAPI : `X-Real-IP` **et** `X-Forwarded-For` = `$portal_client_real_ip` (pas `$http_x_real_ip`)
- App : `TRUSTED_PROXY_CIDRS` = docker seulement ; `172.24.0.108` = infra hop (jamais client)

## Validation rapide après deploy

```bash
# Depuis une machine LAN, tenter break-glass puis lire le dernier audit :
# Admin → Logs → breakglass.login* 
# Attendu : resolved = votre IP LAN ; x_forwarded_for ne doit PAS être seulement 172.24.0.108
```
