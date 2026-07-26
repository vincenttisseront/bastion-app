# Chaîne IP client — portal bastion (ops + nginx-bastion)

> **Source de vérité** pour la topologie Phase 7 et le déploiement ops.
> Toute checklist du type `reverse01 → 127.0.0.1:PORT_NGINX_BASTION` est **obsolète**
> et ne doit pas être appliquée.

## Symptôme (2026-07-26)

`breakglass.login_denied_non_lan` avec :

| Champ | Valeur observée | Signification |
|-------|-----------------|---------------|
| `peer` (vu par **FastAPI**) | `10.5.0.8` | Conteneur **nginx-bastion** → app (**correct**) |
| `x_real_ip` / `x_forwarded_for` | `172.24.0.108` | IP de **reverse01**, pas le client |
| `resolved` | `null` | Fail-safe app : refuse plutôt que traiter reverse01 comme client |

Le peer TCP **de nginx-bastion** (vers l’amont) est Traefik sur `10.5.0.0/16` — une autre IP
docker que `10.5.0.8`. Ne pas confondre les deux hops.

## Topologie réelle confirmée (Phase 7)

```
client → reverse01:443 (172.24.0.108, DMZ)
      → Traefik docker01 (vpcbr 10.5.0.0/16)
      → nginx-bastion:8080   ← real_ip + map portal_client_real_ip
      → bastion-app          ← client_ip_from_request (trusted peer = docker only)
```

## Diagnostic (confirmé)

nginx-bastion avait déjà `real_ip` correctement configuré. Le symptôme montre que **la vraie IP
client n’arrive pas** jusqu’à nginx-bastion tant que Traefik / reverse01 ne sont pas redéployés
avec les bons réglages. L’app fait son travail (fail-closed).

## Les trois couches sont obligatoires

| Couche | Repo / commit | Rôle |
|--------|---------------|------|
| Edge + Traefik | **awx-playbook** `26dcbbc` | XFF + `X-Portal-Client-IP` depuis reverse01 ; Traefik `trustedIPs` |
| nginx-bastion | **bastion-app** `22b7774` (+ antérieurs) | `real_ip` ; `X-Real-IP`/`XFF` = `$portal_client_real_ip` |
| App | **bastion-app** | Confiance TCP **uniquement** peer docker ; `172.24.0.108` = infra (jamais client) |

Aucun sous-ensemble ne suffit.

## Checklist déploiement (ordre)

1. **Traefik (docker01)** — compose Keycloak / awx-playbook :
   - `--entrypoints.websecure.forwardedHeaders.trustedIPs=172.24.0.108/32`
   - idem `web` si utilisé
2. **reverse01 (DMZ)** — `vhost_portal_bastion.conf.j2` / `linux_nginx_dmz` :
   - `proxy_set_header X-Real-IP $remote_addr;`
   - `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`
   - `proxy_set_header X-Portal-Client-IP $remote_addr;` (overwrite, jamais pass-through)
3. **Stack portal** — redeploy nginx-bastion + app (bastion-app déjà sur `master`)
4. **Retest** break-glass depuis une IP LAN légitime (`172.24.x` workstation ≠ `.108`) :
   - Admin → Logs → `breakglass.login*`
   - Attendu : `resolved` = IP du poste (ni `null`, ni seulement `172.24.0.108`)

## nginx-bastion (ce repo) — état

| Point | État |
|-------|------|
| `set_real_ip_from` + `real_ip_header XFF` + `recursive on` | OK |
| Confiance limitée (`172.24.0.108/32`, `10.5/16`, bridges) — pas `0.0.0.0/0` ni `172.24.0.0/16` | OK — `10.5/16` requis car peer amont = Traefik |
| App : pas de confiance TCP reverse01 | OK |
| `X-Real-IP` et `X-Forwarded-For` synchronisés sur `$portal_client_real_ip` | OK (`22b7774`) |
| Fallback `X-Portal-Client-IP` si real_ip ne sort que des hops infra | OK |

## Validation rapide après deploy

```text
# Depuis une machine LAN, tenter break-glass puis lire le dernier audit :
# Admin → Logs → breakglass.login* / breakglass.login_denied_non_lan
# Attendu : resolved = votre IP LAN ; x_forwarded_for ne doit PAS être seulement 172.24.0.108
```
