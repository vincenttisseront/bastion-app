# Chaîne IP client — portal bastion (ops + nginx-bastion)

> **Source de vérité** pour la topologie Phase 7 et le déploiement ops.
> Toute checklist du type `reverse01 → 127.0.0.1:PORT_NGINX_BASTION` est **obsolète**
> et ne doit pas être appliquée.

## Topologie réelle (bastion indépendant)

```
client → reverse01:443 (172.24.0.108, DMZ) — catch-all TLS (rôle bastion_edge_dmz)
      → Traefik docker01 (vpcbr 10.5.0.0/16)
      → bastion-nginx:8080   ← real_ip + map portal_client_real_ip (+ Host routing)
      → bastion-app / Keycloak / apps
```

Entry AWX : **projet bastion-app** → `ansible/linux_sso_portal_docker.yml`.
Catch-all edge : `bastion_edge_catchall_enabled: true` (opt-in). Voir `ansible/README.md`.

## Symptôme historique (2026-07-26)

`breakglass.login_denied_non_lan` avec :

| Champ | Valeur observée | Signification |
|-------|-----------------|---------------|
| `peer` (vu par **FastAPI**) | `10.5.0.8` | Conteneur **nginx-bastion** → app (**correct**) |
| `x_real_ip` / `x_forwarded_for` | `172.24.0.108` | IP de **reverse01**, pas le client |
| `resolved` | `null` | Fail-safe app : refuse plutôt que traiter reverse01 comme client |

Le peer TCP **de nginx-bastion** (vers l’amont) est Traefik sur `10.5.0.0/16` — une autre IP
docker que `10.5.0.8`. Ne pas confondre les deux hops.

## Diagnostic confirmé (cause directe)

nginx-bastion a un **fallback** : si `real_ip` / XFF ne sort que des hops infra
(reverse01 / docker), il retombe sur `X-Portal-Client-IP`.

| Couche | État |
|--------|------|
| Template AWX `vhost_portal_bastion.conf.j2` | **OK** depuis **awx-playbook** `26dcbbc` (`proxy_set_header X-Portal-Client-IP $remote_addr` sur `/api/health` et `/`) |
| Fichier **live** sur `vmdmz-reverse01` | **Manquant** — grep de la config déployée : aucune occurrence de `X-Portal-Client-IP` |
| Traefik `forwardedHeaders.trustedIPs` | Ajouté dans le compose AWX, mais le conteneur peut tourner depuis longtemps **sans recreate** → flags non pris en compte |

**Cause unique du `resolved: null` persistant :** reverse01 ne pose pas `X-Portal-Client-IP`
(template non appliqué). Le fallback nginx-bastion n’a donc rien à lire.

## Topologie réelle confirmée (Phase 7)

```
client → reverse01:443 (172.24.0.108, DMZ)
      → Traefik docker01 (vpcbr 10.5.0.0/16)
      → nginx-bastion:8080   ← real_ip + map portal_client_real_ip
      → bastion-app          ← client_ip_from_request (trusted peer = docker only)
```

## Correctif prioritaire — reverse01

Préférer le catch-all bastion (`bastion_edge_dmz`, template
`vhost_bastion_edge_catchall.conf.j2`) qui pose déjà
`X-Portal-Client-IP $remote_addr` sur tout le trafic.

Sinon, sur un vhost portal legacy encore en place, les blocs
`location = /api/health` et `location /` doivent contenir :

```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Portal-Client-IP $remote_addr;   # ← souvent absente en live
```

Puis :

```bash
sudo nginx -t && sudo systemctl reload nginx
```

**Préférer** redéployer le rôle via AWX (`linux_nginx_dmz.yml` / inventaire DMZ) pour
réaligner le live sur le template `26dcbbc`, plutôt qu’un `sed` durable.

Vérification post-reload :

```bash
sudo grep -n X-Portal-Client-IP /etc/nginx/conf.d/vhost_portal_bastion.conf
# Attendu : au moins 2 lignes (health + /)
```

Ce seul header suffit à débloquer le break-glass LAN **même si Traefik n’est pas encore corrigé**.

## Défense en profondeur — Traefik (ensuite)

```bash
docker inspect traefik --format '{{json .Config.Cmd}}' | tr ',' '\n' | grep -i trustedip
# Attendu : --entrypoints.websecure.forwardedHeaders.trustedIPs=172.24.0.108/32
```

Si absent, ou si le conteneur n’a **pas** été **recréé** après l’ajout du flag (un
`restart` ne recharge pas la `Cmd`) :

```bash
# Sur docker01, via le compose AWX Keycloak / Traefik — recreate, pas restart seul
docker compose up -d traefik   # ou équivalent playbook
```

## Les trois couches (après deploy)

| Couche | Repo / commit | Rôle |
|--------|---------------|------|
| Edge + Traefik | **awx-playbook** `26dcbbc` | XFF + `X-Portal-Client-IP` ; Traefik `trustedIPs` |
| nginx-bastion | **bastion-app** | `real_ip` ; sync `X-Real-IP`/`XFF` = `$portal_client_real_ip` ; fallback portal header |
| App | **bastion-app** | Confiance TCP **uniquement** peer docker ; `172.24.0.108` = infra (jamais client) |

## Checklist déploiement (ordre)

1. **reverse01** — appliquer / recharger `X-Portal-Client-IP` (**priorité #1**)
2. **Traefik (docker01)** — vérifier `trustedIPs` + **recreate** si besoin
3. **Stack portal** — déjà OK côté bastion-app / nginx-bastion si à jour sur `master`
4. **Retest** break-glass depuis une IP LAN légitime (`172.24.x` workstation ≠ `.108`) :
   - Admin → Logs → `breakglass.login*`
   - Attendu : `resolved` = IP du poste (ni `null`, ni seulement `172.24.0.108`)

## nginx-bastion (ce repo) — état

| Point | État |
|-------|------|
| `set_real_ip_from` + `real_ip_header XFF` + `recursive on` | OK |
| Confiance limitée (`172.24.0.108/32`, `10.5/16`, bridges) — pas `0.0.0.0/0` ni `172.24.0.0/16` | OK |
| App : pas de confiance TCP reverse01 | OK |
| `X-Real-IP` et `X-Forwarded-For` synchronisés sur `$portal_client_real_ip` | OK |
| Fallback `X-Portal-Client-IP` si real_ip ne sort que des hops infra | OK (côté code) — **exige le header depuis reverse01** |

## Validation rapide après deploy

```text
# Depuis une machine LAN, tenter break-glass puis lire le dernier audit :
# Admin → Logs → breakglass.login* / breakglass.login_denied_non_lan
# Attendu : resolved = votre IP LAN ; x_forwarded_for ne doit PAS être seulement 172.24.0.108
```
