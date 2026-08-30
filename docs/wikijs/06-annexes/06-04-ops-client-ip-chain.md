> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d'origine :** docs/ops-client-ip-chain.md — garder les deux synchronisés (voir docs/wikijs/MAINTENANCE.md).

---
# Chaîne IP client — portal bastion (ops + nginx-bastion)

> **Source de vérité** pour la topologie après cutover reverse01 → nginx-bastion edge
> (2026-08-06). Traefik est **hors chemin** ingress public bastion
> (`bastion_require_traefik: false`).

## Topologie cible (Cloudflare → bastion-nginx)

```
client → Cloudflare (orange cloud)
      → bastion-nginx:443   ← real_ip CF-Connecting-IP + security-headers
      → bastion-nginx:8080  ← portal / subdomain / public_proxy (Host routing)
      → bastion-app
```

`set_real_ip_from` : plages Cloudflare versionnées
(`docker/nginx/includes/cloudflare-ips.conf`, snapshot daté — à revérifier
périodiquement) + hops internes `10.5.0.0/16`, `172.17.0.0/16`, `127.0.0.0/8`.

**Ne plus** faire confiance à `172.24.0.108` (reverse01) comme source `real_ip` —
machine en décommission.

Header utilisé : `real_ip_header CF-Connecting-IP;` + `real_ip_recursive on;`.

Traefik `forwardedHeaders.trustedIPs` : **non requis** pour l’ingress public bastion
(confirmé hors chemin). Ne pas retoucher Traefik pour ce cutover.

## Fallback `X-Portal-Client-IP` (flag)

Conservé pour rollback pendant le cutover. Flag nginx :

```nginx
# docker/nginx/includes/nginx-portal-client-ip.map.conf
map $host $bastion_portal_client_ip_fallback {
    default 1;   # on — désactiver (0) après recette CF real_ip seule
}
```

Quand `fallback=1` et que `$remote_addr` après real_ip est encore un hop infra
(docker/loopback), nginx préfère `X-Portal-Client-IP` s’il est présent.

**Critique hop `:443` → `:8080`** : le terminateur ACME (`sync-acme-tls.sh`) doit poser
`X-Portal-Client-IP $remote_addr` (IP déjà corrigée par `real_ip` / LAN). Sans ce
header, le vhost portal sur `:8080` ne voit que `127.0.0.1` → FastAPI fail-closed →
pas de formulaire break-glass (même depuis le LAN). Les logs `apps/portal.access.log`
montrent la vraie IP ; `/var/log/nginx/portal.access.log` (:8080) montre `127.0.0.1`.

Après recette (audit / break-glass voient l’IP client via CF), passer le default à
`0`.

L’app FastAPI ne lit **jamais** `CF-Connecting-IP` directement (anti-spoof) : elle
fait confiance au peer docker + `X-Real-IP` / XFF posés par nginx-bastion
(`$portal_client_real_ip`).

## Tests attendus (ops)

1. Requête avec peer TCP dans une plage Cloudflare + header
   `CF-Connecting-IP: <IP client>` → audit / break-glass voient **cette** IP, pas
   une IP Cloudflare ni `10.5.x`.
2. Avec fallback `1` : si la chaîne ne sort que de l’infra docker, un
   `X-Portal-Client-IP` légitime (posé par un hop de confiance amont) reste utilisable.
3. `curl -sI https://<portal>` et 1 subdomain + 1 public_proxy : headers sécurité
   **une seule fois** (voir `docs/lets-encrypt-acme-nginx-bastion.md` / F-09).

## Symptôme historique (2026-07-26) — reverse01

Avant cutover, reverse01 (172.24.0.108) ne posait pas toujours `X-Portal-Client-IP`,
ce qui produisait `breakglass.login_denied_non_lan` avec `resolved: null`.
Voir historique AWX `bastion_edge_dmz` / playbook DMZ — **obsolète** une fois le
DNS Cloudflare pointé directement sur bastion-nginx:443.

## nginx-bastion (ce repo) — état cutover

| Point | État |
|-------|------|
| `cloudflare-ips.conf` + `CF-Connecting-IP` | OK |
| Pas de `set_real_ip_from 172.24.0.108` | OK |
| Confiance limitée (pas `0.0.0.0/0` ni `172.24.0.0/16`) | OK |
| `X-Real-IP` / `X-Forwarded-For` = `$portal_client_real_ip` | OK |
| Fallback `X-Portal-Client-IP` derrière flag (défaut on) | OK |
| `:443` pose `X-Portal-Client-IP $remote_addr` vers `:8080` | OK (requis break-glass) |
| App : peer TCP trusted = docker only | OK |
| Traefik trustedIPs | Hors chemin ingress public |

## Validation rapide après deploy

```text
# Admin → Logs → breakglass.login* / sessions
# Attendu : resolved = IP client réelle (CF-Connecting-IP), pas IP Cloudflare
```
