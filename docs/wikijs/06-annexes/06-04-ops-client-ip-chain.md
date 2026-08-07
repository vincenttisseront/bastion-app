> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/ops-client-ip-chain.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# ChaÃ®ne IP client â€” portal bastion (ops + nginx-bastion)

> **Source de vÃ©ritÃ©** pour la topologie aprÃ¨s cutover reverse01 â†’ nginx-bastion edge
> (2026-08-06). Traefik est **hors chemin** ingress public bastion
> (`bastion_require_traefik: false`).

## Topologie cible (Cloudflare â†’ bastion-nginx)

```
client â†’ Cloudflare (orange cloud)
      â†’ bastion-nginx:443   â† real_ip CF-Connecting-IP + security-headers
      â†’ bastion-nginx:8080  â† portal / subdomain / public_proxy (Host routing)
      â†’ bastion-app
```

`set_real_ip_from` : plages Cloudflare versionnÃ©es
(`docker/nginx/includes/cloudflare-ips.conf`, snapshot datÃ© â€” Ã  revÃ©rifier
pÃ©riodiquement) + hops internes `10.5.0.0/16`, `172.17.0.0/16`, `127.0.0.0/8`.

**Ne plus** faire confiance Ã  `172.24.0.108` (reverse01) comme source `real_ip` â€”
machine en dÃ©commission.

Header utilisÃ© : `real_ip_header CF-Connecting-IP;` + `real_ip_recursive on;`.

Traefik `forwardedHeaders.trustedIPs` : **non requis** pour lâ€™ingress public bastion
(confirmÃ© hors chemin). Ne pas retoucher Traefik pour ce cutover.

## Fallback `X-Portal-Client-IP` (flag)

ConservÃ© pour rollback pendant le cutover. Flag nginx :

```nginx
# docker/nginx/includes/nginx-portal-client-ip.map.conf
map $host $bastion_portal_client_ip_fallback {
    default 1;   # on â€” dÃ©sactiver (0) aprÃ¨s recette CF real_ip seule
}
```

Quand `fallback=1` et que `$remote_addr` aprÃ¨s real_ip est encore un hop infra
(docker/loopback), nginx prÃ©fÃ¨re `X-Portal-Client-IP` sâ€™il est prÃ©sent.

**Critique hop `:443` â†’ `:8080`** : le terminateur ACME (`sync-acme-tls.sh`) doit poser
`X-Portal-Client-IP $remote_addr` (IP dÃ©jÃ  corrigÃ©e par `real_ip` / LAN). Sans ce
header, le vhost portal sur `:8080` ne voit que `127.0.0.1` â†’ FastAPI fail-closed â†’
pas de formulaire break-glass (mÃªme depuis le LAN). Les logs `apps/portal.access.log`
montrent la vraie IP ; `/var/log/nginx/portal.access.log` (:8080) montre `127.0.0.1`.

AprÃ¨s recette (audit / break-glass voient lâ€™IP client via CF), passer le default Ã 
`0`.

Lâ€™app FastAPI ne lit **jamais** `CF-Connecting-IP` directement (anti-spoof) : elle
fait confiance au peer docker + `X-Real-IP` / XFF posÃ©s par nginx-bastion
(`$portal_client_real_ip`).

## Tests attendus (ops)

1. RequÃªte avec peer TCP dans une plage Cloudflare + header
   `CF-Connecting-IP: <IP client>` â†’ audit / break-glass voient **cette** IP, pas
   une IP Cloudflare ni `10.5.x`.
2. Avec fallback `1` : si la chaÃ®ne ne sort que de lâ€™infra docker, un
   `X-Portal-Client-IP` lÃ©gitime (posÃ© par un hop de confiance amont) reste utilisable.
3. `curl -sI https://<portal>` et 1 subdomain + 1 public_proxy : headers sÃ©curitÃ©
   **une seule fois** (voir `docs/lets-encrypt-acme-nginx-bastion.md` / F-09).

## SymptÃ´me historique (2026-07-26) â€” reverse01

Avant cutover, reverse01 (172.24.0.108) ne posait pas toujours `X-Portal-Client-IP`,
ce qui produisait `breakglass.login_denied_non_lan` avec `resolved: null`.
Voir historique AWX `bastion_edge_dmz` / playbook DMZ â€” **obsolÃ¨te** une fois le
DNS Cloudflare pointÃ© directement sur bastion-nginx:443.

## nginx-bastion (ce repo) â€” Ã©tat cutover

| Point | Ã‰tat |
|-------|------|
| `cloudflare-ips.conf` + `CF-Connecting-IP` | OK |
| Pas de `set_real_ip_from 172.24.0.108` | OK |
| Confiance limitÃ©e (pas `0.0.0.0/0` ni `172.24.0.0/16`) | OK |
| `X-Real-IP` / `X-Forwarded-For` = `$portal_client_real_ip` | OK |
| Fallback `X-Portal-Client-IP` derriÃ¨re flag (dÃ©faut on) | OK |
| `:443` pose `X-Portal-Client-IP $remote_addr` vers `:8080` | OK (requis break-glass) |
| App : peer TCP trusted = docker only | OK |
| Traefik trustedIPs | Hors chemin ingress public |

## Validation rapide aprÃ¨s deploy

```text
# Admin â†’ Logs â†’ breakglass.login* / sessions
# Attendu : resolved = IP client rÃ©elle (CF-Connecting-IP), pas IP Cloudflare
```

