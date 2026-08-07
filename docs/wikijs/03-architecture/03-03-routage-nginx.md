# 03.03 — Routage nginx & vhosts

## Rôles de nginx

1. Terminer TLS (certs ACME sous `data/certs/<fqdn>/`)
2. Router par `server_name` (portail, apps, fallback)
3. Exécuter `auth_request` vers FastAPI
4. Proxy vers upstreams (HTTP/HTTPS, WebSocket)
5. Émettre les access logs par app (`{slug}.access.log`)
6. WAF ModSecurity / CRS (selon profil)

## Portail

Décisions figées : `docs/sdd/SDD-002-nginx-vhost-portail.md`
(locations auth, oauth2 start, headers internes, CSRF admin).

## Apps sous-domaine

Blocs générés par `nginx_subdomain_export` lors d’**Apply infra** :

- `auth_request` + capture cookies
- `error_page 401 403 503` → redirect login portail avec `rd=` absolu
- `proxy_set_header` identité (`X-Forwarded-Email`, …)
- hop session robotic si besoin (CrushFTP)

## Chaîne IP client

Edge → (éventuel hop ACME `:443`→`:8080`) → FastAPI.
Headers `X-Portal-Client-IP` / `X-Forwarded-For` doivent être posés correctement
sinon break-glass / allowlist voient `127.0.0.1`.

Détail : `docs/ops-client-ip-chain.md` · page [05.04](../05-configuration/05-04-ip-client-troubleshooting.md).

## Apply = source générée

Modifierier à la main un vhost sous `exports/` est **éphémère** : le prochain apply
écrase. Toujours modifier l’app / realm en base puis appliquer.

Suite : [03.04 Données](./03-04-donnees-vault-hotstore.md)
