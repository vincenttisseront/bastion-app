# 05.04 — Chaîne IP client & dépannage nginx

## Pourquoi c’est critique

Break-glass, allowlists, audit IP et ban dépendent de l’**IP client réelle**.
Un hop mal configuré fait apparaître `127.0.0.1` → fail-closed ou faux positifs.

## Chaîne typique

```
Client → edge TLS (:443)
      → (sync ACME) proxy local :8080
      → FastAPI
```

Sur le hop `:443` → `:8080`, nginx doit propager :

- `X-Portal-Client-IP` (depuis `$remote_addr` edge)
- `X-Forwarded-For` cohérent

FastAPI ne fait confiance aux headers spoofables que si le **peer TCP** est dans
`TRUSTED_PROXY_CIDRS`.

Détail : `docs/ops-client-ip-chain.md`.

## Symptômes & pistes

| Symptôme | Pistes |
|----------|--------|
| Pas de formulaire break-glass sur LAN | IP vue = 127.0.0.1 / hors CIDR |
| 500 sur app, `upstream=-` | auth_request 5xx (corriger codes 401) ; ModSec ; vhost manquant |
| 302 portail + `access_denied_no_grant` | Grant launch manquant |
| Boucle 301/308 Wiki.js | `X-Forwarded-Proto`, upstream HTTPS, trustProxy |
| Access log vide dans l’UI | Mauvais volume `nginx-logs` ; onglet Accès apps ; slug |
| Tuile ouvre home anonyme Wiki.js | Entrée `/login` + Bypass Login Screen |

## Outils

- Admin → Logs → Accès apps (`auth_err`, `auth_email`)
- `docs/troubleshooting-nginx.md`
- `nginx -t` dans le conteneur après apply

Retour : [Accueil](../00-accueil.md)
