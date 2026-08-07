# 03.01 — Architecture : vue d’ensemble

## Schéma logique

```
Clients (navigateur)
        │
        ▼
 bastion-nginx :80  → 301 HTTPS
 bastion-nginx :443 (TLS ACME, SNI par FQDN)
        │
        ├─ Host = portal.*     → auth_request → bastion-app
        │                         (+ oauth2-proxy / BFF)
        ├─ Host = app SSO      → subdomain-auth → upstream
        └─ Host = app public   → proxy (sans auth bastion)

 bastion-app (FastAPI)     SQLite / SQLCipher + exports
 oauth2-proxy-*            sessions OIDC par realm
 acme-companion            DNS-01 → data/certs/<fqdn>/
```

## Composants

| Composant | Rôle |
|-----------|------|
| **bastion-app** | Portail, admin, API, auth_request handlers, vault, RBAC |
| **bastion-nginx** | TLS edge, vhosts, ModSecurity, logs apps |
| **oauth2-proxy** | Session OIDC (miroir généré depuis RealmConfig) |
| **acme-companion** | Certificats Let’s Encrypt |
| **IdP** | Keycloak (externe au dépôt) |

## Couches

1. **Edge** — TLS, WAF, routage Host
2. **Identité** — oauth2-proxy / BFF, break-glass
3. **Autorisation** — AccessGrant, `require_admin`
4. **Application** — proxy upstream, robotic, fichiers
5. **Données** — SQLite config + option hot store PostgreSQL

## Invariant

Le core portail ne dépend pas du cycle de vie d’une app métier.
Apply infra régénère nginx/oauth2 **depuis la base**, pas l’inverse.

Suite : [03.02 Chaîne auth](./03-02-chaine-auth.md)
