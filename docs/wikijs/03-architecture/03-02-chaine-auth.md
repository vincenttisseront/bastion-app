# 03.02 — Chaîne d’authentification

## Portail (SDD-001)

Flux unique catalogue / admin :

```
Navigateur → nginx auth_request
          → FastAPI GET /internal/oauth2-auth
          → oauth2-proxy /oauth2/auth  (et/ou bastion_session natif)
          → 200 (identité) ou 401 → redirect login
```

- Admin = **même** session SSO ; distinction via `require_admin` (groupes / grants).
- Réponses auth_request hors 200/401 sont normalisées pour éviter les **500 nginx**.
- **Gate jeton interne (SDD-001 §3.3) :** FastAPI n’utilise `X-Email` / `X-Groups` / … que si
  `X-Portal-Internal-Token` (snippet `proxy_portal_trusted_internal`) correspond à
  `VAULT_PORTAL_INTERNAL_TOKEN`. Sans jeton valide, les headers d’identité sont ignorés
  (anti-spoof sur accès direct `:8000` / vpcbr). Break-glass cookie reste indépendant.
## Sous-domaine

```
Navigateur → FQDN app
          → auth_request /internal/subdomain-auth
          → session OIDC | bastion_session | break-glass
          → AccessGrant launch+
          → 200 + headers identité  |  401 → @portal_redirect
```

Cas particuliers :

| Code / erreur | Signification |
|---------------|----------------|
| `no-session` | Non authentifié → login portail |
| `access_denied_no_grant` | Authentifié sans grant launch |
| `oauth2-unreachable` | Proxy realm down → 401 (pas 503) |

## Break-glass

Parallèle à OIDC : cookie `bg_session`, allowlist IP, bypass grants apps.

## Références normatives

- Dépôt : `docs/sdd/SDD-001-authentification-sso.md`
- BFF : `docs/bff-oidc-native-session.md`

Suite : [03.03 Routage nginx](./03-03-routage-nginx.md)
