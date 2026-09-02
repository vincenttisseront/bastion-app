# 05.01 — Environnement & secrets

## Fichiers

| Fichier | Rôle |
|---------|------|
| `.env` | Variables stack (gitignored) |
| `.env.example` | Modèle documenté |
| `.env.acme` / `.env.acme.example` | Credentials DNS ACME |

## Variables critiques (extrait)

| Variable | Rôle |
|----------|------|
| `PORTAL_DOMAIN` | FQDN portail (cookies domaine parent) |
| `SSO_PORTAL_DATA_DIR` | Données persistantes |
| `VAULT_PORTAL_INTERNAL_TOKEN` | Auth nginx → FastAPI interne |
| `BREAKGLASS_JWT_SECRET` | Signature `bg_session` |
| `SESSION_HOP_SECRET` | Hop cookies robotic |
| `PORTAL_SECRET_ENCRYPTION_KEY` | Chiffrement vault / secrets DB |
| `SSO_PORTAL_DEFAULT_REALM_SLUG` | Realm login par défaut |
| `TRUSTED_PROXY_CIDRS` | Confiance X-Forwarded-* / client IP |

Les secrets OIDC **client_secret / cookie_secret** se saisissent dans
**Admin → Realms**, pas dans un fichier oauth2-proxy édité à la main.

## Règles

- Jamais committer `.env`, dumps de secrets, HAR avec cookies
- Tourner les secrets après exposition accidentelle
- Aligner `PORTAL_INTERNAL_TOKEN` (nginx snippet) ↔ `VAULT_PORTAL_INTERNAL_TOKEN` (app)
- Sans cet alignement, FastAPI **ignore** les headers d’identité (SDD-001) — symptômes :
  sessions SSO « perdues » / 401 systématiques derrière nginx mal configuré

Suite : [05.02 Realms](./05-02-realms-oidc-source-verite.md)
