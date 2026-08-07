# 02.03 — Realms OIDC

## Rôle

Un **realm** décrit un fournisseur d’identité OIDC utilisé par le portail
(et éventuellement par les apps).

Champs principaux (`RealmConfig`) :

- `slug`, nom affiché
- `issuer_url`, `client_id`, `client_secret` (chiffré)
- `redirect_uri`, cookie / PKCE selon config
- port oauth2-proxy associé
- flags : défaut, activé, test OIDC, BFF natif éventuel

## Source de vérité

**La base SQLite (RealmConfig)** est la source de vérité.

Flux correct :

1. Admin → Realms (saisie des secrets)
2. **Test OIDC**
3. **Apply infrastructure** (`python -m app.admin.infrastructure apply` ou UI)
4. Script Docker synchronise les exports vers oauth2-proxy

Les fichiers sous `exports/` et `docker/oauth2-core/` sont des **miroirs générés**.
Ne pas les éditer à la main comme source de secrets.

## Multi-realm

Plusieurs realms peuvent coexister (ex. interne / clients). Chaque application
référence un `realm_slug`. Le realm par défaut sert le login portail principal.

## Session native (BFF)

Si activé, le portail peut émettre un cookie `bastion_session` en plus / à la place
du chemin oauth2-proxy pur. Voir annexe dépôt `docs/bff-oidc-native-session.md`.

Suite : [02.04 RBAC](./02-04-rbac-grants.md) · [05.02 Realms config](../05-configuration/05-02-realms-oidc-source-verite.md)
