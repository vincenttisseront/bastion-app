# Audit — Gestion des sessions (suivi)

> Document de suivi issu de l'audit du 2026-07-23 (`audit-gestion-sessions`).
> Ne remplace pas le Pod source ; enregistre l'état d'implémentation dans `bastion-app`.

## §6.2 / §8 — AccessGrant ↔ session active (proxy / subdomain)

| Date | Statut | Résumé |
|------|--------|--------|
| 2026-07-23 | **Confirmé** (gap) | `/internal/subdomain-auth` et `/internal/oauth2-auth` ne vérifiaient que la session, pas le grant applicatif. |
| 2026-07-23 | **Corrigé** | Enforcement `AccessGrant` `launch+` sur `/internal/subdomain-auth` via `get_effective_apps_for_user` / `user_can_launch_application`. Refus → **403** + audit `access_denied_no_grant`. |

### Implémentation réelle

- **Fichier** : `app/subdomain/subdomain_auth.py`
- **Helper** : `user_can_launch_application()` dans `app/rbac/effective_access_service.py`
- **`/internal/oauth2-auth`** : **inchangé** pour les grants — protège uniquement le portail (`/apps`, `/dashboard`) ; tout utilisateur authentifié doit y accéder. Docstring explicite dans `app/auth.py`.
- **Proxy legacy `/proxy/{slug}/`** : pas de second handler FastAPI ; redirections Nginx vers subdomain (voir `app/proxy/proxy_service.py`). L'enforcement est donc celui de `subdomain-auth`.
- **Break-glass** : accès total aux apps subdomain **sans** AccessGrant (secours admin IdP down) — commenté dans le code.
- **RFC1918 bypass** : inchangé (200 sans identité → pas de contrôle grant).
- **Tests** : `tests/test_subdomain_auth_access_grant.py` (grant launch → 200 ; sans grant / view-only / grant révoqué + cookie encore valide → 403 ; break-glass → 200 ; portail oauth2-auth sans grant → OK).

### Effet attendu en prod

Retirer un `AccessGrant` coupe l'accès direct par URL **immédiatement** (prochaine requête `auth_request`), sans attendre l'expiration du cookie oauth2-proxy.
