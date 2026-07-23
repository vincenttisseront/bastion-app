# Audit — Rotation anti-replay des cookies break-glass (suivi)

> Design validé le 2026-07-23 (§7). Portée : **family B uniquement**.

## Décisions retenues

| # | Point | Décision |
|---|---|---|
| 1 | Fréquence | Rotation `jti` sur les réponses portal **visibles** par le navigateur (middleware), pas sur `auth_request` |
| 2 | Réutilisation hors grâce | Coupure de **toute** la chaîne (`chain_revoked`) |
| 3 | Fenêtre de grâce | **5 s** (`GRACE_WINDOW_SECONDS`) — resync cookie vers le tip, pas de nouvelle rotation |
| 4 | Révocation admin | Étendue à toute la chaîne |
| 5 | Family A / C | Hors code (limitation documentée) |
| 6 | auth_request | Validate-only (`rotate=False`) — nginx ne propage pas `Set-Cookie` du subrequest |

## Hors périmètre

- SSO oauth2-proxy (family A) — pas de rotation côté bastion
- Robotic/vault (family C)
- GeoIP / fingerprint JS

---

## Clôture — implémentation réelle (2026-07-23)

| Élément | Emplacement |
|---------|-------------|
| Colonnes chaîne | `BreakGlassSession.chain_id`, `superseded_by`, `superseded_at`, `chain_revoked` |
| Migration | `025_breakglass_rotation_chain` |
| Pipeline | `process_breakglass_auth_request(rotate=…)` dans `app/breakglass.py` |
| Points d’entrée auth | `app/auth.py`, `app/subdomain/subdomain_auth.py` (`rotate=False`) |
| Rotation navigateur | `BreakglassCookieRotationMiddleware` dans `app/breakglass_cookie_middleware.py` |
| Listing admin | `GET /api/admin/breakglass/sessions` → `chains[]` (groupé) |
| Purge | par chaîne (max `expires_at`) |
| Tests | `tests/test_breakglass_rotation_replay.py` |

**Comportement** :

1. Login → `chain_id = jti` initial.
2. `auth_request` (`/internal/oauth2-auth`, `/internal/subdomain-auth`) → valide sans rotation (sinon la DB avance et le navigateur garde l’ancien `jti` → faux replay).
3. Réponse portal OK (middleware) → nouveau `jti`, ancien `superseded_by`/`superseded_at` ; `Set-Cookie` ; `exp` et ancrage IP/empreinte **inchangés**.
4. Rejeu &lt; 5 s → `breakglass_cookie_grace_reuse` + cookie tip (si `rotate=True`).
5. Rejeu &gt; 5 s → `chain_revoked` sur toute la chaîne + `breakglass_cookie_replay_detected` + `401` (y compris le tip légitime).
6. Admin « Révoquer » → `revoked*` sur le jti ciblé + `chain_revoked` partout.

**Prod** :

- [ ] Migration `025` appliquée
- [ ] Sessions déjà `chain_revoked` par le bug Set-Cookie / auth_request → nouveau login break-glass
- [ ] Vérifier qu’un rejeu hors grâce coupe aussi le cookie courant
