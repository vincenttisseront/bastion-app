# Audit — Rotation anti-replay des cookies break-glass (suivi)

> Design validé le 2026-07-23 (§7). Portée : **family B uniquement**.

## Décisions retenues

| # | Point | Décision |
|---|---|---|
| 1 | Fréquence | Rotation `jti` à **chaque** requête protégée (`/internal/oauth2-auth`, `/internal/subdomain-auth`) |
| 2 | Réutilisation hors grâce | Coupure de **toute** la chaîne (`chain_revoked`) |
| 3 | Fenêtre de grâce | **5 s** (`GRACE_WINDOW_SECONDS`) — resync cookie vers le tip, pas de nouvelle rotation |
| 4 | Révocation admin | Étendue à toute la chaîne |
| 5 | Family A / C | Hors code (limitation documentée) |

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
| Pipeline | `process_breakglass_auth_request()` dans `app/breakglass.py` |
| Points d’entrée | `app/auth.py`, `app/subdomain/subdomain_auth.py` |
| Listing admin | `GET /api/admin/breakglass/sessions` → `chains[]` (groupé) |
| Purge | par chaîne (max `expires_at`) |
| Tests | `tests/test_breakglass_rotation_replay.py` |

**Comportement** :

1. Login → `chain_id = jti` initial.
2. Requête OK → nouveau `jti`, ancien `superseded_by`/`superseded_at` ; `Set-Cookie` ; `exp` et ancrage IP/empreinte **inchangés**.
3. Rejeu &lt; 5 s → `breakglass_cookie_grace_reuse` + cookie tip.
4. Rejeu &gt; 5 s → `chain_revoked` sur toute la chaîne + `breakglass_cookie_replay_detected` + `401` (y compris le tip légitime).
5. Admin « Révoquer » → `revoked*` sur le jti ciblé + `chain_revoked` partout.

**Prod** :

- [ ] Migration `025` appliquée
- [ ] Vérifier qu’un rejeu hors grâce coupe aussi le cookie courant
