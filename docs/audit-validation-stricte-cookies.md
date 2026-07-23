# Audit — Validation stricte des cookies (suivi)

> Document de suivi issu de l’audit du 2026-07-23 (`audit-validation-stricte-cookies`).
> Complète `audit-gestion-sessions.md` (durée / révocation) sur l’axe **attributs +
> intégrité** des cookies.

## §8 — Ordre d’implémentation

| # | Point | Statut |
|---|---|---|
| 1 | Secret HMAC `bg_session` dédié (`BREAKGLASS_JWT_SECRET`) | **Corrigé** (2026-07-23) |
| 2 | Test explicite claim `type == "bg"` | **Corrigé** (déjà en code ; test ajouté) |
| 3 | `cookie_samesite="lax"` + smoke flags oauth2-proxy | **Corrigé** (2026-07-23) |
| 4 | Doc politique `cookie_secret` | **Corrigé** → `docs/oauth2-cookie-secret-policy.md` |
| 5 | Préfixe `__Secure-` | Hors périmètre (différé) |

---

## Gap #1 — Secret break-glass dédié

| Date | Statut | Résumé |
|------|--------|--------|
| 2026-07-23 | **Corrigé** | Signature `bg_session` via `BREAKGLASS_JWT_SECRET` ; fallback temporaire sur `VAULT_PORTAL_INTERNAL_TOKEN`. |

### Implémentation réelle

- **Settings** : `breakglass_jwt_secret`, `breakglass_jwt_secret_fallback_enabled` (défaut `true`)
- **Signature** : `resolve_breakglass_signing_secret()` — secret dédié, sinon secret
  éphémère process-lifetime (log warning) si env absente
- **Validation** : `decode_breakglass_token_with_fallback()` / `validate_breakglass_cookie(..., settings=)`
  essaie d’abord le secret dédié, puis (si fallback) l’ancien token Bearer
- **Refresh** : re-signe toujours avec le secret dédié (upgrade des cookies legacy)
- **Ansible** : `portal.env.j2` + defaults `breakglass_jwt_secret*`
- **Tests** : `tests/test_breakglass_jwt_secret.py` (+ suite `-k breakglass`)

**Ops** : renseigner `BREAKGLASS_JWT_SECRET` en vault (distinct de
`VAULT_PORTAL_INTERNAL_TOKEN`), laisser le fallback actif le temps d’un cycle de
sessions BG (≤ 8h), puis `BREAKGLASS_JWT_SECRET_FALLBACK_ENABLED=false`.

---

## Gap #2 — Claim `type == "bg"`

| Date | Statut | Résumé |
|------|--------|--------|
| 2026-07-23 | **Confirmé + test** | Déjà dans `decode_breakglass_token()` ; test `test_breakglass_rejects_wrong_type_claim`. |

---

## Gap #3 — Flags oauth2-proxy

| Date | Statut | Résumé |
|------|--------|--------|
| 2026-07-23 | **Corrigé** | `cookie_samesite = "lax"` dans le générateur ; smoke Ansible sur les 3 flags ; page Alignement sessions enrichie. |

### Implémentation réelle

- `generate_oauth2_proxy_config()` + `docker/oauth2-core/oauth2-proxy.cfg.example`
- Smoke : `ansible/roles/bastion_app_docker/tasks/smoke_test.yml` (échec si ligne absente)
- UI lecture seule : `/admin/realms/session-alignment` colonne Flags

---

## Gap #4 — Politique `cookie_secret`

| Date | Statut | Résumé |
|------|--------|--------|
| 2026-07-23 | **Corrigé** | `docs/oauth2-cookie-secret-policy.md` (génération, stockage Fernet, rotation manuelle). |

---

## Clarification famille C (robotic)

Les cookies CrushFTP / Grommunio ne sont **pas** signés par le bastion ; httpOnly/secure/SameSite
sont appliqués au rejeu via `build_response_cookies()`. Intégrité at-rest = vault applicatif
(hors ce document).
