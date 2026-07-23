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
- **Signature** : `resolve_breakglass_signing_secret()` — priorité env
  `BREAKGLASS_JWT_SECRET`, sinon secret UI chiffré (`portal_settings`), sinon
  `VAULT_PORTAL_INTERNAL_TOKEN`, sinon secret éphémère process-lifetime
- **Validation** : `decode_breakglass_token_with_fallback()` accepte la source
  active + secret UI courant/précédent + legacy (si fallback) pendant la transition
- **Refresh** : re-signe toujours avec la source active (upgrade des cookies)
- **Ansible** : `portal.env.j2` + defaults `breakglass_jwt_secret*`
- **UI** : Admin → Sécurité → Break-glass JWT (statut + génération si env absente)
- **Tests** : `tests/test_breakglass_jwt_secret.py`, `tests/test_breakglass_secret_status.py`

**Ops** : renseigner `BREAKGLASS_JWT_SECRET` en vault (distinct de
`VAULT_PORTAL_INTERNAL_TOKEN`), laisser le fallback actif le temps d’un cycle de
sessions BG (≤ 8h), puis `BREAKGLASS_JWT_SECRET_FALLBACK_ENABLED=false`.

### Filet de sécurité UI (statut + remédiation)

| Date | Statut | Résumé |
|------|--------|--------|
| 2026-07-23 | **Livré (code)** | Statut visible Admin → Sécurité ; génération UI si env absente. |

**Pourquoi** : après déploiement du secret dédié, rien dans l’admin ne permettait de
vérifier si `BREAKGLASS_JWT_SECRET` était positionné et distinct du token partagé
(lecture logs / SSH uniquement).

**Comportement** :

1. **Canal principal** reste AWX (`BREAKGLASS_JWT_SECRET` dans `portal.env`).
2. **Filet UI** : si l’env est absente, l’admin peut générer un secret aléatoire
   (`secrets.token_urlsafe(32)`), stocké chiffré dans
   `portal_settings.breakglass_jwt_secret_encrypted` (même Fernet que les secrets
   realm). Pas de saisie manuelle ; pas d’affichage en clair ; audit
   `breakglass_secret_generated_from_ui` / `breakglass_secret_rotated_from_ui`
   (acteur seulement, jamais la valeur).
3. Si l’env est déjà définie, le bouton est **grisé** — l’UI ne doit pas
   écraser le canal as-code.
4. Rotation UI : ancienne valeur conservée dans
   `breakglass_jwt_secret_previous_encrypted` pour validation sans coupure.
5. Statut 🟢 **Conforme** si source active `env` ou `ui` **et** distincte de
   `VAULT_PORTAL_INTERNAL_TOKEN` (`hmac.compare_digest`) ; sinon 🔴.

**Prod (à renseigner après vérif)** : env AWX positionnée / ou secret UI généré
en attendant le prochain run AWX — cocher ici une fois confirmé sur l’instance.

- [ ] Prod : `BREAKGLASS_JWT_SECRET` présent via AWX **ou** secret UI actif
- [ ] Prod : statut Admin → Sécurité → Break-glass JWT = Conforme

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

---

## §9 — Filet UI : statut + remédiation `BREAKGLASS_JWT_SECRET`

Voir sous-section **Filet de sécurité UI** sous Gap #1 ci-dessus.

Livrables code (2026-07-23) :

| Élément | Emplacement |
|---------|-------------|
| Résolveur 3 sources | `app/breakglass.py` (`resolve_breakglass_signing_secret*`) |
| Stockage chiffré | `portal_settings.breakglass_jwt_secret[_previous]_encrypted` + migration `023` |
| Service statut / génération | `app/breakglass_secret_service.py` |
| UI admin | Admin → Sécurité → onglet Break-glass JWT |
| Tests | `pytest -k breakglass_secret_status` |
