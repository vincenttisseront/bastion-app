# Audit — Protection contre l'usurpation d'identité (suivi)

> Design validé le 2026-07-23. Implémentation V1 livrée le même jour dans `bastion-app`.

## Décisions retenues (§7)

| # | Question | Décision |
|---|---|---|
| 1 | Granularité IP | `/24` IPv4, `/64` IPv6 (pas d'IP exacte) |
| 2 | Family B fort | `401` + re-auth obligatoire |
| 3 | Family A fort | `WARN` only (pas de coupure Keycloak en V1) |
| 4 | Ancrage SSO | Hash SHA-256 du/des cookie(s) oauth2-proxy |

**Matrice de dérive** (après revue) : changement de bloc IP seul = **fort** (même empreinte),
pas seulement IP+empreinte — un cookie volé rejoué avec le même User-Agent doit être détecté.

## Hors périmètre V1

- Family C (robotic/vault) — faux positifs CrushFTP
- GeoIP / impossible travel
- Fingerprinting client (JS/canvas)
- Auto-logout Keycloak sur signal fort SSO

---

## Clôture — implémentation réelle (2026-07-23)

| Élément | Emplacement |
|---------|-------------|
| Signaux purs | `app/security/identity_binding.py` |
| Politique A/B + purge | `app/security/session_binding_service.py` |
| Modèle BG étendu | `BreakGlassSession` (+ migration `024`) |
| Ancrage SSO | `SsoSessionAnchor` (`cookie_hash` unique) |
| Points d'entrée | `/internal/oauth2-auth`, `/internal/subdomain-auth` |
| UI | Badge `/sessions` si `mismatch_count > 0` |
| Audit | `session_hijack_suspected`, `session_fingerprint_drift` |
| Tests | `tests/test_identity_binding.py` |

**Comportement** :

- **B** : ancrage au login ; dérive forte → `401` (indistinguable d'un cookie invalide) + audit ;
  dérive faible (empreinte seule) → passe + log léger.
- **A** : première vue d'un cookie = ancrage (déploiement à chaud sans 401) ; dérive forte →
  `200` + `mismatch_count++` + audit `warn_only`.
- **Purge** ancrages SSO : `last_seen` > **30 jours** (via `expire_stale_sessions`).
- Jamais de cookie en clair en base ni dans les logs.

**Prod (à cocher)** :

- [ ] Migration `024_session_identity_binding` appliquée
- [ ] Test manuel : BG login puis requête autre `/24` → 401 + entrée audit
- [ ] Test manuel : SSO dérive forte → session toujours OK, audit WARN visible
