# Addendum — retest offensif F-01 (posture attaquant)

**Date :** 2026-07-26 (~12:51 UTC)  
**Cible :** `https://portal.ar-systems.fr` → **172.24.0.108** (DNS re-vérifié immédiatement avant les probes)  
**Autorisation :** Vincent — périmètre **A** (« un attaquant n’a pas de compte breakglass »)  
**Script :** `scripts/offensive_f01_attacker_retest_20260726.py`  
**Preuves :** [`rapport-audit-securite-bastion-offensif-addendum-2026-07-26-evidence.json`](rapport-audit-securite-bastion-offensif-addendum-2026-07-26-evidence.json)  
**Rapport parent :** [`rapport-audit-securite-bastion-offensif-2026-07-25.md`](rapport-audit-securite-bastion-offensif-2026-07-25.md)

## Périmètre et limites

| Inclus | Exclu (volontairement) |
|--------|-------------------------|
| Chemin réseau externe réel (TLS → reverse01) | Compte / mot de passe break-glass valide |
| Credentials inventés jetables | Baseline LAN « bon MDP » (étapes 1/4 du brief initial) |
| Spoof `X-Real-IP` / `X-Forwarded-For` / `X-Portal-Client-IP` / `CF-Connecting-IP` | Lecture `/admin/logs` (`resolved`) — nécessite session admin |

**Conclusion anticipée sur F-01 :** ce retest **ne peut pas** conclure « F-01 prouvé efficace avec bon mot de passe + IP externe ». Un attaquant sans secret ne produit que des rejets indiscernables (mauvais MDP vs politique IP). La réserve du rapport du 25/07 **reste ouverte** pour la preuve isolée F-01.

Contexte ops (hors posture attaquant, déjà documenté ailleurs) : login break-glass légitime LAN réussi le 26/07/2026 12:07:57 UTC depuis `192.168.2.172` (jti `b2770768-…`) — chaîne IP réelle corrigée côté reverse01. Cela ne remplace pas le test « bon MDP + IP non-LAN ».

---

## Étape A1 — Mauvais mot de passe, chemin externe, sans spoof

**Méthode.** `POST /auth/login` et `POST /api/admin/breakglass/login` avec  
`audit-attacker-probe-20260726` / mot de passe inventé (n’existe pas).

| Surface | Status | `bg_session` | Corps / détail |
|---------|--------|--------------|----------------|
| HTML `/auth/login` | **200** (page login) | **non** | message « Identifiants invalides » |
| API `/api/admin/breakglass/login` | **401** | **non** | `{"detail":"Invalid credentials"}` |

**Note vs 25/07 :** l’API répond désormais **401 JSON** (plus un 302 SSO nginx). Compatible avec un déploiement F-06 / exposition LAN de l’API, mais depuis l’extérieur on n’obtient toujours **pas** de session.

**Conclusion étape :** rejet sans session, attendu pour un attaquant. **N’isole pas** la politique IP.

---

## Étape A2 — Même mauvais MDP + spoof IP LAN (dont `X-Portal-Client-IP`)

**Méthode.** Identiques credentials ; headers client :

```
X-Real-IP: 10.0.0.5
X-Forwarded-For: 10.0.0.5
X-Portal-Client-IP: 10.0.0.5
CF-Connecting-IP: 192.168.1.50
```

| Surface | Status | `bg_session` | Détail |
|---------|--------|--------------|--------|
| HTML | **200** | **non** | Identifiants invalides |
| API | **401** | **non** | Invalid credentials |

GET protégés avec les mêmes headers spoofés :

| Path | Status | Location |
|------|--------|----------|
| `/admin` | 302 | `/auth/login?rd=/admin` |
| `/admin/logs` | 302 | `/auth/login?rd=/admin/logs` |
| `/dashboard` | 302 | `/auth/login?rd=/apps` |
| `/api/apps` | 301 | `/api/apps/` |

**Conclusion étape :** spoof client **inefficace** pour obtenir `bg_session` ou ouvrir l’admin. Cohérent avec un reverse qui impose / écrase l’IP de confiance.  
**Non vérifiable en posture A :** le champ audit `resolved` (nécessite `/admin/logs`). On ne prouve donc pas ici que `resolved` = IP externe réelle plutôt que `10.0.0.5`.

---

## Étapes non exécutées (brief initial §1–4)

| Étape brief | Statut | Raison |
|-------------|--------|--------|
| 0 — Compte jetable + vrai MDP | **non faite** | Périmètre A : pas de compte break-glass |
| 1 — Baseline LAN bon MDP | **non faite** | Idem |
| 2 — Bon MDP + IP non-LAN | **non faite** | Idem — **seul test qui isole F-01** |
| 3 — Bon MDP + spoof depuis externe | **non faite** | Remplacée par A2 (mauvais MDP + spoof) |
| 4 — Non-régression LAN | **non faite** | Dépend des étapes 1–3 |

---

## Verdict F-01 (addendum 2026-07-26)

| Affirmation | Statut |
|-------------|--------|
| Attaquant externe sans secret n’obtient pas `bg_session` | **Observé** (HTML + API) |
| Spoof `X-Portal-Client-IP` / XFF / X-Real-IP ne crée pas de session | **Observé** |
| `resolved` audit = vraie IP externe sur rejet | **Non vérifié** (pas d’accès logs) |
| **« F-01 prouvé efficace avec bon mot de passe + IP externe »** | **Non prouvé** — réserve maintenue |

Pour clôturer F-01 sans ambiguïté, il faudra un **périmètre B** (compte jetable fourni hors bande) ou un opérateur LAN qui rejoue le brief §1–4 avec le bon MDP.

---

## Fichiers

- Preuves JSON : `rapport-audit-securite-bastion-offensif-addendum-2026-07-26-evidence.json`
- Script : `scripts/offensive_f01_attacker_retest_20260726.py`
