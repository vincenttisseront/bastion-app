# Rapport complémentaire — audit offensif bastion

**Date :** 2026-07-25 (soir)  
**Cible :** `https://portal.ar-systems.fr` → **172.24.0.108** (vmdmz-reverse01) → portal Docker **172.24.0.110**  
**Autorisation :** Vincent — « démarre la partie offensif » (chat), IP re-résolue immédiatement avant les probes.  
**Preuves brutes :** [`rapport-audit-securite-bastion-offensif-evidence.json`](rapport-audit-securite-bastion-offensif-evidence.json)  
**Script :** `scripts/offensive_staging_probes.py`  
**Limites respectées :** pas de DoS, pas de bruteforce prolongé (5 essais), credentials jetables uniquement, pas de session admin réelle.

## Prérequis / périmètre déployé

| Correctif | Dans le working tree local | Observé sur staging ce soir |
|-----------|----------------------------|-----------------------------|
| Chaîne IP trusted-proxy (Partie 1) | Oui | **Non confirmé déployé** |
| F-01 LAN break-glass app | Oui | Comportement compatible (pas de `bg_session`) |
| F-03 API apps RBAC | Oui | Non testable live sans compte restreint |
| F-04 bypass RFC1918 off | Oui | Non testable live (flag + auth_request) |
| F-06 API break-glass hors auth_request | Oui | **Non** — API toujours **302 → SSO** |
| F-07 `/internal/*` → 404 public | Oui | **Oui** — 404 nginx |

**Point ops hors repo :** la fiabilité F-01/F-04 en conditions réelles dépend encore du nginx host DMZ (`awx-playbook` / `nginx_reverse_proxy_dmz`) qui doit poser `X-Real-IP $remote_addr` + `X-Forwarded-For $proxy_add_x_forwarded_for`.

**Chemin réseau des probes live :** poste auditeur → DNS → TLS vers `portal.ar-systems.fr` (172.24.0.108) → reverse DMZ → stack portal. Ce n’est pas une simulation header-only locale.

---

## 1 — Bypass break-glass depuis une source externe

**Méthode.** `POST /auth/login` et `POST /api/admin/breakglass/login` avec user/mot de passe jetables (`audit-offensive-probe-20260725` / mot de passe faux), sans spoof puis avec `X-Real-IP` / `X-Forwarded-For` / `CF-Connecting-IP` RFC1918.

**Résultat.**
- HTML : **200** page login, **aucun** `Set-Cookie: bg_session`, message d’échec (« Identifiants invalides » vérifié en follow-up).
- Spoof RFC1918 : **identique** — pas de cookie session.
- API : **302** nginx vers `/auth/login?rd=/apps` (auth_request encore actif → F-06 non appliqué sur l’edge).

**Conclusion :** **fermé** pour l’obtention d’une session avec credentials jetables + spoof depuis l’extérieur.  
**Réserve :** sans mot de passe break-glass de test valide, on ne prouve pas encore le cas « bon secret + IP réellement publique après chaîne DMZ ». À rejouer après déploiement Partie 1 + confirmation XFF DMZ.

---

## 2 — Spoofing d’en-têtes (matrice)

**Méthode.** GET `/api/apps`, `/admin`, `/dashboard`, `/api/admin/breakglass/sessions` avec XFF, X-Real-IP, CF-Connecting-IP, True-Client-IP, X-Client-IP et combinaisons contradictoires.

**Résultat.** Toutes les surfaces protégées restent en **301/302** vers login SSO. Aucun 200 admin/catalogue, aucun `bg_session`.

**Conclusion :** **fermé** pour élévation non authentifiée via spoof d’IP/CDN headers sur le chemin public.

---

## 3 — SSRF analyzer (admin)

**Méthode.** `POST /admin/apps/analyze-login-form` sans session, URLs `127.0.0.1`, metadata AWS, `10.5.0.1`, `172.24.0.110`.

**Résultat.** **302** → `/auth/login?rd=/admin/apps/analyze-login-form` pour toutes. Pas de JSON `forms_found`.

**Conclusion :** **fermé** sans auth.  
**Non testable** en conditions admin authentifiées (pas de compte admin jetable fourni) — la preuve F-02 reste celle des tests unitaires SSRF locaux + code analyzer.

---

## 4 — JWT break-glass (falsification)

**Méthode.**
- Cookies forgés (`alg=none`, signature vide, secret `dev`, expiré) envoyés vers `/internal/oauth2-auth` sur staging.
- Décodage local PyJWT `algorithms=["HS256"]` (miroir app) + `decode_breakglass_token`.

**Résultat.**
- Staging : **404** nginx sur `/internal/oauth2-auth` (F-07) — pas de validation auth réussie (`x-auth-source` absent).
- Local : `alg=none` → `InvalidAlgorithmError` ; signature vide / mauvais secret → rejet ; token valide HS256 + claims `type=bg` accepté uniquement avec le bon secret.

**Conclusion :** **fermé** pour contournement via JWT forgé sur la surface publique. La lib refuse `alg=none` quand la liste d’algos est restreinte à HS256.

---

## 5 — Host header / subdomain RBAC

**Méthode.**
- Sur le vhost portal : GET `/internal/subdomain-auth` avec `X-Original-Host` usurpé (`transfer…`, `evil.example`, …) — **sans** casser le SNI TLS.
- Accès direct `https://transfer.ar-systems.fr/` (résout aussi 172.24.0.108).

**Résultat.**
- `/internal/subdomain-auth` public : **404** (F-07) — pas de bypass auth_request.
- `transfer.ar-systems.fr` : **302** vers UI CrushFTP (`/WebInterface/new-ui/...`) sans `bg_session` — comportement vhost normal, pas d’ouverture portal admin via Host.

**Conclusion :** **fermé** pour injection Host vers le handler interne public. Test RBAC cross-app authentifié (session A → Host app B) **non testable** sans comptes jetables.

---

## 6 — IDOR catalogue (F-03)

**Méthode.** GET `/api/apps` et `/api/apps/{slug}` sans session ; follow redirect sur `/api/apps/`.

**Résultat.** Redirections SSO / page login — **pas** de JSON catalogue.  
Couverture authentifiée : tests unitaires `tests/security/test_f03_api_apps_rbac.py` (11 passed dans la session) — code local filtre AccessGrant.

**Conclusion :** surface anonyme **fermée**. IDOR authentifié **non rejoué live** (pas de user restreint) ; **fermé en unit** si le lot F-03 est déployé.

---

## 7 — Anti-bruteforce break-glass

**Méthode.** 5 `POST /auth/login` contrôlés (intervalles ~0,3 s), mots de passe jetables distincts.

**Résultat.** 5× **200** en ~23–38 ms, **pas** de `429`, **pas** de `Retry-After`, pas de ralentissement observé.  
Nginx `limit_req` `portal_login` (3 r/s, burst 5) existe en template mais n’a pas produit de rejet sur cet échantillon.

**Conclusion :** **finding nouveau (F-10, Faible/Moyenne)** — **pas de verrouillage applicatif** (lockout / progressive delay) sur le login break-glass. À ajouter à la grille de correctifs (throttle par IP+username, backoff, éventuel CAPTCHA LAN-only).

---

## Niveau de sécurité global (mise à jour)

| Avant (audit léger) | Après offensif |
|---------------------|----------------|
| **Faible** (F-01/F-02 principalement) | **Faible → Faible+** : pas de réouverture critique observée sur staging pour spoof/JWT/internal ; **nouveau F-10** (absence lockout break-glass). |

Les risques structurels restants sont surtout **ops / déploiement** :
1. Déployer Partie 1 (nginx-bastion + app trusted proxy) + vérifier DMZ XFF.
2. Déployer F-06 (API break-glass LAN hors `auth_request`).
3. Traiter F-10 (anti-bruteforce).

Sans déploiement de la chaîne IP, **ne pas déclarer F-01/F-04 « fiables en production »** malgré les preuves unitaires et l’absence de bypass spoof observée ce soir.

---

## Prochaines actions recommandées

1. Commit + déploiement staging du lot (F-03/F-04/F-06 + chaîne IP + pydantic-settings 2.14.2).  
2. Checklist ops DMZ (`awx-playbook`) X-Real-IP / XFF.  
3. Re-probe offensif n°1 avec un **mot de passe break-glass de test jetable** depuis une IP clairement non-LAN.  
4. Correctif F-10 lockout break-glass.  
5. Si besoin : compte admin + user restreint jetables pour SSRF auth (n°3) et IDOR auth (n°6).
