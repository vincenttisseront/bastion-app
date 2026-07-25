# Rapport d'audit de sécurité — bastion-app

**Date :** 2026-07-25  
**Cible tests actifs :** `https://portal.ar-systems.fr` → IP confirmée `172.24.0.108` (nginx front) → portal Docker `172.24.0.110` (staging, confirmé Vincent)  
**Auditeur :** Cursor (revue code + probes actifs légers)  
**Correctifs :** non implémentés (audit seul)

---

## 1. Résumé exécutif

Le bastion présente une base solide (auth_request Nginx, strip des en-têtes d'identité, break-glass bcrypt + JWT + jti, vault Fernet, couverture de routes CI, cookies Secure/HttpOnly, pip-audit sans CVE connue). Deux faiblesses structurelles tirent le niveau global vers le bas : (1) l'endpoint « Analyser » formulaire de login n'a **aucun filtrage SSRF** des cibles internes/metadata malgré timeout et `require_admin` ; (2) la restriction LAN sur `/breakglass` est **contournable** via `POST /auth/login`, public et hors allowlist IP. Les probes actifs sans session confirment le refus des surfaces admin/vault et l'inefficacité d'un spoof XFF pour ouvrir `/admin` ou `/api/apps`. Niveau global : **Faible** (maillon le plus faible, pas une moyenne).

---

## 2. Périmètre et méthodologie

### Couvert
- Code `app/` (auth, break-glass, vault, robotic, subdomain, proxy placeholder, audit, route_access)
- Templates Nginx `nginx/vhosts/*.j2`, `nginx/snippets/*.j2`, `docker/nginx/**`
- `.env.example`, `pyproject.toml`
- Tests actifs légers contre staging (IP confirmée)
- `ruff check app/`, `pip-audit` (deps hors sqlcipher Linux-only)

### Non couvert / hors périmètre
- Infra réseau physique, sécurité Keycloak IdP, tests de charge/DoS
- Tests authentifiés SSO complets (pas de compte de test jetable fourni) → pas de validation IDOR catalogue avec session utilisateur, ni SSRF « Analyser » en session admin réelle
- Confirmation `.env` Fernet distinct prod/staging : non vérifiée côté ops

### Commandes / scripts réellement exécutés

```text
nslookup portal.ar-systems.fr
# → 172.24.0.108 (CNAME vmdmz-reverse01) — confirmé staging par Vincent

python -m ruff check app/
python -m pip_audit -r <deps sans sqlcipher3-binary>
python -m pytest tests/security/ -v
python tests/security/dump_staging_evidence.py
```

Scripts persistants : `tests/security/test_active_staging_light.py`, `tests/security/test_ssrf_analyzer_static.py`, `tests/security/dump_staging_evidence.py`.

Résultat pytest sécurité : **21 passed** (2026-07-25).

---

## 3. Synthèse par catégorie

| Catégorie | Niveau | Résumé |
|---|---|---|
| Authentification & bypass | Faible | Bypass LAN `/breakglass` contournable via `/auth/login` public ; RFC1918 portail désactivé (bien) mais subdomain encore dépendant de `X-Real-IP` |
| RBAC / autorisation | Moyen | AccessGrant sur subdomain + couverture routes CI ; `GET /api/apps` expose toute la config sans filtre grant |
| Vault & secrets | Bon | Fernet + store local, API credential sans plaintext, Bearer interne ; hop HMAC fallback `"dev"` si token absent |
| Drivers robotic SSO | Bon | Timeouts, cookies host-only par défaut, messages d'erreur sans secret ; SSRF driver limité aux URL admin configurées |
| SSRF / endpoints sortants | Faible | Analyzer : timeout/redirects OK, **pas de deny-list** IP privées / metadata |
| Sessions & cookies | Bon | `bg_session` httponly/secure/SameSite=lax ; hop TTL 60s ; `wide_domain` opt-in documenté |
| Audit & logs | Bon | Pas de password dans `log_action` vault ; middleware documente l'absence de body logging |
| Configuration Nginx/Docker | Moyen | Strip identity + auth_request scopé ; `/auth/` public vs `/breakglass` LAN ; `/internal/*` parfois 302 au lieu de 404 |
| Dépendances | Élevé | `pip-audit` : aucune CVE connue sur les deps auditées |

---

## 4. Findings détaillés

### F-01 — Élevée — Restriction LAN break-glass contournable via `/auth/login`

**Description.** Nginx restreint `/breakglass` aux RFC1918, mais le formulaire et `POST /auth/login` acceptent le mot de passe break-glass **sans** allowlist IP.

**Preuve (config).**

```157:180:nginx/vhosts/vhost_sso_portal.conf.j2
    # Break-glass : page publique hors SSO (GET + POST), sans auth_request — LAN uniquement
    location ^~ /breakglass {
        auth_request off;
        allow 127.0.0.0/8;
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
        ...
    }

    # Entrée SSO publique (sans auth_request) — construit /oauth2/{realm}/start?rd=…
    location ^~ /auth/ {
        auth_request off;
        ...
    }
```

```339:375:app/web/pages.py
@router.post("/auth/login")
async def login_post(...):
    ...
    if not verify_breakglass_password(db, username, password):
        ...
        return render("auth/login.html", **ctx)
    return _breakglass_login_response(...)
```

**Preuve (actif).** `POST /auth/login` avec mauvais mot de passe → HTTP 200 page login, **pas** de `Set-Cookie bg_session` (dump_staging_evidence.py). Le endpoint est joignable hors location LAN.

**Impact.** Un attaquant Internet peut bruteforcer / tenter le compte break-glass malgré la restriction documentée « LAN uniquement » sur `/breakglass`.

**Recommandation.** Appliquer la même allowlist IP (ou `auth_request` + challenge) sur `POST /auth/login` pour la branche break-glass, ou déplacer le POST break-glass sous `/breakglass` uniquement et retirer la vérification mot de passe de `/auth/login`.

---

### F-02 — Élevée — SSRF « Analyser » : aucun filtrage des cibles internes

**Description.** `validate_analyze_url` n'accepte que le schéma http(s) ; `fetch_login_page` n'utilise pas `ipaddress`, ne bloque ni loopback, RFC1918, ni `169.254.169.254`.

**Preuve (code).**

```173:206:app/bastion/login_form_analyzer.py
def validate_analyze_url(url: str) -> str:
    ...
    if parsed.scheme not in ("http", "https"):
        raise AnalyzeLoginFormError(...)
    ...
async def fetch_login_page(url: str) -> tuple[str, str]:
    validate_analyze_url(url)
    ...
        async with httpx.AsyncClient(
            timeout=TIMEOUT_SECONDS,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
```

**Preuve (test).** `tests/security/test_ssrf_analyzer_static.py` — `validate_analyze_url("http://169.254.169.254/...")` **accepte** l'URL ; module sans `import ipaddress`.

**Mitigations présentes.** `require_admin` sur la route ; timeout 10 s ; max 5 redirects ; body ≤ 2 Mo.

**Preuve (actif).** Sans session : `POST /admin/apps/analyze-login-form` → 302 `/auth/login` (non exploitable anonymement).

**Impact.** Un admin compromis (ou XSS admin) peut faire le bastion fetcher le réseau interne / metadata cloud.

**Recommandation.** Résoudre le host, refuser IP privées/loopback/link-local/metadata, bloquer DNS rebinding (re-check après redirect), allowlist optionnelle de préfixes.

---

### F-03 — Moyenne — `GET /api/apps` sans filtre AccessGrant

**Description.** Tout utilisateur authentifié reçoit la liste complète des apps enabled avec `upstream_url`, champs de login, etc.

```120:123:app/services.py
@authenticated_router.get("", response_model=list[AppOut])
def list_apps(db: Session = Depends(get_db)):
    apps = db.query(App).filter_by(enabled=True).all()
    return [_app_to_out(app) for app in apps]
```

Le portail HTML utilise `get_effective_apps_for_user` (`app/web/portal.py`) — l'API catalogue non.

**Impact.** Fuite d'URL internes et de la surface d'attaque applicative à tout compte SSO valide.

**Recommandation.** Filtrer comme le catalogue effectif, ou réserver `GET /api/apps` aux admins / token interne.

---

### F-04 — Moyenne — Confiance aux en-têtes client pour l'IP (subdomain RFC1918)

**Description.** `client_ip_from_request` lit `CF-Connecting-IP` / `True-Client-IP` / `X-Client-IP` / XFF sans ACL « trusted proxy ». Le bypass RFC1918 du **portail** est désactivé (bien) :

```122:124:app/auth.py
    # Do NOT apply RFC1918 bypass here. Behind Traefik/vpcbr, X-Real-IP is often
    # 10.5.0.0/16 — a bypass would return 200 with no identity...
```

Mais subdomain applique encore le bypass sur `X-Real-IP` :

```126:135:app/subdomain/subdomain_auth.py
    client_ip = request.headers.get("X-Real-IP", "")
    if settings.rfc1918_bypass_enabled and _is_rfc1918(client_ip, settings.rfc1918_cidrs):
        return Response(status_code=200, headers={"X-Auth-Source": "rfc1918-bypass"})
```

Nginx map fait confiance à `$http_x_real_ip` s'il est présent (`docker/nginx/includes/nginx-portal-client-ip.map.conf`).

**Preuve (actif).** Spoof `X-Forwarded-For: 10.0.0.50` + `X-Real-IP: 10.0.0.50` sur `/apps` et `/admin` → toujours 302 login (pas d'ouverture admin).

**Impact.** Risque surtout si FastAPI est joignable hors Nginx, ou si l'edge ne réécrit pas `X-Real-IP`. Sur le chemin nginx confirmé, le spoof externe n'ouvre pas le portail.

**Recommandation.** Désactiver RFC1918 en staging/prod exposé (`RFC1918_BYPASS_ENABLED=false` déjà dans ansible docker) ; ne pas faire confiance aux en-têtes edge non écrasés ; unifier sur `client_ip_from_request` + peers de confiance.

---

### F-05 — Moyenne — Secret hop cookies : fallback `"dev"` + couplage au token interne

```48:50:app/robotic/session_cookie_hop.py
def _hop_secret(settings: Settings) -> bytes:
    raw = (settings.vault_portal_internal_token or "").strip() or "dev"
    return hashlib.sha256(f"session-cookie-hop:{raw}".encode()).digest()
```

**Impact.** Si `VAULT_PORTAL_INTERNAL_TOKEN` est absent, HMAC prévisible ; réutilisation du token vault pour signer des cookies de session cible.

**Recommandation.** Exiger un secret dédié ; refuser le démarrage si absent (comme le vault Fernet).

---

### F-06 — Faible — API break-glass login derrière `auth_request` Nginx

FastAPI allowlist `PUBLIC_ROUTES_ALLOWLIST` inclut `/api/admin/breakglass/login`, mais `location ^~ /api/admin` impose `auth_request`. Probe : POST → 302 `/auth/login?rd=/apps`.

**Impact.** Pas de faille d'élévation ; recovery API inutilisable sans SSO (incohérence ops). Le flux HTML `/auth/login` reste le vrai vecteur (F-01).

**Recommandation.** Exclure `/api/admin/breakglass/login|logout` de la location auth, **avec** la même allowlist LAN que `/breakglass`.

---

### F-07 — Faible — `/internal/oauth2-auth` et `/internal/portal-rfc1918-bypass-auth` répondent 302 (pas 404)

**Preuve (actif).**  
- `/internal/subdomain-auth` → **404** (attendu pour `internal`)  
- `/internal/oauth2-auth` → **302** login  
- `/internal/portal-rfc1918-bypass-auth` → **302** login  

Pas de `X-Auth-Source` en anonyme (pas de bypass observé).

**Recommandation.** Forcer `location = /internal/... { internal; }` (ou deny) sur le vhost edge pour tous les handlers auth, pas seulement via `/portal_auth_check`.

---

### F-08 — Faible — JWT break-glass : fallback legacy sur `VAULT_PORTAL_INTERNAL_TOKEN`

Priorité env → UI → legacy vault token → éphémère (`app/breakglass.py`). Cookie flags OK :

```811:826:app/breakglass.py
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        ...
        httponly=True,
        secure=True,
        samesite="lax",
    )
```

Break-glass bypass AccessGrant sur subdomain : **volontaire** (commentaire 2026-07-23) — à traiter comme risque résiduel accepté, pas un bug.

**Recommandation.** Forcer `BREAKGLASS_JWT_SECRET` dédié ; désactiver le fallback legacy en prod.

---

### F-09 — Info — En-têtes de sécurité dupliqués

`/health` renvoie HSTS / X-Frame-Options / etc. **deux fois** (concaténés). Fonctionnellement OK ; hygiène Nginx (un seul `add_header`).

### F-10 — Info — Dépendances

`pip-audit` (20 deps, sqlcipher exclu Windows) : **No known vulnerabilities found**. `ruff` : 8 findings style/qualité, pas de `eval`/`verify=False`/SQL concat dangereux trouvé.

### F-11 — Info — Points positifs vérifiés

| Contrôle | Preuve |
|---|---|
| Admin sans session | 302 login (`/admin`, `/dashboard`, `/api/admin/...`) |
| Vault sans Bearer | 302/401/403, pas de password dans le corps |
| Bearer inventé | refusé |
| Analyzer sans auth | 302 |
| XFF spoof ≠ accès | 302 sur `/apps` et `/admin` |
| Pas de traceback 404 | chemins inconnus → 302 login, corps sans traceback |
| Identity strip Nginx | `proxy_portal_strip_identity.conf` |
| Route coverage CI | `tests/test_route_coverage.py` + allowlist justifiée |
| CredentialOut | username/métadonnées seulement (`app/vault/routes.py`) |
| `.env.example` | tokens placeholder, pas de secret réel |

---

## 5. Niveau de sécurité global

**Faible**

Justification (règle maillon faible) : les catégories Authentification et SSRF portent des findings **Élevée** et sont notées **Faible**. Le niveau global ne peut pas dépasser cette borne, malgré Vault/Dépendances/Sessions à Bon/Élevé.

---

## 6. Plan d'action priorisé

### Quick wins
1. **F-01** — Allowlist IP (ou déplacement) du POST break-glass sur `/auth/login` / aligner avec `/breakglass`
2. **F-02** — Deny-list SSRF (IP privée, loopback, link-local, metadata) + revalidation post-redirect
3. **F-05** — Secret hop dédié, fail-closed si absent
4. **F-08** — `BREAKGLASS_JWT_SECRET` obligatoire, fallback legacy off en prod
5. **F-07** — `internal`/`deny` sur tous les `/internal/*` auth au edge
6. **F-09** — Dédupliquer `add_header` sécurité

### Correctifs plus lourds
7. **F-03** — Aligner `GET /api/apps` sur AccessGrant / catalogue effectif
8. **F-04** — Revue bout-en-bout trusted proxies + désactivation RFC1918 hors LAN réel
9. **F-06** — Redesign locations Nginx break-glass API vs HTML
10. Campagne de tests actifs **authentifiés** (compte jetable) : IDOR grants, analyzer SSRF en session admin, cookies `bg_session` flags sur login réussi, absence password dans logs applicatifs

---

## 7. Couverture grille des 13 surfaces

| # | Surface | Mode | Résultat |
|---|---|---|---|
| 1 | Bypass RFC1918 | Statique + actif (spoof XFF) | Portail : bypass off. Subdomain : encore actif via X-Real-IP. Spoof externe n'ouvre pas `/admin` sur staging |
| 2 | Break-glass | Statique + actif (échec login) | bcrypt/JWT/cookie flags OK ; F-01 LAN bypass via `/auth/login` ; API login derrière SSO |
| 3 | Vault | Statique + actif (sans token) | Fernet OK ; refus sans/bogus Bearer ; plaintext absent des réponses |
| 4 | Drivers robotic | Statique | Timeouts, host-only, pas de log password trouvé ; pas de test actif login robotic |
| 5 | Analyser / SSRF | Statique + actif (unauth) | F-02 prouvé en code ; unauth bloqué ; **pas** de fetch admin réel (pas de compte) |
| 6 | RBAC | Statique (+ CI existante) | Route coverage ; F-03 catalogue ; IDOR session user non testé activement |
| 7 | Proxy legacy | Statique | Placeholder redirects Nginx, pas de proxy FastAPI arbitraire |
| 8 | Subdomain Host | Statique | `X-Original-Host` depuis `$host` ; spoof Host direct FastAPI non testé (dépend exposition réseau) |
| 9 | Sessions & cookies | Statique + actif partiel | Flags code OK ; login réussi non exercé (pas de credentials) |
| 10 | Audit | Statique | Pas de password dans details vault ; body middleware exclu |
| 11 | Secrets & config | Statique | `.env.example` propre ; F-05 fallback hop |
| 12 | Nginx auth_request | Statique + actif | Scoping globalement bon ; F-01/F-06/F-07 |
| 13 | Dépendances | `pip-audit` | Aucune CVE connue (hors sqlcipher non audité sur Windows) |

Aucun point n'est déclaré « sans risque » sans preuve associée.
