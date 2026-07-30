# Audit — anti-brute-force / banning préexistant (2026-07-30)

> Étape 0 avant toute nouvelle implémentation du module générique
> (`securite-anti-bruteforce-banning-generique` / pod `ptd_5sQCZyla1filo3NQJy8m`).
>
> **Verdict :** le module demandé est **déjà largement livré** dans `bastion-app`
> (migration `033_security_banning`, moteur `app/security/banning/`, middleware,
> UI onglet `/admin/security#banning`, tests `tests/test_security_banning.py`).
> L’étape 1 ne doit **pas** recréer un second moteur : elle doit combler les
> écarts listés en §7, ou se clôturer si le produit accepte l’existant.

Aucun code de production modifié pour produire ce rapport.

---

## 1. Persistance / ORM

| Point | État réel |
|---|---|
| ORM | **SQLAlchemy ORM** (`declarative_base` dans [`app/models.py`](../app/models.py)) |
| Session | `SessionLocal` / `get_db` dans [`app/database.py`](../app/database.py) ; engine via `create_portal_engine` ([`app/db_cipher.py`](../app/db_cipher.py)) |
| DB prod | SQLite (souvent SQLCipher) — `.env.example` : `DATABASE_URL=sqlite:///./portal.db` ; Docker Phase 7 : `sqlite:////var/lib/sso-portal/portal.db` |
| Migrations | **Alembic** sous [`migrations/versions/`](../migrations/versions/) |

### Modèles déjà présents (cohérents avec la spec)

| Modèle | Table | Migration |
|---|---|---|
| `SecurityPolicy` (singleton id=1, enable + CIDR break-glass) | `security_policy` | `033_security_banning` |
| `SecurityBanRule` | `security_ban_rules` | idem |
| `SecurityBan` | `security_bans` | idem |
| `SecurityAllowlistEntry` | `security_allowlist` | idem |

Conventions : snake_case tables, `Column` SQLAlchemy classiques, `utcnow()`, JSON pour `config_json` — **aligné** catalogue / RBAC.

**Implication étape 1 :** réutiliser ces modèles ; pas de nouvelles tables sauf besoin explicite (ex. persistance des compteurs multi-workers — absente aujourd’hui).

---

## 2. Points d’entrée sensibles

### 2.1 Login SSO

- **Pas de formulaire password SSO côté FastAPI.** Le login IdP est **oauth2-proxy + Keycloak** (`/oauth2/*` côté proxy, callback realm).
- Le bastion expose principalement :
  - `GET /auth/login` / `GET /breakglass` → page HTML ([`app/web/pages.py`](../app/web/pages.py)) avec lien OIDC + formulaire **break-glass**
  - `POST /auth/login` → **uniquement** break-glass (mot de passe vault)
- Les échecs SSO (mauvais mot de passe Keycloak) se produisent **chez Keycloak / oauth2-proxy**, hors du compteur `evaluate_login_attempt` actuel.

**Implication :** le module protège bien le **login break-glass** et le **surface admin HTTP** ; il ne voit pas les échecs de login Keycloak. Toute couverture SSO nécessiterait des hooks oauth2-proxy / logs IdP (hors périmètre actuel du moteur).

### 2.2 Break-glass

| Endpoint | Hook banning |
|---|---|
| `POST /auth/login` (HTML) | `is_breakglass_ip_allowed` + `evaluate_login_attempt` (pré + échec) |
| `POST /api/admin/breakglass/login` ([`app/breakglass.py`](../app/breakglass.py)) | Idem |
| Gate LAN | `SecurityPolicy.breakglass_allow_cidrs` / `deny_cidrs`, sinon RFC1918 |

Mécanisme d’échec : `401` (API) / message « Identifiants invalides » (HTML) + `breakglass.login_failed` en audit. Compteur anti-bruteforce : **oui**, via `evaluate_login_attempt(..., success=False)`.

### 2.3 `/admin/*` et `/api/admin/*`

- Routers FastAPI avec `dependencies=[Depends(require_admin)]` (ex. `admin_router` dans `pages.py`).
- **Protection banning en amont** : middleware ASGI [`SecurityBanMiddleware`](../app/security/banning/middleware.py) enregistré dans [`app/main.py`](../app/main.py) — **pas** un `Depends()` par router.
- Préfixes sensibles (`engine.is_sensitive_path`) :
  - `/auth/login`, `/auth/setup`
  - `/admin`, `/api/admin`
  - login API break-glass

**Implication :** le pattern middleware est le bon accroche pour hammering/IP ban ; garder `Depends` pour RBAC. Ne pas remplacer le middleware par une dépendance route-par-route.

### 2.4 IP source

Utiliser **`client_ip_from_request()`** ([`app/request_client_ip.py`](../app/request_client_ip.py)) — déjà branché dans le middleware et break-glass :

- Honore `X-Real-IP` / `X-Forwarded-For` **seulement** si le peer TCP est dans `TRUSTED_PROXY_CIDRS` (défaut Docker : `10.5.0.0/16`, `172.17.0.0/16`, `127.0.0.0/8` ; export Ansible `portal.env.j2`).
- Ignore `CF-Connecting-IP` / `True-Client-IP` (anti-spoof).
- Documenté F-01 / F-04 / `docs/ops-client-ip-chain.md`.

**Implication :** ne jamais lire `request.client.host` seul pour les bans.

---

## 3. Audit existant

[`app/audit.py::log_action`](../app/audit.py) :

```text
log_action(db, actor, action, target=None, details=None, ip_address=None, *, forward_to_siem=True)
  → AuditLog en SQLite + enqueue SIEM optionnel
```

Événements **déjà émis** par le moteur / service :

| Action | Quand |
|---|---|
| `security.ban.applied` | Ban auto ou manuel |
| `security.ban.lifted` | Levée manuelle ou auto (expiry) |
| `security.hack_attempt.detected` | Username leurre |
| `security.ban_rules.updated` | UI règles |
| `security.policy.updated` | Enable / CIDR break-glass |
| `security.allowlist.added` / `.removed` | Liste blanche |

**Implication :** réutiliser ces noms ; pas de nouveau bus d’audit.

---

## 4. Mécanismes déjà en place (ne pas dupliquer)

| Couche | Rôle | Interaction banning |
|---|---|---|
| Nginx `limit_req` (`portal_login` / `portal_api`) | Rate-limit edge (429) | **Complémentaire** — pas un ban DB ; message 429 nginx distinct |
| `SecurityBanMiddleware` | Ban IP + hammering + concurrent sur paths sensibles | Cœur du module |
| `evaluate_login_attempt` | Leurres + échecs login | Break-glass uniquement |
| Break-glass JWT / rotation / denylist jti | Session BG | En aval du ban |
| RBAC `require_admin` / AccessGrant | Authz | En aval |
| Session binding (IP/fingerprint WARN) | Anti-hijack SSO | Orthogonal |
| `app/admin/throttling.py` | Rate-limit **tests** OIDC/impersonate (mémoire) | **Ne pas fusionner** avec le ban moteur |

**Pas de** `slowapi` / `fastapi-limiter` / Redis pour le ban.

Compteurs hammering / failed_login : **deque in-memory** process-local (`engine._counters`). Sous multi-workers uvicorn, les seuils ne sont pas partagés.

---

## 5. UI admin

| Attendu spec | Réel |
|---|---|
| Page `/admin/security/banning` | **Onglet** `Banning` dans [`/admin/security`](../app/templates/admin/security.html) (`#banning`) |
| POST sous `/admin/security/banning/*` | Oui ([`pages.py`](../app/web/pages.py) : rules, add, lift, allowlist) |
| Config règles (seuils, fenêtres, durées) | Accordion : hammering, failed_login, hack_username, concurrent |
| Ban permanent + confirmation | Checkbox + `confirm_permanent` (service refuse permanent sans confirm) |
| Liste bans + Ajouter / Retirer | Oui (modales) |
| Éditer ban / Paste IP list CrushFTP | **Non** |
| Style | Même design system (`form-section`, `data-table`, modales bastion) |

**Implication :** étendre l’onglet existant plutôt que créer une page parallèle, sauf décision produit de splitter l’URL.

---

## 6. Réseau / docker

Chaîne Phase 7 :

```text
client → vmdmz-reverse01 (nginx) → Traefik → bastion-nginx → bastion-app:8000
```

- Edge pose typiquement `X-Portal-Client-IP` / chaîne forwardée ; nginx-bastion → app avec peer dans `10.5.0.0/16`.
- Résolution fiable = `client_ip_from_request` + `TRUSTED_PROXY_CIDRS`.
- Paths exclus middleware : `/static/`, `/media/`, `/api/health`, `/health`, `/ready`.

---

## 7. Couverture fonctionnelle vs spec CrushFTP générique

| Règle spec | État code | Écart |
|---|---|---|
| Anti-hammering N/T → ban | **Oui** (`RULE_HAMMERING`) | Un seul compteur « paths sensibles » ; `is_login_path()` existe mais **n’alimente pas** un 2ᵉ compteur login-only |
| Échecs login N/T → ban IP et/ou username | **Oui** (`RULE_FAILED_LOGIN`, `ban_username` dans `config_json`) | Uniquement sur **break-glass** (pas Keycloak) |
| Hammering **successful** logins → ban username | **Non** | Fonctionnalité CrushFTP absente |
| Usernames leurres → ban IP immédiat | **Oui** | Défaut : `administrator`, `root` — **`admin` volontairement omis** (compte BG légitime fréquent) |
| Connexions simultanées / IP | **Oui** (refus 429, pas de ban) | OK |
| Allowlist IP/username | **Oui** | OK (CIDR IP supportés) |
| Ban temp / permanent sans ambiguïté 0 | **Oui** (`ban_permanent` bool + confirm) | OK — ne copie pas l’UX CrushFTP |
| Expiry auto | **Oui** (`lift_expired_bans` à la volée) | Pas de job périodique dédié (suffisant à la requête) |
| Audit | **Oui** | OK |
| Ban username appliqué hors login | Partiel | Middleware ne vérifie que l’**IP** ; un ban `target_type=username` ne coupe `/admin` tant que le cookie SSO est valide |

Tests déjà nommés comme demandé par la spec :

- `test_security_hammering_*`
- `test_security_hack_username_*`
- `test_security_allowlist_*`
- `test_security_ban_expiry_*`
- `test_security_audit_*`
- (+ permanent confirm, failed_login, UI accordion, CIDR BG)

---

## 8. Implications concrètes pour l’étape 1

1. **Ne pas réimplémenter** `SecurityBan*` / middleware / UI from scratch.
2. Traiter l’étape 1 comme un **gap-fill** priorisé, si le produit le valide :
   - (A) Compteur hammering **login-only** distinct (réutiliser `is_login_path`).
   - (B) Règle optionnelle « successful logins » (ban username), absente aujourd’hui.
   - (C) Enforcement des bans **username** sur les routes authentifiées (après résolution identité), pas seulement au POST login.
   - (D) Persistance / partage des compteurs si multi-workers (SQLite table ou Redis) — aujourd’hui mémoire process.
   - (E) UX : Edit ban / import liste d’IP (nice-to-have).
   - (F) Documenter clairement : **SSO Keycloak hors compteurs d’échecs** ; protection SSO = Keycloak + nginx `limit_req`.
3. Accroches à conserver :
   - IP → `client_ip_from_request`
   - Audit → `log_action`
   - Gate BG LAN → `is_breakglass_ip_allowed`
   - Middleware pour `/admin` + login paths
4. Si l’audit produit suffit et qu’aucun gap n’est priorisé : **clôturer le pod** comme déjà livré (réf. migration `033` + `tests/test_security_banning.py`).

---

## 9. Carte des fichiers clés

```text
app/models.py                          SecurityPolicy, SecurityBanRule, SecurityBan, SecurityAllowlistEntry
migrations/versions/033_security_banning.py
app/security/banning/engine.py         compteurs, evaluate_login_attempt, apply_ban, check_request_allowed
app/security/banning/middleware.py     SecurityBanMiddleware
app/security/banning/service.py        CRUD UI
app/main.py                            add_middleware(SecurityBanMiddleware)
app/web/pages.py                       POST /auth/login + routes /admin/security/banning/*
app/breakglass.py                      POST /api/admin/breakglass/login
app/templates/admin/security.html      onglet #banning
app/request_client_ip.py               IP trusted-proxy
app/audit.py                           log_action
tests/test_security_banning.py
nginx … limit_req                      rate-limit edge (complément)
```

---

*Audit lecture seule — 2026-07-30.*

---

## Addendum — Étape 1 bis (2026-07-30)

Écarts A–E comblés sans réécriture du module :

| Écart | Livraison |
|---|---|
| A | `GET /auth/sso-failed` + `?error=` sur `/auth/login` → `evaluate_login_attempt(success=False)` ; hammering login sur `/auth/sso-start` |
| B | Règle `successful_login` — ban **username** ; hooks break-glass + nouvel ancre SSO (`SsoSessionAnchor`) |
| C | Règle `hammering_login` branchée via `is_login_path` |
| D | Middleware lit `X-Email` / `X-User` / `X-Preferred-Username` et applique `find_active_ban(..., username=)` |
| E | Compteurs partagés table `security_rate_events` (migration `044`) — pas de Redis dans la stack |

Tests : `tests/test_security_banning.py` (marqueurs `security_sso_failed_login`, `security_successful_login_hammering`, `security_login_only_counter`, `security_admin_username_ban`, `security_shared_counters`).
