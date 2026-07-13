# CURSOR_CONTEXT — bastion-app

Document de référence pour les sessions Cursor. **Tenir à jour** à chaque changement de phase.

## Phase en cours : UI Bastion Pro (Sentinel Core)

**Phases 1–3 terminées** (structure, auth API, vhosts Nginx). **Phase UI en cours** : templates Jinja2, assets CSS/JS, routes HTML.

## Plan de projet (6 phases)

### Phase 1 — Setup
- Initialisation repo Git, arborescence FastAPI / Nginx / Ansible
- Placeholders Python, templates Nginx restaurés depuis `awx-playbook@ff4f66b`
- Documentation de référence copiée dans `docs/`

### Phase 2 — Core Auth
- Auth portail (`auth.py`), multi-realm Keycloak (`realm_service.py`)
- Break-glass (`breakglass.py`, `breakglass_store.py`)
- Modèles catalogue / RBAC (`models.py`, `services.py`)
- Route `/internal/oauth2-auth`

### Phase 3 — Routage Nginx
- Vhosts portail et subdomain
- Proxy transparent legacy `/proxy/{slug}/`
- Mode subdomain SSO (cohabitation avec proxy legacy)
- Snippets auth_request, redirects

### Phase 4 — Intégrations spécifiques
- Drivers bastion (CrushFTP, Wiki.js, Grafana, generic)
- Robotic SSO / impersonation
- Vault applicatif (Fernet)

### Phase 5 — Observabilité & Tests
- Audit admin, health probes upstream
- Tests unitaires pytest, e2e Playwright

### Phase 6 — Déploiement
- Preflight et smoke_test Ansible fonctionnels
- Pipeline AWX, secrets Vault

### Phase UI — Bastion Pro (Sentinel Core)
- `app/static/` : CSS tokens, composants, JS theme/sessions/audit
- `app/templates/` : layout sidebar+topbar, dashboard, sessions, audit, catalogue, admin
- `app/web/` : user context (headers Nginx), pages HTML, metrics/sessions/audit services
- Nginx : favicon `bastion-icon.svg`, erreurs via templates FastAPI

## Décisions arbitrées (Phase 1)

| Sujet | Décision |
|-------|----------|
| Nom du repo | `bastion-app` |
| Dépendances Python | `pyproject.toml` uniquement (pas de `requirements.txt`) |
| `ansible/roles/sso_portal/files/portal/` | Copie buildée de `app/` (+ `static/`, `templates/`) au déploiement ; `.gitkeep` en dev |
| Architecture routage | Cohabitation proxy legacy **et** subdomain SSO |
| `subdomain_auth_common.conf.j2` | Fusion de `subdomain_auth_check` + `subdomain_auth_protect` (historique ff4f66b) |

## Mapping écarts de nommage Nginx

| Nom historique (awx-playbook) | Nom cible (bastion-app) |
|-------------------------------|-------------------------|
| `nginx-portal.conf.j2` | `nginx/vhosts/vhost_sso_portal.conf.j2` |
| `subdomain_auth_check.conf.j2` + `subdomain_auth_protect.conf.j2` | `nginx/snippets/subdomain_auth_common.conf.j2` (fusionné) |

Les tâches Ansible référencent les chemins sous `nginx/` (pas de duplication dans `ansible/roles/sso_portal/templates/`).

## Points ouverts (avant Phase 2)

- Créer le remote Git pour `bastion-app`
- Valider la liste complète des secrets Vault AWX (`.env.example` contient les variables minimales)
- Lors de la Phase 3 : vérifier que les vhosts subdomain incluent `subdomain_auth_common.conf` et non les anciens snippets `check`/`protect`

## Source de restauration

Code et templates historiques : `C:\Users\vincent.tisseront\awx-playbook` (commit `ff4f66b` pour templates bastion Nginx).
