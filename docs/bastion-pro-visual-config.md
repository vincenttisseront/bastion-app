# Configuration Visuelle — Interface Bastion Pro

Document de référence pour la génération des templates Jinja2 et assets statiques du portail SSO bastion-app.

**Cible :** `app/static/` (CSS, JS) et `app/templates/` (Jinja2)  
**Thème :** Sentinel Core (dark par défaut, light commutable)  
**Dernière mise à jour :** 2026-07-10

## Identité visuelle

| Token | Dark | Light |
|-------|------|-------|
| `--bg-primary` | `#051424` | `#f8f9ff` |
| `--accent-primary` | `#10b981` | `#10b981` |
| `--font-sans` | Inter | Hanken Grotesk |

## Arborescence implémentée

```
app/static/css/     bastion-tokens.css … bastion.css (import master)
app/static/js/      bastion-theme.js, bastion.js, bastion-sessions.js, bastion-audit.js
app/static/img/     bastion-icon.svg, bastion-logo.svg
app/templates/      base.html, partials/, auth/, dashboard/, sessions/, catalogue/, audit/, admin/, errors/
```

## Routes FastAPI

| Route | Template / API |
|-------|------------------|
| `/dashboard` | `dashboard/index.html` |
| `/sessions` | `sessions/index.html` |
| `/catalogue` | `catalogue/index.html` |
| `/audit` | `audit/index.html` (+ export CSV/PDF) |
| `/api/metrics` | JSON KPIs |
| `/api/sessions` | JSON sessions actives |
| `/admin/sessions/{id}/isolate` | POST action sécurité |
| `/auth/login`, `/breakglass` | `auth/login.html` |
| `/errors/{403,404,500}` | Pages d'erreur Jinja2 |

## Contexte Jinja2 global

Injecté via `app/web/flash.py` → `base_template_context()` :

- `current_user`, `is_admin`, `realm_slug`, `app_version`
- `messages` (flash cookie signé), `csrf_token`, `now`, `hide_chrome`

## Nginx

- Favicon : proxy vers `/static/img/bastion-icon.svg`
- Erreurs 404/5xx : proxy vers FastAPI `/errors/404`, `/errors/500`

## Dépendances export audit

- `pandas>=2.2` — export CSV
- `reportlab>=4.2` — export PDF

Pour la spec complète (composants CSS, exemples de templates), voir le document PRD Bastion v1.0 et la tâche `ptd_Td1RnYtovXMtQR2ypA85`.
