# bastion-app

Portail SSO et bastion applicatif AR-Systems (ex-DMZ). Ce dépôt regroupe l'application FastAPI, les templates Nginx et le rôle Ansible de déploiement.

Architecture détaillée : [docs/bastion-architecture.md](docs/bastion-architecture.md)

## Setup local

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # puis renseigner les secrets
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Vérification : `GET http://127.0.0.1:8000/api/health` → `{"status":"ok"}`

## Plan de projet (6 phases)

| Phase | Objectif | Statut |
|-------|----------|--------|
| **1 — Setup** | Structure du repo (FastAPI / Nginx / Ansible) | **Terminée** |
| **2 — Core Auth** | Auth portail, oauth2-proxy, break-glass, RBAC | **Prochaine** |
| 3 — Routage Nginx | Vhosts, proxy legacy `/proxy/{slug}/`, subdomain SSO | À venir |
| 4 — Intégrations spécifiques | Drivers (CrushFTP, Wiki.js, Grafana), robotic SSO | À venir |
| 5 — Observabilité & Tests | Audit, health probes, tests unitaires et e2e Playwright | À venir |
| 6 — Déploiement | Preflight/smoke Ansible, pipeline AWX | À venir |

Contexte Cursor : voir [CURSOR_CONTEXT.md](CURSOR_CONTEXT.md).

## Structure

```
app/          # Application FastAPI
nginx/        # Templates Nginx (vhosts + snippets)
ansible/      # Playbook et rôle sso_portal
docs/         # Architecture, SDD, troubleshooting
tests/        # Unit et e2e
```
