# Playwright e2e — Phase 5

## Prérequis

```bash
npm install
npx playwright install --with-deps chromium
```

Démarrer le portail localement (ou pointer vers le staging) :

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Lancer

```bash
# Sans environnement : les specs se skipent proprement (pas de faux échecs)
npx playwright test

# Avec portail + break-glass
set E2E_BASE_URL=http://127.0.0.1:8000
set E2E_BG_USER=admin
set E2E_BG_PASSWORD=...
npx playwright test
```

## Limitations (IdP / CrushFTP)

| Spec | Dépendance externe | Stratégie actuelle |
|------|--------------------|-------------------|
| `login.spec.ts` | Compte break-glass | Exécutable en local avec `E2E_BG_*` |
| `catalogue.spec.ts` | Idem | Local / staging |
| `admin-health-probe.spec.ts` | Idem | Local / staging |
| `admin-logs.spec.ts` | Idem | Local / staging |
| `admin-oidc-test.spec.ts` | Keycloak réel | **Skip** sans `E2E_OIDC_REALM_URL` — pas de mock navigateur MSW dans cette itération |
| `subdomain-redirect.spec.ts` | transfer.* + CrushFTP | **Skip** sans `E2E_STAGING_TRANSFER_URL` |

La CI (GitHub Actions) est hors scope Phase 5 — reportée Phase 6.

Les tests unitaires/API (`pytest -k oidc`, `pytest -k probe`) couvrent déjà OIDC/CrushFTP via **respx** sans dépendre d'un IdP réel.
