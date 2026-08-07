# 06.00 — Annexes techniques (Markdown)

Toutes les annexes de cette section sont des fichiers **Markdown** prêts à coller
dans Wiki.js. Elles reprennent les docs techniques du dépôt (`docs/*.md`, `docs/sdd/`).

| Page | Sujet | Source dépôt |
|------|-------|--------------|
| [06.01](./06-01-sdd-001-authentification-sso.md) | SDD-001 Authentification SSO | `docs/sdd/SDD-001-…` |
| [06.02](./06-02-sdd-002-nginx-vhost-portail.md) | SDD-002 Vhost nginx portail | `docs/sdd/SDD-002-…` |
| [06.03](./06-03-bff-oidc-native-session.md) | Session OIDC native (BFF) | `docs/bff-oidc-native-session.md` |
| [06.04](./06-04-ops-client-ip-chain.md) | Chaîne IP client | `docs/ops-client-ip-chain.md` |
| [06.05](./06-05-lets-encrypt-acme.md) | ACME / Let’s Encrypt | `docs/lets-encrypt-acme-nginx-bastion.md` |
| [06.06](./06-06-ops-modsecurity-crs.md) | Ops ModSecurity CRS | `docs/ops-modsecurity-crs.md` |
| [06.07](./06-07-troubleshooting-nginx.md) | Dépannage nginx | `docs/troubleshooting-nginx.md` |
| [06.08](./06-08-admin-logs.md) | Logs admin & containers | `docs/admin-logs-live-and-containers.md` |
| [06.09](./06-09-oauth2-cookie-secret-policy.md) | Politique cookie_secret | `docs/oauth2-cookie-secret-policy.md` |
| [06.10](./06-10-migrations.md) | Migrations Alembic | `docs/migrations.md` |
| [06.11](./06-11-rbac-information-architecture.md) | IA RBAC admin | `docs/rbac-information-architecture.md` |
| [06.12](./06-12-keycloak-crushftp-setup.md) | Keycloak + CrushFTP | `docs/KEYCLOAK_CRUSHFTP_SETUP.md` |
| [06.13](./06-13-conception-modsecurity.md) | Conception ModSecurity | `docs/conception-modsecurity-crs-…` |
| [06.14](./06-14-gestion-fichiers-versionnes.md) | Fichiers versionnés | `docs/gestion-fichiers-versionnes-bastion.md` |

## Autres Markdown du dépôt (non dupliqués ici)

Audits / fixes UX internes — toujours en `.md` sous `docs/` :

- `audit-*.md`, `fix-ux-*.md`, `phase4-rbac-ui-v2-delivery.md`
- `bastion-architecture.md` (long ; préférer section **03** du wiki produit)
- `bastion-pro-visual-config.md`, `awx-playbook-dmz-coordination.md`
- `gestion-fichiers-complements-chiffrement-semver-volume.md`
- `audit-preintegration-modsecurity-crs-nginx-bastion.md`

Inventaire complet : [MANIFEST.md](../MANIFEST.md)

## Synchronisation

Quand vous modifiez une source sous `docs/*.md`, mettez à jour la copie
`06-annexes/06-xx-*.md` (ou régénérez-la) dans la même PR. Voir [MAINTENANCE.md](../MAINTENANCE.md).
