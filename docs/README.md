# Documentation (`docs/`)

## Format

**Toute** la documentation produit et les annexes publiables sont en **Markdown**
(`.md`). Voir [`wikijs/MANIFEST.md`](./wikijs/MANIFEST.md).

## Wiki produit (Wiki.js)

La documentation structurée pour publication dans Wiki.js vit dans
**[`wikijs/`](./wikijs/README.md)** :

- Doc utilisateur, fonctionnelle, architecture, administrateur, configuration
- Glossaire + guide de **[maintenance](./wikijs/MAINTENANCE.md)**

## Docs techniques du dépôt

| Fichier / dossier | Sujet |
|-------------------|--------|
| [`bastion-architecture.md`](./bastion-architecture.md) | Architecture longue (historique) |
| [`sdd/`](./sdd/) | Décisions figées auth / nginx |
| [`lets-encrypt-acme-nginx-bastion.md`](./lets-encrypt-acme-nginx-bastion.md) | ACME |
| [`ops-modsecurity-crs.md`](./ops-modsecurity-crs.md) | WAF ops |
| [`ops-client-ip-chain.md`](./ops-client-ip-chain.md) | IP client |
| [`troubleshooting-nginx.md`](./troubleshooting-nginx.md) | Dépannage nginx |
| [`admin-logs-live-and-containers.md`](./admin-logs-live-and-containers.md) | Logs admin |
| [`bff-oidc-native-session.md`](./bff-oidc-native-session.md) | Session OIDC native |
| [`migrations.md`](./migrations.md) | Alembic |
| [`activesync-devices-inventaire-approbation-user.md`](./activesync-devices-inventaire-approbation-user.md) | ActiveSync : inventaire, gate, portail, Lot 3 clone |
| [`activesync-bascule-grommunio-checklist.md`](./activesync-bascule-grommunio-checklist.md) | Checklist ops bascule Grommunio (§16) |
| `audit-*.md`, `fix-ux-*.md` | Audits / suivi interne (non wiki produit) |

En cas de conflit, les pages **`wikijs/`** + SDD prévalent pour le narratif produit ;
les audits restent des annexes d’ingénierie.
