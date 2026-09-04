# Anonymisation — périmètre distribution

## Objectif

Le dossier `deploy/` + les images Hub `vincenttisseront/bastion-pro:*` sont
la surface destinée à un déploiement **externe**. Le reste du dépôt
(ansible, docs/wikijs, rapports d’audit, tests, scripts offensifs) reste
interne / développement.

## Déjà neutralisé (code / défauts runtime)

| Zone | Avant (interne) | Après |
|------|-----------------|-------|
| Défauts `PORTAL_DOMAIN` | `portal.ar-systems.fr` | `portal.example.com` |
| Défauts realm core | `ar-systems` | `default` |
| Snippet nginx oauth2 core | slug hardcodé | `envsubst` `${SSO_PORTAL_DEFAULT_REALM_SLUG}` |
| Exemple oauth2-proxy | IdP / cookies AR-Systems | `idp.example.com` / `.example.com` |
| `.env*.example` | références zone AR-Systems | génériques |
| Placeholders UI | `@ar-systems.fr`, `/crush_data/AR-SYSTEMS` | `@example.com`, `/crush_data/COMPANY` |
| IP infra hardcodée | `172.24.0.108/32` | retirée (vpcbr / docker bridge uniquement) |

## À ne jamais livrer dans un tarball externe

- `ansible/` (inventaires, IPs `172.24.0.x`, hosts `vmdmz-*`)
- `docs/wikijs/`, `docs/auth-audit.md`, docs ops Wazuh internes
- `rapport-audit-*.md/json`
- `tmp/`, `nginx/reference-from-awx/`
- `apply-infra.*`, `CURSOR_CONTEXT.md`
- `.secrets/`, `data/`, `exports/` runtime, `.env` réel

## Rebuild images après anonymisation

Les images Hub déjà poussées peuvent encore contenir d’anciens défauts.
Rebuild + retag + push (`app` / `migrate` / `nginx`) avant distribution externe.
