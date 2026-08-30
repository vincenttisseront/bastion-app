# Documentation Bastion — pages Wiki.js

Ce dossier est la **source de vérité rédactionnelle** pour le wiki produit (Wiki.js).
Chaque fichier Markdown correspond à **une page** à publier sous le chemin indiqué.

| Attribut | Valeur |
|----------|--------|
| Produit | Bastion applicatif (UI : Bastion Pro) |
| Version documentée | **0.5.0** (`APP_VERSION`) |
| Dépôt | `bastion-app` |
| Langue | Français |
| Maintenance | Voir [MAINTENANCE.md](./MAINTENANCE.md) |

## Arborescence Wiki.js recommandée

```
Bastion /
├── Accueil                              ← 00-accueil.md
├── 01 — Documentation utilisateur
│   ├── 01.00 Accueil utilisateurs externes ← 01-utilisateur/00-accueil.md
│   ├── 01.01 Connexion                  ← 01-utilisateur/01-01-connexion.md
│   ├── 01.02 Mes applications           ← 01-utilisateur/01-02-mes-applications.md
│   ├── 01.03 Lancer une application     ← 01-utilisateur/01-03-lancer-une-application.md
│   └── 01.04 Fichiers                   ← 01-utilisateur/01-04-fichiers.md
├── 02 — Documentation fonctionnelle
│   ├── 02.01 Modes d’accès              ← 02-fonctionnel/02-01-modes-acces.md
│   ├── 02.02 Modes d’auth & vault       ← 02-fonctionnel/02-02-modes-auth-vault.md
│   ├── 02.03 Realms OIDC                ← 02-fonctionnel/02-03-realms-oidc.md
│   ├── 02.04 RBAC & grants              ← 02-fonctionnel/02-04-rbac-grants.md
│   ├── 02.05 Comptes & provisioning     ← 02-fonctionnel/02-05-comptes-provisioning.md
│   └── 02.06 Break-glass                ← 02-fonctionnel/02-06-break-glass.md
├── 03 — Documentation d’architecture
│   ├── 03.01 Vue d’ensemble             ← 03-architecture/03-01-vue-ensemble.md
│   ├── 03.02 Chaîne d’authentification  ← 03-architecture/03-02-chaine-auth.md
│   ├── 03.03 Routage nginx              ← 03-architecture/03-03-routage-nginx.md
│   └── 03.04 Données & vault            ← 03-architecture/03-04-donnees-vault-hotstore.md
├── 04 — Documentation administrateur
│   ├── 04.01 Parcours admin             ← 04-administrateur/04-01-parcours-admin.md
│   ├── 04.02 Apps, domaines, Apply      ← 04-administrateur/04-02-apps-domaines-apply.md
│   ├── 04.03 Sessions & logs            ← 04-administrateur/04-03-sessions-logs.md
│   ├── 04.04 ACME / certificats         ← 04-administrateur/04-04-acme-certificats.md
│   ├── 04.05 WAF ModSecurity            ← 04-administrateur/04-05-waf-modsecurity.md
│   └── 04.06 SIEM — niveaux criticité   ← 04-administrateur/04-06-siem-niveaux-criticite.md
├── 05 — Documentation de configuration
│   ├── 05.01 Environnement & secrets    ← 05-configuration/05-01-environnement-secrets.md
│   ├── 05.02 Realms (source de vérité)  ← 05-configuration/05-02-realms-oidc-source-verite.md
│   ├── 05.03 Déploiement Docker         ← 05-configuration/05-03-deploiement-docker.md
│   └── 05.04 IP client & dépannage      ← 05-configuration/05-04-ip-client-troubleshooting.md
├── 06 — Annexes techniques (Markdown)
│   ├── 06.00 Index annexes              ← 06-annexes/00-index.md
│   ├── 06.01–06.14                      ← SDD, BFF, IP, ACME, WAF, nginx, logs, …
└── Glossaire                            ← 99-glossaire.md
```

**Tout est en Markdown (`.md`).** Inventaire : [`MANIFEST.md`](./MANIFEST.md).

## Publication Confluence (espace DL)

```bash
python scripts/publish_confluence_docs.py
python scripts/publish_confluence_docs.py --attachments-only
```

Cartographie pages : [`confluence-page-map.json`](./confluence-page-map.json).
Configs externes jointes aux pages (Wazuh, nginx templates, ModSecurity, oauth2,
ACME…) : [`confluence-attachments.json`](./confluence-attachments.json).

## Publication dans Wiki.js

1. Créer les dossiers / pages selon l’arborescence ci-dessus (chemins stables).
2. Coller le contenu **Markdown** de chaque fichier (mode Markdown Wiki.js, pas HTML).
3. Conserver les liens relatifs entre pages.
4. Après chaque release produit significative : suivre [MAINTENANCE.md](./MAINTENANCE.md).

## Liens vers docs techniques du dépôt

Les pages wiki **résument** le produit. Les détails ops / SDD restent dans :

| Sujet | Fichier dépôt |
|-------|----------------|
| Architecture historique | [`../bastion-architecture.md`](../bastion-architecture.md) |
| SDD auth | [`../sdd/SDD-001-authentification-sso.md`](../sdd/SDD-001-authentification-sso.md) |
| SDD nginx portail | [`../sdd/SDD-002-nginx-vhost-portail.md`](../sdd/SDD-002-nginx-vhost-portail.md) |
| ACME | [`../lets-encrypt-acme-nginx-bastion.md`](../lets-encrypt-acme-nginx-bastion.md) |
| ModSecurity | [`../ops-modsecurity-crs.md`](../ops-modsecurity-crs.md) |
| Chaîne IP | [`../ops-client-ip-chain.md`](../ops-client-ip-chain.md) |
| Logs admin | [`../admin-logs-live-and-containers.md`](../admin-logs-live-and-containers.md) |
| BFF OIDC | [`../bff-oidc-native-session.md`](../bff-oidc-native-session.md) |
| Onboarding code | [`../../README.md`](../../README.md) |
