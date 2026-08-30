# Manifeste — toute la documentation Markdown

**Format unique : Markdown (`.md`).** Aucune page Wiki.js du produit n’est en HTML,
AsciiDoc ou PDF source.

## A. Pages Wiki.js produit (`docs/wikijs/`)

### Racine

| Fichier | Titre |
|---------|-------|
| `00-accueil.md` | Accueil Bastion |
| `99-glossaire.md` | Glossaire |
| `README.md` | Sommaire publication |
| `MAINTENANCE.md` | Règles de tenue à jour |
| `MANIFEST.md` | Ce fichier |

### 01 — Utilisateur

| Fichier | Titre |
|---------|-------|
| `01-utilisateur/00-accueil.md` | Accueil utilisateurs externes |
| `01-utilisateur/01-01-connexion.md` | Connexion |
| `01-utilisateur/01-02-mes-applications.md` | Mes applications |
| `01-utilisateur/01-03-lancer-une-application.md` | Lancer une application |
| `01-utilisateur/01-04-fichiers.md` | Fichiers |

### 02 — Fonctionnel

| Fichier | Titre |
|---------|-------|
| `02-fonctionnel/02-01-modes-acces.md` | Modes d’accès |
| `02-fonctionnel/02-02-modes-auth-vault.md` | Modes d’auth & vault |
| `02-fonctionnel/02-03-realms-oidc.md` | Realms OIDC |
| `02-fonctionnel/02-04-rbac-grants.md` | RBAC & grants |
| `02-fonctionnel/02-05-comptes-provisioning.md` | Comptes & provisioning |
| `02-fonctionnel/02-06-break-glass.md` | Break-glass |

### 03 — Architecture

| Fichier | Titre |
|---------|-------|
| `03-architecture/03-01-vue-ensemble.md` | Vue d’ensemble |
| `03-architecture/03-02-chaine-auth.md` | Chaîne d’authentification |
| `03-architecture/03-03-routage-nginx.md` | Routage nginx |
| `03-architecture/03-04-donnees-vault-hotstore.md` | Données & vault |

### 04 — Administrateur

| Fichier | Titre |
|---------|-------|
| `04-administrateur/04-01-parcours-admin.md` | Parcours admin |
| `04-administrateur/04-02-apps-domaines-apply.md` | Apps, domaines, Apply |
| `04-administrateur/04-03-sessions-logs.md` | Sessions & logs |
| `04-administrateur/04-04-acme-certificats.md` | ACME |
| `04-administrateur/04-05-waf-modsecurity.md` | WAF |
| `04-administrateur/04-06-siem-niveaux-criticite.md` | SIEM — niveaux CEF / criticité |

### 05 — Configuration

| Fichier | Titre |
|---------|-------|
| `05-configuration/05-01-environnement-secrets.md` | Environnement & secrets |
| `05-configuration/05-02-realms-oidc-source-verite.md` | Realms source de vérité |
| `05-configuration/05-03-deploiement-docker.md` | Déploiement Docker |
| `05-configuration/05-04-ip-client-troubleshooting.md` | IP client & dépannage |

### 06 — Annexes techniques

| Fichier | Titre |
|---------|-------|
| `06-annexes/00-index.md` | Index annexes |
| `06-annexes/06-01-…` → `06-14-…` | SDD, ops, ACME, WAF, logs, migrations, RBAC IA, CrushFTP, fichiers… |

## B. Markdown techniques hors copie wiki (`docs/`)

Toujours en Markdown dans le dépôt (import Wiki.js optionnel) :

- `bastion-architecture.md`, `bastion-pro-visual-config.md`
- `awx-playbook-dmz-coordination.md`
- `gestion-fichiers-complements-chiffrement-semver-volume.md`
- `audit-*.md`, `fix-ux-*.md`, `phase4-rbac-ui-v2-delivery.md`
- `rbac-enforcement-audit.md`, `auth-audit.md`
- `audit-preintegration-modsecurity-crs-nginx-bastion.md`

## Publication Wiki.js

1. Créer l’arbre selon [`README.md`](./README.md).
2. Pour chaque fichier `.md` des sections 00–06 : coller le Markdown brut (éditeur Markdown Wiki.js).
3. Ne pas convertir en HTML WYSIWYG si vous voulez rester synchronisé avec le dépôt.
