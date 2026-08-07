# Accueil — Bastion applicatif

**Bastion** (UI *Bastion Pro*) est le portail SSO et le reverse-proxy sécurisé qui expose
les applications internes derrière une authentification unique (OIDC), un catalogue,
un vault de credentials et une administration centralisée.

| | |
|--|--|
| Version documentée | **0.5.0** |
| Public | Utilisateurs, admins, ops, architectes |
| Dépôt | `bastion-app` |

## À quoi ça sert

| Besoin | Réponse |
|--------|---------|
| Point d’entrée HTTPS unique | FQDN portail + FQDN par application |
| SSO entreprise | OIDC (Keycloak, etc.) — configuration **realm en base** |
| Apps sans OIDC natif | Vault + robotic SSO (formulaire / basic / cookies) |
| Droits | RBAC : groupes, AccessGrant, rôles système |
| Secours admin | Break-glass (indépendant de l’IdP) |
| Certificats | Let’s Encrypt DNS-01 (ACME) sur nginx |

**Principe fondateur :** le *core* portail (`/`, `/apps`, `/admin`, santé, SSO, break-glass)
ne doit pas être cassé par une application métier ou un proxy.

## Parcours de lecture

| Vous êtes… | Commencez par… |
|------------|----------------|
| Utilisateur externe (partenaire / client) | [01.00 Accueil utilisateurs externes](./01-utilisateur/00-accueil.md) |
| Utilisateur interne | [01.01 Connexion](./01-utilisateur/01-01-connexion.md) |
| Product owner / métier | [02.01 Modes d’accès](./02-fonctionnel/02-01-modes-acces.md) |
| Architecte | [03.01 Vue d’ensemble](./03-architecture/03-01-vue-ensemble.md) |
| Administrateur portail | [04.01 Parcours admin](./04-administrateur/04-01-parcours-admin.md) |
| Ops / déploiement | [05.01 Environnement](./05-configuration/05-01-environnement-secrets.md) |

## Glossaire express

- **Realm** — configuration OIDC d’un IdP (issuer, client, secrets) stockée en base.
- **AccessGrant** — droit effectif (user ou groupe) sur une application ou un rôle.
- **Sous-domaine** — app exposée sur `app.example.com` via nginx + `auth_request`.
- **Apply infra** — régénération des exports nginx / oauth2-proxy depuis la base.
- **Break-glass** — connexion locale de secours admin.

→ [Glossaire complet](./99-glossaire.md)

## Maintenance

Cette documentation vit dans le dépôt (`docs/wikijs/`). Voir [MAINTENANCE.md](./MAINTENANCE.md).
