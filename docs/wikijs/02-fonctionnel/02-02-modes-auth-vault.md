# 02.02 — Modes d’authentification & vault

## Définition

Le **mode d’authentification applicative** (`auth_mode`) décrit comment l’utilisateur
est authentifié **auprès de l’application**, une fois le bastion franchi.

| Mode | Rôle |
|------|------|
| `sso` | Porte bastion (session + grant) ; voir **mode SSO applicatif** |
| `generic_form` | Vault : POST formulaire de login robotic |
| `generic_basic_auth` | Vault : Basic Auth injecté par nginx |
| `generic_wsse` | Vault : en-tête X-WSSE |
| Drivers spécifiques | ex. CrushFTP (`robotic_driver=crushftp`) |

## Mode SSO — sous-choix `sso_bridge`

Lorsque `auth_mode=sso`, Admin → Apps propose un **mode SSO applicatif**
(`sso_bridge`) — sans nommer les produits dans le sélecteur :

| Valeur | Libellé UI | Comportement |
|--------|------------|--------------|
| `trusted_headers` | Injection d’identité (en-têtes de confiance) | Nginx injecte `X-Forwarded-Email` / `X-Auth-*` ; l’app doit les consommer |
| `app_oidc` | OIDC délégué à l’application | L’app ignore les en-têtes bruts ; elle crée sa session via sa stratégie OpenID / OAuth (même IdP). **URL d’entrée portail obligatoire** |

### Injection d’identité (`trusted_headers`)

Configurer côté app la confiance en ces en-têtes et **désactiver** un OAuth
intégré concurrent. L’URL d’entrée portail reste optionnelle (défaut = racine du FQDN).

### OIDC délégué (`app_oidc`)

1. Stratégie OpenID / OAuth dans l’application (même realm que le portail).
2. Bypass Login / équivalent + masquage du login local si disponible.
3. Champ **URL d’entrée portail** = chemin qui déclenche le SSO (souvent `…/login`).

Le bastion reste la **porte réseau** (session + AccessGrant) ; l’application crée
**sa** session via l’IdP.

## Vault

Secrets applicatifs chiffrés (Fernet) dans la base :

- credential **partagé** (compte de service),
- **individuel** (par utilisateur Keycloak),
- **identité utilisateur** (login dérivé email / username).

Jamais stockés en clair dans les exports git.

Suite : [02.03 Realms OIDC](./02-03-realms-oidc.md)
