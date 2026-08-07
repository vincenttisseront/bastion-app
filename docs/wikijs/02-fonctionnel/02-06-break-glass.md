# 02.06 — Break-glass (secours admin)

## Objectif

Garantir un accès administrateur au portail (et aux apps sous-domaine) lorsque
l’IdP est indisponible ou la session SSO cassée.

## Caractéristiques

- Comptes locaux (username / password) gérés hors Keycloak
- Cookie JWT `bg_session`, HttpOnly / Secure / SameSite=Lax
- Domaine parent partagé (comme `bastion_session`) pour atteindre les FQDN apps
- Contrôle d’accès par **CIDR** (allowlist LAN typique)
- Sessions révocables (`jti`), audit des login / logout
- Sur subdomain-auth : **bypass des AccessGrant** (admin de secours)

## Parcours utilisateur

1. IP autorisée → formulaire « Connexion locale » sur `/auth/login`
2. Succès → cookie `bg_session` → dashboard admin
3. Ouverture d’une app sous-domaine : auth_request accepte le break-glass

## Sécurité

- Ne jamais exposer break-glass sur Internet sans allowlist stricte
- Mot de passe fort, rotation, révocation des sessions après incident
- Distinct du rôle `portal_admin` OIDC (complémentaire)

## Références dépôt

Politiques cookies / anti-replay : docs `audit-rotation-anti-replay-cookies.md`,
`audit-validation-stricte-cookies.md`.

Suite : [03.01 Architecture](../03-architecture/03-01-vue-ensemble.md)
