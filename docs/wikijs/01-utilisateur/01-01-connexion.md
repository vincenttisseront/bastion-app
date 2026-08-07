# 01.01 — Connexion au portail

## Objectif

Accéder au portail Bastion avec votre identité (SSO). Les administrateurs sur le
réseau de confiance disposent en plus d’une connexion locale de secours.

**Utilisateurs externes :** commencez par
[01.00 Accueil utilisateurs externes](./00-accueil.md).

## Connexion SSO (cas normal)

1. Ouvrir l’URL du portail (ex. `https://portal.example.com`).
2. Choisir **Se connecter via SSO / Identifiant Unique**.
3. S’authentifier auprès de l’IdP (Keycloak, etc.) — mot de passe, MFA si configuré.
4. Retour automatique vers le portail (`/apps` ou l’URL demandée).

La session repose sur les cookies SSO du domaine parent (et éventuellement
`bastion_session` si le mode BFF natif est activé).

## Connexion locale (break-glass)

Réservée aux **administrateurs de secours** :

- visible seulement si votre adresse IP est dans la plage autorisée (LAN / allowlist) ;
- indépendante de Keycloak (utile si l’IdP est indisponible) ;
- crée un cookie `bg_session` (domaine parent partagé avec les apps sous-domaine).

En cas d’échec : vérifier VPN / IP, ou contacter un admin portail.

## Déconnexion

Utiliser **Déconnexion** dans le menu utilisateur. Cela révoque la session portail
et efface les cookies SSO / break-glass côté navigateur.

## Problèmes fréquents

| Symptôme | Piste |
|----------|--------|
| Boucle de login | Cookies tiers bloqués, mauvais `PORTAL_DOMAIN`, session IdP expirée |
| Pas de formulaire « Connexion locale » | IP hors allowlist break-glass |
| Accès admin refusé (403) | Compte sans rôle `portal_admin` / groupes admin |

Suite : [01.02 Mes applications](./01-02-mes-applications.md)
