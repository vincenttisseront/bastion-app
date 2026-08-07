# 01.02 — Mes applications

## Objectif

Consulter et ouvrir les applications auxquelles vous avez droit.

## Page `/apps`

Après connexion SSO, **Mes applications** affiche les tuiles autorisées par vos
**AccessGrant** (directs ou via groupes).

- **Accès rapides** : applications épinglées en favoris.
- **Applications** : catalogue effectif (niveau `view` ou `launch` selon le droit).

Les administrateurs break-glass sont redirigés vers le **tableau de bord** admin
plutôt que `/apps`.

## Favoris

Épingler / désépingler depuis la tuile (selon droits UI). Les favoris sont liés
à votre identité Keycloak.

## Ce qui n’apparaît pas

- Applications **désactivées**
- Mode **proxy public** (`public_proxy`) — hors catalogue utilisateur
- Applications sans grant pour votre compte / groupes

## Sessions

La page **Sessions** (si accessible) montre vos sessions portail et applications
actives. Un admin peut voir l’ensemble des sessions.

Suite : [01.03 Lancer une application](./01-03-lancer-une-application.md)
