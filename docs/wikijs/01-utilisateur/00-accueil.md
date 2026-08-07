# 01.00 — Accueil utilisateurs externes

Bienvenue sur le **portail Bastion**. Cette page s’adresse aux **utilisateurs externes**
(partenaires, clients, prestataires) qui accèdent aux applications mises à disposition
par l’organisation hôte via une connexion sécurisée (SSO).

## Ce que vous pouvez faire

| Action | Description |
|--------|-------------|
| Vous connecter | Identifiant unique (SSO) fourni ou validé par l’organisation |
| Voir vos applications | Catalogue **Mes applications** — uniquement ce qui vous est autorisé |
| Ouvrir une application | Clic sur une tuile → ouverture dans le navigateur |
| Télécharger des fichiers | Si un espace fichiers vous a été ouvert |
| Vous déconnecter | Menu utilisateur → Déconnexion |

Vous ne voyez **que** les applications et fichiers pour lesquels un droit vous a été
accordé (directement ou via un groupe).

## Ce que vous ne faites pas

- Pas d’accès à l’**administration** du portail
- Pas de connexion « locale / secours » (réservée aux admins internes)
- Pas de demande de droits en libre-service avancée (sauf si un formulaire
  d’accès vous a été indiqué par votre contact)

Pour un nouveau droit ou une app manquante : contactez votre **référent** chez
l’organisation hôte (commercial, chef de projet, support).

## Premiers pas

1. Ouvrir l’URL du portail communiquée (ex. `https://portal.example.com`).
2. Choisir **Se connecter via SSO / Identifiant Unique**.
3. S’authentifier (mot de passe, e-mail de bienvenue, MFA si demandé).
4. Atterrir sur **Mes applications** et ouvrir la tuile concernée.

Détails : [01.01 Connexion](./01-01-connexion.md) · [01.02 Mes applications](./01-02-mes-applications.md)

## Ouvrir une application — à savoir

- Certaines apps s’ouvrent **déjà connecté** (SSO transparent).
- D’autres affichent encore un bouton de connexion de l’application : un clic
  suffit en général (même identité, sans re-saisir le mot de passe si la session
  est active). Voir [01.03 Lancer une application](./01-03-lancer-une-application.md).

## Sécurité & bonnes pratiques

- Ne partagez pas votre session (poste partagé : toujours **Déconnexion**).
- N’envoyez jamais votre mot de passe par e-mail / chat.
- En cas d’ordinateur public : navigation privée + déconnexion en partant.
- Signalez immédiatement un accès suspect à votre référent.

## Aide rapide

| Problème | Que faire |
|----------|-----------|
| Mot de passe oublié | Utiliser « mot de passe oublié » sur l’écran IdP, ou votre référent |
| Aucune application | Droit pas encore accordé — contacter le référent |
| Accès refusé après ouverture | Droit insuffisant ou session expirée — se reconnecter / référent |
| Page inaccessible | Vérifier VPN / lien exact / horaires d’ouverture éventuels |

## Suite de la doc utilisateur

| Page | Contenu |
|------|---------|
| [01.01 Connexion](./01-01-connexion.md) | SSO, déconnexion, incidents fréquents |
| [01.02 Mes applications](./01-02-mes-applications.md) | Catalogue, favoris |
| [01.03 Lancer une application](./01-03-lancer-une-application.md) | Comportement au clic |
| [01.04 Fichiers](./01-04-fichiers.md) | Téléchargements autorisés |

La documentation **administrateur / architecture / configuration** s’adresse aux
équipes internes — elle n’est pas nécessaire pour un usage quotidien externe.
