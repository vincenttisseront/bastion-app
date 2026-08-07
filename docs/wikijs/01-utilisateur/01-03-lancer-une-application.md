# 01.03 — Lancer une application

## Objectif

Comprendre ce qui se passe quand vous cliquez une tuile.

## Prérequis

Un AccessGrant de niveau **`launch`** (ou supérieur) sur l’application.
Un grant `view` seul affiche la tuile mais **bloque** l’ouverture sur un sous-domaine
(redirection vers le portail, `access_denied_no_grant`).

## Selon le mode d’accès

| Mode | Comportement au clic |
|------|----------------------|
| **SSO Gate** | Redirection vers l’URL publique de l’app (pas de proxy bastion) |
| **Sous-domaine** | Ouverture de `https://{fqdn}/…` derrière nginx + contrôle SSO |
| **Legacy `/proxy/`** | Ouverture sous `/proxy/{slug}/` |
| **Robotic** (CrushFTP, formulaire…) | Passage éventuel par impersonation / hop de cookies |

## Sous-domaine + SSO bastion

1. Le navigateur appelle le FQDN de l’app.
2. Nginx interroge `/internal/subdomain-auth` (session portail + grant).
3. Si OK : proxy vers l’upstream ; identité éventuellement injectée en en-têtes
   (`X-Forwarded-Email`, etc.).

**Important :** selon le **mode SSO applicatif** choisi en Admin :

- **Injection d’identité** — l’app consomme les en-têtes injectés ; la tuile
  ouvre en général la racine du FQDN.
- **OIDC délégué** — l’app ignore les en-têtes ; la tuile doit ouvrir l’**URL
  d’entrée** (souvent `/login`) et l’app doit être configurée pour un SSO IdP
  silencieux (Bypass Login / équivalent, même realm). Vous arrivez alors
  connectés sans re-saisir le mot de passe si la session IdP est déjà ouverte.
## Credential individuel

Si l’app demande un credential personnel (vault « identité utilisateur »),
compléter le formulaire demandé avant le premier lancement.

Suite : [01.04 Fichiers](./01-04-fichiers.md) · [02.01 Modes d’accès](../02-fonctionnel/02-01-modes-acces.md)
