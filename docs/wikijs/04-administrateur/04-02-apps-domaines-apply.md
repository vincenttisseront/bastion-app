# 04.02 — Applications, domaines & Apply infra

## Créer / éditer une application

Champs critiques :

- `slug`, label, `access_mode`, `upstream_url`, `public_fqdn` (si requis)
- `realm_slug`, `auth_mode`, et si SSO : **mode SSO applicatif** (`sso_bridge`)
  — injection d’identité **ou** OIDC délégué à l’application
- **URL d’entrée portail** (`login_form_url`) — obligatoire si OIDC délégué
- Options TLS upstream, ActiveSync, logo, description

Après enregistrement d’une app SSO/sous-domaine, l’admin est redirigé vers une
**page d’attente apply hôte** qui poll jusqu’à `ok` / `error` (ou timeout 180s)
avant de rendre la main sur la liste apps. Même comportement pour le bouton
**Appliquer l’infrastructure**.

Après enregistrement : **Apply infrastructure** pour régénérer nginx (si besoin hors flux auto).

## Domaines inconnus

Un Host non déclaré frappant nginx est journalisé / mis en file
**Admin → Domaines**. Traiter (créer l’app, ignorer, etc.).

## Apply infrastructure

Actions :

- exporter configs oauth2-proxy par realm
- exporter vhosts / includes nginx apps
- synchroniser vers les volumes Docker
- recharger nginx (test config préalable)

CLI : `python -m app.admin.infrastructure apply`  
Script : `scripts/apply-infra-docker.sh`

## Checklist après modification app SSO en OIDC délégué

1. Grant `launch` pour le groupe utilisateurs
2. `sso_bridge=app_oidc` + `login_form_url` = chemin d’entrée SSO (souvent `…/login`)
3. Côté application : Bypass Login / équivalent + IdP même realm que le portail
4. Apply infra + hard-refresh tuile portail
Suite : [04.03 Sessions & logs](./04-03-sessions-logs.md)
