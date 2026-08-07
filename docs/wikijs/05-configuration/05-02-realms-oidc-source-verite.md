# 05.02 — Realms OIDC (source de vérité)

## Règle d’or

> La configuration OIDC du realm portail (issuer, client_id, client_secret,
> cookie_secret, redirect_uri, PKCE) vit dans **`RealmConfig` en base SQLite**.
>
> Ne jamais éditer à la main `docker/oauth2-core/oauth2-proxy.cfg` ni d’autres
> fichiers secrets oauth2 comme source de vérité.

## Flux opérationnel

```
Admin → Realms (saisie)
     → Test OIDC
     → Apply infrastructure (API / CLI / bouton)
     → scripts/apply-infra-docker.sh
     → sync export → oauth2-proxy-*
```

`exports/` et `docker/oauth2-core/` = **miroirs générés**.

## Redirect URI

Doit correspondre exactement à ce que l’IdP autorise, typiquement :

`https://{PORTAL_DOMAIN}/oauth2/{realm_slug}/callback`

## Après changement de secret

1. Mettre à jour en base (UI)
2. Test OIDC
3. Apply + restart/reload proxy si nécessaire
4. Demander aux utilisateurs de se reconnecter

Suite : [05.03 Déploiement](./05-03-deploiement-docker.md)
