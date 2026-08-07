# 04.03 — Sessions & journaux

## Sessions (`/sessions`)

Registre des sessions **portail** et **application** (présence via auth_request /
launch-ping). Permet :

- voir IP, User-Agent, dernière activité ;
- révoquer une session ;
- ouvrir les logs associés.

### Liens logs depuis une session app

- **Access log app** → onglet Accès apps (`{slug}.access.log`) — trafic HTTP réel
- **Audit acteur** → Audit filtré sur l’email (les ids `app:email:slug` ne sont
  **pas** stockés dans AuditLog)

## Audit (`/admin/logs` → Audit)

Événements métier : login, `app_launch`, `access_denied_no_grant`, admin, etc.
Intégrité chaînée affichée en bannière.

Filtres : acteur, IP, action, détail, recherche tokenisée, niveaux success/error/info.

## Accès apps

Parse le `log_format app` nginx : timings (`rt`/`uct`/`uht`/`ut`), upstream,
taille requête, XFF / `X-Portal-Client-IP`, proto, `X-Request-Id`, identité
(`auth_email`/`auth_user`/`auth_app`/`auth_src`/`auth_pref`), `auth_err`.
Masque par défaut les hops internes `127.0.0.1:8080`.
Après changement du format : `apply` infra + recreate nginx pour les nouvelles lignes.

## Conteneurs

Si activé : proxy vers docker-socket-proxy, whitelist de noms de conteneurs.
Voir `docs/admin-logs-live-and-containers.md`.

Suite : [04.04 ACME](./04-04-acme-certificats.md)
