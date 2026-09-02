# 04.03 — Sessions & journaux

## Sessions (`/sessions`)

Registre des sessions **portail** (utilisateur) et **application** (présence via
auth_request / launch-ping). Filtres :

| Vue | URL |
|-----|-----|
| Toutes | `/sessions` |
| Utilisateurs (portail) | `/sessions?kind=user` |
| Applications | `/sessions?kind=app` |

Onglets en tête de page ; rail latéral « Utilisateurs » pour filtrer le détail des
sessions applicatives par personne.

Actions : voir IP, User-Agent, dernière activité ; révoquer une session ; ouvrir les
logs associés.

### Dashboard

La tuile **Sessions actives** du dashboard (`/dashboard`) affiche le total avec
détail **utilisateurs · applicatives** et liens directs vers `/sessions?kind=user`
et `/sessions?kind=app`.

### Liens logs depuis une session app

- **Access log app** → onglet Accès apps (`{slug}.access.log`) — trafic HTTP réel
- **Audit acteur** → Audit filtré sur l’email (les ids `app:email:slug` ne sont
  **pas** stockés dans AuditLog)

## Tentatives bloquées (dashboard)

KPI **24 h** : somme des blocages WAF + refus auth/access récents (pas un cumul
historique). Détail sous la tuile : `X WAF · Y auth · Z ban(s)`. Lien vers
`/admin/security/waf` (Bilan).

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

## Catalogue & SIEM

Codes `BST-…` et criticité : **Admin → Logs → Catalogue**.

Niveaux envoyés au SIEM (CEF 1 / 3 / 5 / 7 / 10, domaine WAF, vs `rule.level`
Wazuh) : voir [04.06 SIEM — niveaux de criticité](./04-06-siem-niveaux-criticite.md).

## Conteneurs

Si activé : proxy vers docker-socket-proxy, whitelist de noms de conteneurs.
Voir `docs/admin-logs-live-and-containers.md`.

Suite : [04.04 ACME](./04-04-acme-certificats.md)
