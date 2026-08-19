# Runbook — réactivation ModSecurity / OWASP CRS

**Statut** : brouillon lancé 2026-08-18. **Ne pas exécuter** tant que le prérequis §0 n’est pas tranché.
**Ne pas** confondre avec l’IHM WAF (Phase B) : Enregistrer / Appliquer ne réactive **pas** le moteur.

Liens : [`ops-modsecurity-crs.md`](ops-modsecurity-crs.md) · conception §9 · PR IHM honnête [#151](https://github.com/vincenttisseront/bastion-app/pull/151) · lecture live conteneur [#152](https://github.com/vincenttisseront/bastion-app/issues/152).

---

## 0. Prérequis bloquant — `error.log` du 2026-08-06

Cause racine du 500 **non levée**. L’urgence a coupé `modsecurity` + `SecRuleEngine Off` + retiré l’Include `engine-mode-generated`. Rejouer `On` sans diag = rejouer l’incident.

| Fichier | Monté sur l’hôte ? | Conséquence |
|---------|--------------------|-------------|
| `/var/log/nginx/error.log` | **Non** (`error_log` dans `nginx.conf`, hors volume) | **Perdu au recreate** du conteneur |
| `/var/log/nginx/apps/modsec_audit.log` | Oui (`SSO_PORTAL_DATA_DIR/nginx-logs`) | Peut encore être là si le volume n’a pas été rotaté / vidé |
| stdout `docker logs bastion-nginx` | Journal Docker hôte | Peut contenir des lignes `error_log` **seulement** si quelqu’un a redirigé ; par défaut **non** |

**Question ouverte (à trancher avant toute bascule)** :

1. Le conteneur `bastion-nginx` a-t-il été **recréé** depuis le 06/08 soir ?
2. Si non : `docker exec bastion-nginx ls -l /var/log/nginx/error.log` + copie hors conteneur **maintenant**.
3. Si oui : reste-t-il une copie (sauvegarde hôte, ticket, `docker logs` de l’époque, `modsec_audit.log` volume) ?

Sans au moins **une** de ces sources, on ne réactive pas : on n’a que des hypothèses (collision id 901110 déjà écartée après #113 ; autre règle CRS / connecteur / `/tmp/modsecurity`).

Commandes de récupération (lecture seule) :

```bash
docker exec bastion-nginx ls -l /var/log/nginx/error.log /var/log/nginx/apps/modsec_audit.log
docker exec bastion-nginx sh -c 'wc -l /var/log/nginx/error.log; grep -E "2026/08/06|ModSecurity|modsecurity" /var/log/nginx/error.log | tail -n 200'
# Volume hôte (audit, pas error.log global) :
sudo ls -l "${SSO_PORTAL_DATA_DIR:-/tools/portal/data}/nginx-logs/modsec_audit.log"
```

---

## 1. Ce que la réactivation n’est **pas**

- Pas un clic **Appliquer** WAF.
- Pas un changement de `WafProfile.mode` en base.
- Pas un rebranchement à l’aveugle de `crs-setup-generated.conf` (id 901110 → 500).
- Pas les 3 familles en `On` le même soir.

---

## 2. Ordre une fois le diag §0 disponible

Hypothèse de travail (à infirmer/confirmer avec les logs) : le 500 survient **au moment de l’évaluation CRS** (chemins `modsecurity on`), pas sur `/api/health` (`modsecurity off`).

Ordre :

1. **Une famille**, portal d’abord (plus de fumée, rollback le plus simple).
2. `SecRuleEngine DetectionOnly` **avant** `On`.
3. Smoke §3 **avant** la famille suivante.
4. Rebrancher `engine-mode-generated.conf` **seulement** quand `engine-portal.conf` est déjà stable en DetectionOnly/On **et** que le stub sync n’écrase plus Off. Sinon l’IHM `mode=on` force On en dernier — c’est exactement le 06/08.
5. `crs-setup-generated.conf` : **ne pas** Include tant que l’id overlay n’est pas hors plage CRS 9xxxxx (déjà `1000900110` en export ; Include toujours retiré).

Fichiers à toucher **dans l’image / rebuild**, pas via l’IHM :

- `docker/nginx/modsecurity/engine-portal.conf` (puis subdomain, public)
- éventuellement `modsecurity on;` dans les vhosts si encore `off` en dur
- `docker/nginx/sync-exports-to-confd.sh` (stub `SecRuleEngine Off`) — **après** smoke, pas avant
- `docker/nginx/modsecurity/main-*.conf` — Include `engine-mode-generated` en dernier, **après** smoke

---

## 3. Smoke (bloquant)

Après **chaque** bascule d’une famille :

1. `docker exec bastion-nginx nginx -t && docker exec bastion-nginx nginx -s reload`
2. Login SSO → dashboard (`/auth/login` **200**, pas 500)
3. Un flux `subdomain_proxy` (ex. CrushFTP) si cette famille est déjà rebranchée
4. Un flux `public_proxy` idem
5. `POST /admin/apps/analyze-login-form` URL légitime
6. Locations `modsecurity off` : **aucune** ligne correspondante dans `modsec_audit.log`
7. `tail` `error.log` **pendant** le smoke (copier hors conteneur : ce fichier n’est pas persisté)

Rollback immédiat d’une famille : `SecRuleEngine Off` (ou `modsecurity off;` vhost) + `nginx -t` + reload. Ne pas attendre un rebuild si le 500 est là.

---

## 4. Décision go / no-go

| Condition | Go ? |
|-----------|------|
| §0 : error.log 06/08 (ou équivalent) lu, cause racine identifiée **ou** écartée avec test ciblé | obligatoire |
| Overlay 901110 non inclus | déjà vrai aujourd’hui |
| Smoke portal DetectionOnly vert | obligatoire avant On portal |
| Stub sync toujours `SecRuleEngine Off` | OK tant que `engine-mode-generated` n’est pas dans `main-*.conf` |
| IHM affiche encore l’écart DB vs fichiers image | attendu ; le bandeau disparaît quand les `engine-*.conf` **de l’image déployée** rejoignent le mode DB — lecture live conteneur = [#152](https://github.com/vincenttisseront/bastion-app/issues/152) |

**No-go** si le 500 se reproduit sur `/auth/login` avec CRS On/DetectionOnly, même « juste une requête de test ».
