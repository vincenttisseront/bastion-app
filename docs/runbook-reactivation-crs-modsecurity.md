# Runbook — réactivation ModSecurity / OWASP CRS

**Statut** : opérationnel IHM (portal) depuis 2026-08-21 — smoke HTTP + rollback auto.
**Prérequis §0 / §0.1** restent recommandés avant la **première** réactivation prod.

| Action | Où | Effet |
|--------|-----|--------|
| **Réactiver** | Onglet **Réactivation** (visible seulement si désarmé) | DetectionOnly portal + smoke + armement |
| **Couper** | Onglet **Profil** (si armé) | Off immédiat + désarmement |
| **Appliquer** | en-tête WAF | Overlays (exclusions, deny, rates) ; mode moteur **seulement si armé** |

Code : `app/bastion/waf_reactivation.py` · sync : `docker/nginx/sync-exports-to-confd.sh`.

Liens : [`ops-modsecurity-crs.md`](ops-modsecurity-crs.md) · [`04-05-waf-modsecurity.md`](wikijs/04-administrateur/04-05-waf-modsecurity.md) · conception §9.

---

## 0. Prérequis bloquant — `error.log` du 2026-08-06

Cause racine du 500 **On** identifiée (2026-08-22) : `crs-setup.conf` sans
`tx.crs_setup_version=4280` → règle CRS **901001** (`deny,status:500`). En
**DetectionOnly** le deny n’est pas appliqué (smoke vert) ; en **On** chaque requête
ModSec renvoie 500. Rebuild/reload nginx après merge du fix statique.

| Fichier | Monté sur l’hôte ? | Conséquence |
|---------|--------------------|-------------|
| `/var/log/nginx/error.log` | **Non** (`error_log` dans `nginx.conf`, hors volume) | **Perdu au recreate** du conteneur |
| `/var/log/nginx/apps/modsec_audit.log` | Oui (`SSO_PORTAL_DATA_DIR/nginx-logs`) | Peut encore être là si le volume n’a pas été rotaté / vidé |
| stdout `docker logs bastion-nginx` | Journal Docker hôte | Peut contenir des lignes `error_log` **seulement** si quelqu’un a redirigé ; par défaut **non** |

**Avant la première réactivation prod** :

1. Le conteneur `bastion-nginx` a-t-il été **recréé** depuis le 06/08 soir ?
2. Si non : `docker exec bastion-nginx ls -l /var/log/nginx/error.log` + copie hors conteneur.
3. Si oui : reste-t-il une copie (sauvegarde hôte, ticket, `docker logs`, `modsec_audit.log`) ?

Commandes de récupération (lecture seule) :

```bash
docker exec bastion-nginx ls -l /var/log/nginx/error.log /var/log/nginx/apps/modsec_audit.log
docker exec bastion-nginx sh -c 'wc -l /var/log/nginx/error.log; grep -E "2026/08/06|ModSecurity|modsecurity" /var/log/nginx/error.log | tail -n 200'
sudo ls -l "${SSO_PORTAL_DATA_DIR:-/tools/portal/data}/nginx-logs/modsec_audit.log"
```

---

## 0.1 Prérequis bloquant — espace disque et rotation logs

**Incident 2026-08-19** : déploiement bloqué à 98 % sur `/tools`. Réactiver CRS
sur un disque plein provoquerait une panne edge — `modsec_audit.log` peut croître rapidement en
`DetectionOnly`.

| Check | Go ? |
|-------|------|
| `/tools` (ou LV data) **< 70 %** occupé | obligatoire |
| **≥ 3 Go libres** sur la LV data | obligatoire |
| Logrotate hôte actif sur `nginx-logs/` | obligatoire — voir [`ops-retention-donnees-froides-tools.md`](ops-retention-donnees-froides-tools.md) |
| `logrotate -f /etc/logrotate.d/bastion-nginx-logs` produit un `.gz` | vérifié, pas supposé |
| Débit `modsec_audit.log` mesuré (10 min) | obligatoire avant DetectionOnly |

```bash
df -h /tools
df -Pm /tools | awk 'NR==2 {printf "use=%s free=%sMiB\n", $5, $4}'
ls -lh /etc/logrotate.d/bastion-nginx-logs
logrotate -d /etc/logrotate.d/bastion-nginx-logs

f=/tools/portal/data/nginx-logs/modsec_audit.log
s1=$(stat -c%s "$f"); sleep 600; s2=$(stat -c%s "$f")
echo "$(( (s2-s1)/1024 )) Ko / 10 min  →  ~$(( (s2-s1)*144/1048576 )) Mo/jour"
```

**No-go** si `/tools` > 90 % ou si la rotation n'est pas effective (aucun `.gz` après forçage).

---

## 1. Réactivation IHM (portal)

### Déploiement requis

- Rebuild **bastion-nginx** (template vhost + `main-portal.conf` + sync + watcher)
  puis redeploy **bastion-app**.
- En prod, `bastion-app` **n’a pas** `docker.sock` : la réactivation écrit les exports ;
  `watch-exports-reload` synchronise + `nginx -t` + reload ; la **smoke HTTP** décide
  du succès ou du rollback (pas `docker compose exec`).

### Étapes admin

1. Vérifier §0.1 (disque / rotation).
2. Admin → **WAF** → bandeau ou ancre `#reactivation`.
3. Cocher la confirmation → **Réactiver le moteur (DetectionOnly)**.
4. Attendre le flash succès (smoke OK) ou erreur (rollback auto).
5. Observer `modsec_audit.log` / détections Bilan.
6. Plus tard : profil **On** + **Appliquer** (moteur déjà armé) — pas le soir de la 1ʳᵉ réactivation.
7. Urgence : **Couper le moteur** (même panneau).

### Ce que fait le code

1. Écrit `exports/modsecurity/waf-engine-arm.json` (`armed: true`)
2. Écrit `exports/modsecurity-portal-switch.conf` → `modsecurity on;`
3. Profil DB → `detection_only` ; `engine-mode-generated.conf` → `SecRuleEngine DetectionOnly`
4. `docker compose exec nginx` : sync + `nginx -t` + reload + snapshot
5. **Smoke HTTP** (échec → rollback) :
   - `http://nginx:8080/_portal_nginx_ok` → 200
   - `http://nginx:8080/api/health` (Host portal) → pas de 5xx
   - `/auth/login` → pas de 5xx *(panne type 2026-08-06)*
6. Succès → armement `phase: active` ; échec → Off + switch off + `armed: false`

### Garde-fous sync

Sans `armed: true`, `sync-exports-to-confd.sh` **force** `SecRuleEngine Off` même si
l’export profil dit On — un simple Appliquer ne peut plus brick l’edge.

Subdomain / public restent **Off** (hors IHM pour l’instant).

---

## 1bis. Ce que la réactivation n'est **pas**

- Pas un simple **Appliquer** WAF sans armement / smoke.
- Pas un rebranchement à l’aveugle de `crs-setup-generated.conf` (id 901110 → 500).
- Pas les 3 familles en `On` le même soir.
- Pas un contournement des prérequis disque §0.1.

---

## 2. Ordre ops manuel (si IHM indisponible)

1. **Une famille**, portal d’abord.
2. `SecRuleEngine DetectionOnly` **avant** `On`.
3. Smoke §3 **avant** la famille suivante.
4. Armer via IHM de préférence ; sinon aligner `waf-engine-arm.json` + switch + sync.
5. `crs-setup-generated.conf` : **ne pas** Include (seuils = static `crs-setup.conf`).

Fichiers image concernés :

- `docker/nginx/includes/modsecurity-portal-switch.conf` (défaut `off`)
- `docker/nginx/modsecurity/main-portal.conf` — Include `engine-mode-generated` (gated by arm)
- `docker/nginx/sync-exports-to-confd.sh`
- `docker/nginx/templates/vhost_sso_portal.conf.template` — include du switch

---

## 3. Smoke (bloquant)

Après **chaque** bascule portal (IHM ou manuel) :

1. `nginx -t` + reload (fait par IHM / watcher)
2. Login SSO → dashboard (`/auth/login` **pas 500**)
3. Locations `modsecurity off` : health inchangé
4. `tail` `error.log` **pendant** le smoke (copier hors conteneur)

Rollback immédiat : bouton **Couper le moteur** ou désarmer + Off + reload.

---

## 4. Décision go / no-go

| Condition | Go ? |
|-----------|------|
| §0.1 : `/tools` < 70 %, ≥ 3 Go libres, logrotate OK | obligatoire avant 1ʳᵉ réactivation |
| Overlay 901110 non inclus | déjà vrai |
| Smoke IHM vert (probes ci-dessus) | obligatoire |
| Subdomain / public encore Off | attendu en phase 1 |
| Passage On | seulement après observation DetectionOnly |

**No-go** si le 500 se reproduit sur `/auth/login` — l’IHM doit avoir rollback ; ne pas réarmer sans diag.
