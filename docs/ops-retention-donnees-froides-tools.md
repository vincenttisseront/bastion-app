# Ops — rétention et compactage des données froides (`/tools`)

> **Incident 2026-08-19** : pré-vol Ansible `sso_portal_min_free_disk_mb` en échec —
> `/dev/mapper/vg0-lv_tools` 11 G, **255 Mo libres (98 %)**. Il manquait 1 Mo pour déployer.
>
> Lié : [`runbook-reactivation-crs-modsecurity.md`](runbook-reactivation-crs-modsecurity.md)
> (prérequis disque avant réactivation CRS) · [`ops-modsecurity-crs.md`](ops-modsecurity-crs.md).

---

## 1. Constat — répartition réelle (docker01, août 2026)

| Poste | Taille | Part de `/tools` |
|---|---:|---:|
| `data/nginx-logs/` | **~8,4 G** | ~76 % |
| ├─ `immich.error.log` | **~5,2 G** | ~47 % |
| ├─ `immich.access.log` | **~2,3 G** | ~21 % |
| ├─ `keycloak.error.log` | ~0,5 G | |
| ├─ `modsec_audit.log` | ~102 Mo | |
| └─ autres apps | ~0,2 G | |
| `data/pgdata/` | ~70 Mo | |
| `portal.db.bak.*` (14+ copies) | ≥ 92 Mo | |
| Code (`app/`, `docker/`…) | négligeable | |

**Inodes** : OK (~3 %) — problème de **volume**, pas d'inodes.

### Trois diagnostics

1. **Immich seul ~7,6 Go** — boucle d'erreur non vue (symptôme masqué par la saturation disque).
2. **Aucune rotation effective** sur `data/nginx-logs/` côté **hôte** : le logrotate dans
   l'image nginx (`/etc/logrotate.d/modsecurity`) ne couvre que `modsec_audit.log` **dans le
   conteneur** ; les logs per-app (`immich.*`, `keycloak.*`, …) ne sont **pas** rotés.
3. **`portal.db.bak.*`** créées à **chaque déploiement** Ansible (preflight), sans purge.

### Chemins ModSecurity (conteneur vs hôte)

| Vue | Chemin |
|-----|--------|
| Dans `bastion-nginx` | `/var/log/nginx/apps/modsec_audit.log` |
| Sur l'hôte (bind mount) | `{{ bastion_app_docker_data_dir }}/nginx-logs/modsec_audit.log` |
| Prod typique | `/tools/portal/data/nginx-logs/modsec_audit.log` |

`/var/log/nginx/apps/modsec_audit.log` **n'existe pas sur l'hôte** — seulement dans le conteneur,
alias du volume partagé ci-dessus.

---

## 2. Remédiation immédiate (ordre strict)

### 2.1 Préserver la preuve avant troncature

```bash
cd /tools/portal/data/nginx-logs
tail -n 2000 immich.error.log > /root/immich.error.sample.txt
awk -F'] ' '{print $2}' immich.error.log \
  | sed 's/client: [0-9.]*/client: X/g; s/request: "[^"]*"/request: "X"/g' \
  | sort | uniq -c | sort -rn | head -20 > /root/immich.error.patterns.txt
head -1 immich.error.log; tail -1 immich.error.log
```

### 2.2 Tronquer (pas `rm` — nginx garde les fd ouverts)

```bash
: > /tools/portal/data/nginx-logs/immich.error.log
: > /tools/portal/data/nginx-logs/immich.access.log
: > /tools/portal/data/nginx-logs/keycloak.error.log
docker exec bastion-nginx nginx -s reopen
df -h /tools
```

### 2.3 Teleport (373 Mo fantômes)

```bash
systemctl restart teleport   # adapter au mode réel
lsof +L1 2>/dev/null | awk '$5=="REG" && $7>10485760'
```

### 2.4 Sauvegardes SQLite

Automatisé par Ansible après chaque backup preflight — voir
`scripts/purge-portal-db-backups.py` (5 dernières + 1/jour sur 7 j, gzip des anciennes gardées).

Manuel d'urgence :

```bash
ls -1t /tools/portal/data/portal.db.bak.* | tail -n +6 | xargs -r rm --
```

**Gain attendu** après troncature logs : ~8 Go libres.

---

## 3. Politique cible

| Palier | Âge | État | Emplacement |
|---|---|---|---|
| **Chaud** | 0–2 j | clair, live | `…/nginx-logs/` |
| **Tiède** | 2–14 j | `.gz` | même répertoire |
| **Froid** | 14–90 j | `.gz` déporté | NAS / volume dédié (via SIEM) |
| **Archive** | > 90 j | purge ou SIEM seul | cf. `preparation-integration-siem.md` |

### 3.1 Logrotate hôte (déployé par Ansible)

Fichier : `/etc/logrotate.d/bastion-nginx-logs` (template rôle `bastion_app_docker`).

Points critiques :

- `maxsize 200M` sur `*.{access,error}.log` — rotation **à la taille**, pas seulement quotidienne
  (stanza séparée de `modsec_audit.log` pour éviter l'erreur logrotate *duplicate log entry*).
- Stanza séparée `modsec_audit.log` : `maxsize 100M`, `rotate 30`.
- `postrotate` : `docker exec bastion-nginx nginx -s reopen`.

Validation :

```bash
logrotate -d /etc/logrotate.d/bastion-nginx-logs
logrotate -f /etc/logrotate.d/bastion-nginx-logs
ls -lh /tools/portal/data/nginx-logs/
```

### 3.2 Déport froid (> 14 j)

Hebdomadaire : déplacer les `.gz` > 14 j hors `/tools` (NAS). À câbler avec le SIEM — pas de
second mécanisme d'archivage parallèle.

### 3.3 Mesure débit `modsec_audit.log` (avant CRS DetectionOnly)

```bash
f=/tools/portal/data/nginx-logs/modsec_audit.log
s1=$(stat -c%s "$f"); sleep 600; s2=$(stat -c%s "$f")
echo "$(( (s2-s1)/1024 )) Ko / 10 min  →  ~$(( (s2-s1)*144/1048576 )) Mo/jour"
```

102 Mo actuels avec moteur **Off** depuis le 2026-08-06 — anticiper **×10 ou plus** en
`DetectionOnly` sur trafic réel.

---

## 4. Corrections structurelles (backlog)

1. **LV dédiée** pour `nginx-logs/` (ou quota) — une app tierce ne doit pas bloquer le portail.
2. **Alertes Wazuh** : 80 % / 90 % sur `/tools`.
3. **Taux d'erreur nginx** (Immich 5 Go d'errors) — pas seulement l'espace disque.
4. **Pré-vol Ansible** : message avec espace libre **et** seuil (corrigé dans le rôle).
5. **Doc ops ModSec** : chemins hôte vs conteneur (cf. §1 ci-dessus).

---

## 5. Prérequis runbook CRS

Voir [`runbook-reactivation-crs-modsecurity.md`](runbook-reactivation-crs-modsecurity.md) §0.1 :

- `/tools` < 70 % occupé, ≥ 3 Go libres.
- Logrotate hôte vérifié (présence de `.gz` après `logrotate -f`).
- Débit `modsec_audit.log` mesuré.
