> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d’origine :** `docs/admin-logs-live-and-containers.md` — garder les deux synchronisés (voir `docs/wikijs/MAINTENANCE.md`).

---
# Live audit + logs containers (`/admin/logs`)

## Choix sÃ©curitÃ© containers : Option A (proxy socket)

**DÃ©cision :** `tecnativa/docker-socket-proxy` (ou Ã©quivalent) en **lecture seule**,
exposÃ© uniquement sur le rÃ©seau docker interne. `bastion-app` parle HTTP Ã  ce proxy via
lâ€™URL configurÃ©e en base (`ContainerLogsSettings.proxy_url`) â€” **jamais** de montage de
`/var/run/docker.sock` dans `bastion-app`.

| Pourquoi pas Option B (fichiers json-file) | |
|---|---|
| Chemins `/var/lib/docker/containers/<id>/â€¦` changent Ã  chaque recreate | Fragile sous Ansible/Compose |
| Risque de monter trop large si mal bornÃ© | Moins clair quâ€™un proxy `POST=0` |

Le proxy est dÃ©marrÃ© via lâ€™overlay optionnel
`docker-compose.docker-logs.yml` (`CONTAINERS=1`, `POST=0`). Lâ€™app nâ€™appelle que
`GET /containers/{name}/logs` pour les noms de la liste blanche.

## Configuration (en base, Admin UI)

Source de vÃ©ritÃ© : table singleton `container_logs_settings` (id=1), Ã©ditable dans
**Admin â†’ SÃ©curitÃ© â†’ Logs containers** (`/admin/security#container-logs`) :

- toggle **Activer**
- URL du proxy (ex. `http://docker-socket-proxy:2375`)
- liste blanche (ajout / retrait, pas de textarea libre)
- nombre de lignes (tail)

Les variables `DOCKER_LOGS_*` ne sont **plus lues au runtime**. Elles ne servent quâ€™Ã 
**initialiser** la ligne en base lors de la migration `034_container_logs_settings`
(si `DOCKER_LOGS_PROXY_URL` est dÃ©jÃ  prÃ©sent â†’ `enabled=true` + reprise URL / whitelist).

Activation infra du proxy :

```bash
docker compose -f docker-compose.yml -f docker-compose.docker-logs.yml up -d
```

Puis dans lâ€™UI : activer + renseigner lâ€™URL du proxy. Sans activation, lâ€™onglet Containers
renvoie vers `/admin/security#container-logs`.

## Endpoints

| Route | RÃ´le |
|-------|------|
| `GET /admin/logs` | Page (onglets Audit / Containers) |
| `GET /admin/logs/stream` | SSE audit (`action`, `actor`, dates) |
| `GET /admin/logs/containers/{name}/logs` | Snapshot (~tail) |
| `GET /admin/logs/containers/{name}/stream` | SSE follow |
| `POST /admin/security/container-logs` | Enregistrer enabled / proxy / tail |
| `POST /admin/security/container-logs/containers/add\|remove` | Liste blanche |

Hors liste blanche â†’ **403** (pas de 404). Droit admin (`require_admin`) comme le reste de `/admin/*`.

Audit :

- consultation : `admin.container_logs.viewed` (mÃ©tadonnÃ©es uniquement)
- config : `security.container_logs_settings.updated`

