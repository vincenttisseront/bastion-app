# modsec_wazuh_normalizer

Host-side ModSecurity audit → NDJSON for the local Wazuh agent on the
**Bastion docker host** (inventory hostname; examples use `docker01`).

## Done when

- `modsec-wazuh-normalizer.service` is enabled/active
- `/tools/portal/data/nginx-logs/modsec_wazuh.jsonl` grows on new ModSec hits
- `ossec.conf` has a managed `<localfile>` pointing at that path (if agent config enabled)
- First install does **not** replay historical `modsec_audit.log`
- Loopback `Host` (127.0.0.1) events are dropped; no cookies/tokens in output

## AWX

- Project: `bastion-app`
- Playbook: `ansible/linux_sso_portal_docker.yml`
- Limit: Bastion docker host (e.g. `docker01`)
- Tags: `modsec_wazuh`
- `modsec_wazuh_allowed_hosts` defaults to **empty** (any host not in
  `modsec_wazuh_forbidden_hosts`). Pin in inventory only if you want a hard allowlist.
