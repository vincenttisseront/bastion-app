# modsec_wazuh_normalizer

Host-side ModSecurity audit → NDJSON for the local Wazuh agent on **vmdmz-docker01**.

## Done when

- `modsec-wazuh-normalizer.service` is enabled/active
- `/tools/portal/data/nginx-logs/modsec_wazuh.jsonl` grows on new ModSec hits
- `ossec.conf` has a managed `<localfile>` pointing at that path (if agent config enabled)
- First install does **not** replay historical `modsec_audit.log`
- Loopback `Host` (127.0.0.1) events are dropped; no cookies/tokens in output

## AWX

- Project: `bastion-app`
- Playbook: `ansible/linux_sso_portal_docker.yml`
- Limit: `vmdmz-docker01`
- Tags: `modsec_wazuh`
