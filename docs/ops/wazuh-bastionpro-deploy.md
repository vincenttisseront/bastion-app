# Déploiement Wazuh — règles / décodeur BastionPro

Manager : **`vmtools-wazuhdash01`** (`/var/ossec`).  
Forwarder (`vmtools-wazuhlogsfw01`) : agent + rsyslog uniquement — **ne pas** y déployer ces fichiers.

Sources dépôt (aussi pièces jointes Confluence page SIEM) :

| Source | Destination manager |
|--------|---------------------|
| `docs/ops/wazuh-bastionpro-rules.xml` | `/var/ossec/etc/rules/bastionpro_rules.xml` |
| `docs/ops/wazuh-bastionpro-decoders.xml` | `/var/ossec/etc/decoders/bastionpro_decoders.xml` |

## Permissions obligatoires

`wazuh-analysisd` tourne sous l’utilisateur **`wazuh`**. Un fichier `root:root` `0600`
provoque :

```text
Could not open file 'etc/rules/bastionpro_rules.xml' due to [(13)-(Permission denied)]
```

Dans ce cas **analysisd démarre quand même**, mais **sans** charger les règles
BastionPro → plus d’alertes `bastionpro` / `10050x` (incident 2026-08-30 ~09:43).

Cible attendue (comme `local_rules.xml`) :

| Fichier | Owner | Mode |
|---------|-------|------|
| `bastionpro_rules.xml` | `root:wazuh` | `0660` |
| `bastionpro_decoders.xml` | `root:wazuh` | `0660` |

## Déploiement manuel

```bash
# Copie (depuis le dépôt ou les PJ Confluence)
sudo install -o root -g wazuh -m 0660 \
  wazuh-bastionpro-rules.xml \
  /var/ossec/etc/rules/bastionpro_rules.xml

sudo install -o root -g wazuh -m 0660 \
  wazuh-bastionpro-decoders.xml \
  /var/ossec/etc/decoders/bastionpro_decoders.xml
```

Si les fichiers sont déjà en place avec de mauvaises permissions :

```bash
sudo namei -l /var/ossec/etc/rules/bastionpro_rules.xml
sudo stat -c '%A %a %U:%G %n' \
  /var/ossec/etc/rules/bastionpro_rules.xml \
  /var/ossec/etc/rules/local_rules.xml \
  /var/ossec/etc/decoders/bastionpro_decoders.xml

sudo chown root:wazuh \
  /var/ossec/etc/rules/bastionpro_rules.xml \
  /var/ossec/etc/decoders/bastionpro_decoders.xml
sudo chmod 0660 \
  /var/ossec/etc/rules/bastionpro_rules.xml \
  /var/ossec/etc/decoders/bastionpro_decoders.xml

sudo -u wazuh test -r /var/ossec/etc/rules/bastionpro_rules.xml \
  && echo "OK : règles lisibles par wazuh" \
  || echo "ERREUR : règles non lisibles"
sudo -u wazuh test -r /var/ossec/etc/decoders/bastionpro_decoders.xml \
  && echo "OK : décodeur lisible par wazuh" \
  || echo "ERREUR : décodeur non lisible"
```

## Validation avant reload

```bash
sudo xmllint --noout /var/ossec/etc/rules/bastionpro_rules.xml
sudo xmllint --noout /var/ossec/etc/decoders/bastionpro_decoders.xml

sudo /var/ossec/bin/wazuh-analysisd -t
echo "Code retour analysisd : $?"   # attendu : 0
```

## Rechargement

```bash
sudo systemctl reload wazuh-manager
sleep 10
sudo /var/ossec/bin/wazuh-control status

sudo tail -n 200 /var/ossec/logs/ossec.log | \
  grep -Ei 'bastionpro_rules|permission denied|duplicate|invalid|analysisd'
```

La ligne `Could not open file 'etc/rules/bastionpro_rules.xml'` **ne doit plus**
apparaître.

```bash
sudo grep -E '100500|100501|100520|100524|100530|100531|100532' \
  /var/ossec/logs/ossec.log | tail -n 30
```

## Test décodeur / règle (`wazuh-logtest`)

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Coller :

```text
2026-08-30T13:45:00Z bastion BastionPro-Sentinel CEF:0|Bastion|BastionPro-Sentinel|0.5.0|BST-SIEM-0001|SIEM_CONNECTIVITY_TEST|1
```

Attendu : `decoder.name: bastionpro-cef`, `rule.id: 100501`. Quitter : `Ctrl+C`.

Ban IP (CEF 10) → `100524` puis `100530`, `rule.level: 12`.

## Contrôle Discover

Après reload + nouvel événement BastionPro :

- `data.bastion.signature_id: *` (Last 15 minutes ; retirer `rule.groups:bastionpro` si besoin)
- `data.bastion.signature_id: "BST-SIEM-0001"`

## Ansible / AWX (obligatoire)

```yaml
- name: Deploy BastionPro Wazuh rules
  ansible.builtin.copy:
    src: bastionpro_rules.xml
    dest: /var/ossec/etc/rules/bastionpro_rules.xml
    owner: root
    group: wazuh
    mode: "0660"
  notify: Reload Wazuh manager

- name: Deploy BastionPro Wazuh decoder
  ansible.builtin.copy:
    src: bastionpro_decoders.xml
    dest: /var/ossec/etc/decoders/bastionpro_decoders.xml
    owner: root
    group: wazuh
    mode: "0660"
  notify: Reload Wazuh manager
```

Ne jamais déployer avec `mode: "0600"` ni `group: root` sans lecteur `wazuh`.

## Hors scope

L’erreur récurrente `n8n_sysmon_eid10_lsass_access` (intégration manquante) est
**indépendante** et n’explique pas l’arrêt des événements BastionPro.
