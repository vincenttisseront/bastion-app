# 04.05 — WAF ModSecurity (CRS)

## Objectif

Protéger le trafic HTTP au niveau nginx-bastion avec ModSecurity v3 et les
règles **OWASP CRS**, sans casser le core portail.

## Administration

Admin → **WAF** (`/admin/security/waf`) :

| Onglet / zone | Rôle |
|---------------|------|
| **Bilan** | Verdict, KPI, attaques récentes, top attaquants, ban / exclusion |
| **Profil** | Mode, seuil d’anomalie, rate-limits, seuil IP deny |
| **Exclusions** | Désactivation soft de règles CRS |
| **En-têtes** | Lecture snapshot nginx |
| **Détails techniques** | Sources, diagnostic JSON |
| **`Réactivation`** (onglet conditionnel) | Armement portal / subdomain (DetectionOnly), puis **promotion subdomain → On** |
| **Profil** | Mode, seuil ; **Couper le moteur** si armé |

### Appliquer vs Réactiver

- **Appliquer** : pousse exclusions, deny IP, rate-limits (et le mode **portal** si le moteur est déjà armé).
- **Réactiver le moteur (DetectionOnly)** : arme le connecteur portal + `SecRuleEngine DetectionOnly`,
  exécute un **smoke HTTP** ; en échec → **rollback auto** vers Off.
- **Réactiver subdomain (DetectionOnly)** : après portal armé — même logique sur les FQDN `subdomain_proxy`.
- **Promouvoir subdomain (On)** : passe `engine-subdomain-mode-generated.conf` de DetectionOnly à **On**
  (profil WAF doit être On) ; smoke HTTP ; en échec → **retour DetectionOnly** (pas de désarmement).
- **Couper le moteur** : désarmement immédiat.

Sans armement, le sync nginx force `SecRuleEngine Off` même si le profil DB est « en blocage ».

### Smoke de succès (obligatoire à la réactivation)

1. `nginx -t` + reload
2. `/_portal_nginx_ok` → 200
3. `/api/health` → pas de 5xx
4. `/auth/login` → pas de 5xx (panne type 2026-08-06)
5. Sous-domaines : `GET /healthz` (Host = FQDN) → pas de 5xx

## Bonnes pratiques

- Première réactivation = **DetectionOnly** portal uniquement (subdomain / public restent Off)
- Puis réactiver subdomain en DetectionOnly, observer, **promouvoir On** depuis l’onglet Réactivation
- Observer le Bilan / `modsec_audit.log` avant de passer en **On**
- Exclure avec parcimonie (fausses positives documentées)
- Vérifier disque / logrotate avant réactivation (runbook §0.1)
- Ne pas désactiver globalement pour « faire passer » une app — préférer exclusion fine ou ban IP

## Références dépôt

- Ops : `docs/ops-modsecurity-crs.md`
- Runbook réactivation : `docs/runbook-reactivation-crs-modsecurity.md`
- Conception : `docs/conception-modsecurity-crs-nginx-bastion.md`
- Code : `app/bastion/waf_reactivation.py`

Configs versionnées (`docker/nginx/modsecurity/*`, `waf-basic.conf`, switches)
sont **pièces jointes** de cette page Confluence (voir
`docs/wikijs/confluence-attachments.json`).

Suite : [05.01 Configuration](../05-configuration/05-01-environnement-secrets.md)
