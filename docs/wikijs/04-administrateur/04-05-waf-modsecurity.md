# 04.05 — WAF ModSecurity (CRS)

## Objectif

Protéger le trafic HTTP au niveau nginx-bastion avec ModSecurity v3 et les
règles **OWASP CRS**, sans casser le core portail.

## Administration

Admin → **WAF** :

- statut moteur
- profil / mode (DetectionOnly vs Blocking selon config)
- exclusions ciblées

## Bonnes pratiques

- Valider d’abord en DetectionOnly sur un périmètre
- Exclure avec parcimonie (fausses positives documentées)
- Surveiller les logs ModSec / nginx error
- Ne pas désactiver globalement pour « faire passer » une app — préférer exclusion fine

## Références dépôt

- Ops : `docs/ops-modsecurity-crs.md`
- Conception : `docs/conception-modsecurity-crs-nginx-bastion.md`

Suite : [05.01 Configuration](../05-configuration/05-01-environnement-secrets.md)
