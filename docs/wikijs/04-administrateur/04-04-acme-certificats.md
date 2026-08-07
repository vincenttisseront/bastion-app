# 04.04 — ACME & certificats TLS

## Objectif

Émettre et renouveler automatiquement les certificats Let’s Encrypt (DNS-01)
pour le portail et les FQDN d’applications.

## Composants

- Sidecar **acme-companion**
- Stockage `data/certs/<fqdn>/`
- nginx recharge via sync TLS (SNI)

## Administration

Admin → **ACME** :

- liste des domaines issus du manifeste apps / portail
- reconcile / statut
- variables DNS (ex. Cloudflare) via `.env.acme` (hors git)

## Prérequis DNS

- Zone gérée par le provider configuré
- Token avec droit d’édition DNS
- FQDN pointant vers l’edge bastion

## Après ajout d’une app

1. Créer l’app avec `public_fqdn`
2. Apply infra (vhost)
3. Attendre / forcer reconcile ACME
4. Vérifier `https://{fqdn}/` (certificat valide)

Annexe détaillée : `docs/lets-encrypt-acme-nginx-bastion.md`

Suite : [04.05 WAF](./04-05-waf-modsecurity.md)
