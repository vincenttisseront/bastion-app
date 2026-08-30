> **Format :** Markdown (source Wiki.js).  
> **Fichier dépôt d'origine :** docs/KEYCLOAK_CRUSHFTP_SETUP.md — garder les deux synchronisés (voir docs/wikijs/MAINTENANCE.md).

---
# Keycloak + CrushFTP — Dual Authentication Barrier

## Overview

This architecture enforces **two successive authentication steps** before granting access to CrushFTP:

1. **Keycloak (via oauth2-proxy)** — Username + OTP against the `TRANSFER` realm
2. **CrushFTP** — Native CrushFTP login (application password)

```
User
  │
  ▼
Cloudflare (proxy)
  │
  ▼
nginx : transfer.ar-systems.fr:443
  │
  ├─── [No valid _kc_transfer cookie]
  │        │
  │        ▼
  │    oauth2-proxy (127.0.0.1:4183)
  │        │ auth_request
  │        ▼
  │    Keycloak realm TRANSFER
  │    → Username + OTP (flow: crushftp-username-otp)
  │    → _kc_transfer cookie set on browser
  │
  └─── [Valid _kc_transfer cookie]
           │  proxy_pass (forwards CrushAuth cookie only)
           ▼
       CrushFTP (172.24.0.106:443)
       → Native CrushFTP login
```

---

## Components

| Component | Host | Address |
|---|---|---|
| nginx reverse proxy | vmdmz-reverse01 | 172.24.0.108 |
| oauth2-proxy **transfer** | vmdmz-reverse01 (loopback) | 127.0.0.1:**4183** (dédié — **pas** :4180 portail) |
| CrushFTP | vmdmz-crush01 | 172.24.0.106:443 |
| Keycloak | vmdmz-docker01 | 172.24.0.110 (Docker) |
| Traefik | vmdmz-docker01 | 172.24.0.110:443 |

---

## 1. Keycloak — TRANSFER Realm Configuration

### 1.1 Realm settings

- Name: `TRANSFER`
- Login theme: `ar-systems` (custom)
- Brute force protection: enabled

### 1.2 Authentication flow

Custom flow `crushftp-username-otp`:
- **Username Form** (Required)
- **OTP Form** (Required)
- No Password Form

Applied as a **Browser flow override** on the `transfer-ar-systems` client.

> Removing the Keycloak password step is intentional: users authenticate with
> username + TOTP only on the Keycloak side. The application password is
> requested by CrushFTP itself (second barrier).

### 1.3 OIDC Client

| Parameter | Value |
|---|---|
| Client ID | `transfer-ar-systems` |
| Client secret | stored in AWX Credential `vault_transfer_oidc_client_secret` |
| Valid redirect URIs | `https://transfer.ar-systems.fr/oauth2/callback` |
| Web origins | `https://transfer.ar-systems.fr` |
| Browser flow override | `crushftp-username-otp` |

### 1.4 User accounts

Accounts are synchronized from CrushFTP to Keycloak every 15 minutes by `crushftp_sync_keycloak.sh`.

- Email format: `<username>@ext.ar-systems.fr` (placeholder)
- `VERIFY_PROFILE` disabled (unverified email accepted)
- OTP configured by each user on first login

### 1.5 Deployment via AWX

Playbook: `keycloak_provisioning.yml`  
Required AWX credentials:
```yaml
vault_keycloak_auth_url: "https://keycloak.ar-systems.fr"
vault_keycloak_admin_username: "admin"
vault_keycloak_admin_password: "<admin_password>"
```

---

## 2. nginx — transfer.ar-systems.fr vhost

**Source de vérité :** `awx-playbook/roles/nginx_reverse_proxy_dmz/`

| Fichier AWX | Déployé sur reverse01 |
|-------------|------------------------|
| `templates/vhost_transfer_crushftp.conf.j2` | `/etc/nginx/conf.d/vhost_transfer_crushftp.conf` |
| `files/transfer-crushftp.map.conf` | `/etc/nginx/includes/transfer-crushftp.map.conf` |
| `templates/nginx.conf.j2` (include map) | `include ... transfer-crushftp.map.conf` dans `http {}` |

Variable AWX : `transfer_dmz_vhost_enabled: true` (défaut).

**Ne pas patcher manuellement** avec des scripts bastion-app expérimentaux — restaurer via AWX ou `scripts/restore-transfer-nginx-awx.sh`.

### 2.1 Logique proxy (login natif CrushFTP)

```nginx
# Map cookie (http {}) — transfer-crushftp.map.conf
map $http_cookie $transfer_crushftp_backend_cookie { ... }

location / {
    proxy_pass            https://172.24.0.106;
    proxy_set_header Host 172.24.0.106;
    proxy_set_header Cookie $transfer_crushftp_backend_cookie;
    proxy_ssl_verify off;
    proxy_ssl_session_reuse off;
    ...
}
```

> Le vhost AWX actuel est **login natif CrushFTP** (pas d'`auth_request` Keycloak sur transfer).
> La double barrière Keycloak + CrushFTP (oauth2) est une variante documentée historiquement — non déployée si `transfer_dmz_vhost_enabled: true`.

### 2.2 Réglages proxy CrushFTP (AWX)

| Directive | Reason |
|---|---|
| `proxy_http_version 1.1` | CrushFTP speaks HTTP/1.0; keepalive required |
| `proxy_ssl_verify off` | Self-signed cert `CN=www.crushftp.com` |
| `proxy_ssl_protocols TLSv1.2` | Restrict TLS negotiation |
| `proxy_buffering off` | Required for large file transfers |
| `proxy_set_header Cookie $transfer_crushftp_backend_cookie` | Filtre cookies SSO si `_kc_*` présents |
| `proxy_set_header Host "172.24.0.106"` | CrushFTP only responds to its own IP as Host |

---

## 3. oauth2-proxy — Configuration

Source file: `roles/nginx_reverse_proxy_dmz/templates/oauth2-proxy.cfg.j2`  
Deployed to: `/etc/oauth2-proxy/oauth2-proxy.cfg`  
Systemd service: `oauth2-proxy.service`

```ini
provider              = "keycloak-oidc"
oidc_issuer_url       = "https://keycloak.ar-systems.fr/realms/TRANSFER"
client_id             = "transfer-ar-systems"
client_secret         = "<vault_transfer_oidc_client_secret>"
redirect_url          = "https://transfer.ar-systems.fr/oauth2/callback"
scope                 = "openid profile email"
code_challenge_method = "S256"

email_domains                        = ["*"]
insecure_oidc_allow_unverified_email = true
oidc_extra_audiences                 = ["account"]

cookie_name     = "_kc_transfer"
cookie_expire   = "8h"
cookie_refresh  = "1h"
cookie_secure   = true
cookie_httponly = true
cookie_samesite = "lax"
```

> `email_domains = ["*"]` is required because accounts use `@ext.ar-systems.fr`
> placeholder emails which do not match the main domain.

---

## 4. Keycloak vhost — keycloak.ar-systems.fr

Source file: `roles/nginx_reverse_proxy_dmz/templates/vhost_keycloak.conf.j2`  
Deployed to: `/etc/nginx/conf.d/vhost_keycloak.conf`

### 4.1 Backend routing

```
nginx:443  →  https://172.24.0.110 (Traefik)
                  Host: keycloak.ar-systems.fr
                        ↓
               keycloak container:8080 (Docker internal network)
```

Keycloak's port 8080 is **not published** on the Docker host — Traefik is the only internal entry point.

### 4.2 Access restrictions

| Location | Access |
|---|---|
| `/admin` | LAN RFC1918 only (10/8, 172.16/12, 192.168/16) |
| `/health` | LAN RFC1918 only |
| `/metrics` | LAN RFC1918 only |
| `/` | Public — rate limited (10 r/s, burst 30) |

### 4.3 Keycloak proxy mode

```
KC_PROXY_HEADERS=xforwarded
```

Keycloak trusts the `X-Forwarded-Proto: https` header from nginx and generates redirect URLs with `https://`.

---

## 5. CrushFTP → Keycloak User Sync

### 5.1 Mechanism

The script `crushftp_sync_keycloak.sh` runs via cron every 15 minutes on vmdmz-crush01. It:
1. Reads the CrushFTP user list via the local API
2. For each user missing from Keycloak → creates the account with email `<user>@ext.ar-systems.fr`
3. Uses the `crushftp-provisioner` service account client (secret: `vault_crushftp_provisioner_client_secret`)

### 5.2 First OTP setup

On first login, the user is redirected to Keycloak's OTP setup page. They must scan the QR code using Google Authenticator or any compatible TOTP app.

---

## 6. AR Systems Keycloak Theme

Deployment script: `files/deploy-keycloak-theme.sh`

```bash
# Run on vmdmz-docker01
sudo bash deploy-keycloak-theme.sh [/path/to/logo.png]
```

The script:
1. Builds the theme structure under `/tmp/ar-systems-theme/`
2. Copies it into the container: `docker cp ... keycloak:/opt/keycloak/themes/`
3. Activates via `kcadm.sh`: sets `loginTheme=ar-systems` on the `TRANSFER` realm

Customizations:
- White background (PatternFly v5 override)
- AR Systems logo in the header
- Navy blue buttons `#1a2a4a`
- Subtle hint message on the login form
- Footer `© AR-SYSTEMS 2026`

---

## 7. AWX Deployment

### 7.1 Job Template

Name: `App – Nginx reverse`

Permanent Extra Variables (must be saved in the job template):
```yaml
vault_transfer_oidc_client_secret: "NpiCCDcyTCFlSvgbAGf5Igsp9ikmuj9y"
vault_crushftp_provisioner_client_secret: "QyBNpzm1J6nazaO0091A6C80CLog9qBI"
```

### 7.2 Emergency rollback

To instantly disable the Keycloak barrier without a full redeployment:
```yaml
# In AWX Job Template Extra Variables
transfer_keycloak_enabled: false
```

Re-run the job → nginx switches back to direct CrushFTP proxy with no Keycloak barrier.

---

## 8. Cloudflare DNS

Both records must point to **nginx** (vmdmz-reverse01), not directly to Keycloak.

| Record | Type | Origin IP | Proxy |
|---|---|---|---|
| `transfer` | A | vmdmz-reverse01 public IP | ✅ Proxied |
| `keycloak` | A | vmdmz-reverse01 public IP | ✅ Proxied |

---

## 9. Go-live Checklist

- [ ] `TRANSFER` realm created and configured (`keycloak_provisioning.yml`)
- [ ] `crushftp-username-otp` flow created and assigned as browser flow override on client
- [ ] `VERIFY_PROFILE` disabled in realm settings
- [ ] `transfer-ar-systems` client configured (redirect URI, web origin, flow override)
- [ ] `crushftp-provisioner` client configured (service account, `manage-users` role)
- [ ] AWX job `App – Nginx reverse` run with vault secrets in Extra Variables
- [ ] oauth2-proxy running (`systemctl status oauth2-proxy`)
- [ ] Cloudflare DNS `transfer` → nginx public IP
- [ ] Cloudflare DNS `keycloak` → nginx public IP
- [ ] Theme deployed: `sudo bash deploy-keycloak-theme.sh /path/to/logo.png`
- [ ] End-to-end test: private browser → `https://transfer.ar-systems.fr` → Keycloak (username + OTP) → CrushFTP login

---

## 10. Troubleshooting

### Firefox timeout / corps vide sur `/WebInterface/new-ui/`

**Cause :** CrushFTP sert correctement `…/new-ui/index.html` (~20 Ko) mais coupe le TLS sur `GET …/new-ui/` (Content-Length 4096, corps vide → nginx `upstream prematurely closed`).

**Correctif nginx (AWX) :** redirect exact `location = /WebInterface/new-ui/` → `/WebInterface/new-ui/index.html` ; `proxy_redirect` login.html → `index.html` (pas le slash directory).

### IP CrushFTP OK mais `transfer.ar-systems.fr` KO

**Restaurer la config AWX** (ne pas improviser de patch nginx) :

```bash
# Sur vmdmz-reverse01 — depuis bastion-app
sudo bash scripts/restore-transfer-nginx-awx.sh

# Ou relancer le job AWX « App – Nginx reverse » (rôle nginx_reverse_proxy_dmz)
```

Vérifier :

```bash
grep transfer-crushftp /etc/nginx/nginx.conf
nginx -t
curl -sk "https://172.24.0.106/WebInterface/new-ui/" -H "Host: 172.24.0.106" -w "direct=%{size_download}\n" -o /dev/null
curl -sk "https://transfer.ar-systems.fr/WebInterface/new-ui/" --resolve transfer.ar-systems.fr:443:127.0.0.1 -w "proxy=%{size_download}\n" -o /dev/null
```

Référence fichiers : `awx-playbook/roles/nginx_reverse_proxy_dmz/` ou `bastion-app/nginx/reference-from-awx/`.

### 502 on transfer.ar-systems.fr after Keycloak authentication

Most likely cause: oversized cookie forwarded to CrushFTP.  
Verify the `$crushftp_cookie_filtered` map is active and `proxy_set_header Cookie $crushftp_cookie_filtered` is in place.

```bash
sudo tail -50 /var/log/nginx/error.log | grep crush
```

### 502 on keycloak.ar-systems.fr

```bash
# From vmdmz-reverse01 — test Traefik directly
curl -vk https://172.24.0.110 -H "Host: keycloak.ar-systems.fr"
```

### oauth2-proxy returns 403

Check `email_domains = ["*"]` in `/etc/oauth2-proxy/oauth2-proxy.cfg`.  
Verify the user exists in the `TRANSFER` realm.

### OTP not requested at login

Verify that `crushftp-username-otp` is set as the **Browser flow override** on the `transfer-ar-systems` **client** — not at the realm level.

### Keycloak generates http:// redirect URLs

Verify `KC_PROXY_HEADERS=xforwarded` is set in the container:
```bash
sudo docker inspect keycloak --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -i proxy
```
