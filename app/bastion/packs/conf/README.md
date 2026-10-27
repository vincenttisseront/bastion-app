# Virtual-patch pack sources (app image)

Mirrored from `docker/nginx/modsecurity/` so the WAF admin UI can probe
`source_present` inside `bastion-pro-app` (`.dockerignore` excludes `docker/nginx`).

When editing a pack `.conf`, update **both** trees (or copy nginx → here).
Nginx runtime still loads `/etc/nginx/modsecurity/*.conf` from the nginx image.
