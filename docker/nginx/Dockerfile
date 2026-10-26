# Bastion nginx — edge TLS (80→443) + HTTP interne :8080 pour le routage Host
# Certs ACME montés en lecture seule sous /etc/nginx/ssl
#
# Base image: OWASP ModSecurity CRS (nginx connector + libmodsecurity + CRS).
# Tag pinned (never floating latest / nginx-alpine):
#   owasp/modsecurity-crs:4.28.0-nginx-alpine-202607160307
# Published: 2026-07-16 (Docker Hub / CRS docker release).
# Nginx in this image: 1.30.4 (upstream CRS README) — accepted gap vs former
# bastion base nginx:1.27-alpine (no alpine tag pinned to nginx 1.27.x exists
# on owasp/modsecurity-crs as of this pin).
FROM owasp/modsecurity-crs:4.28.0-nginx-alpine-202607160307

# Image defaults to USER nginx; apk and COPY need root during the build.
USER root

RUN apk add --no-cache bash gettext wget jq findutils openssl logrotate su-exec \
    && rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /etc/nginx/snippets /etc/nginx/includes /etc/nginx/modsecurity \
    && mkdir -p /var/lib/sso-portal/exports \
    && mkdir -p /var/www/nginx-errors /var/log/nginx/apps /etc/nginx/ssl /etc/nginx/ssl-local \
    && mkdir -p /tmp/modsecurity/data /tmp/modsecurity/tmp /tmp/modsecurity/upload \
    && mkdir -p /etc/logrotate.d \
    && test -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so \
    && test -d /etc/modsecurity.d/owasp-crs/rules

COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/ /etc/nginx/conf.d/
COPY snippets/ /etc/nginx/snippets/
COPY includes/ /etc/nginx/includes/
COPY modsecurity/ /etc/nginx/modsecurity/
COPY logrotate.d/modsecurity /etc/logrotate.d/modsecurity
COPY templates/ /etc/nginx/templates-portal/
COPY docker-entrypoint.sh /docker-entrypoint-portal.sh
COPY sync-exports-to-confd.sh /sync-exports-to-confd.sh
COPY sync-acme-tls.sh /sync-acme-tls.sh
COPY sync-public-proxy-tls.sh /sync-public-proxy-tls.sh
COPY watch-exports-reload.sh /watch-exports-reload.sh
COPY export-waf-snapshot.sh /export-waf-snapshot.sh
COPY fix-nginx-logs.sh /fix-nginx-logs.sh
COPY errors/ /var/www/nginx-errors/

# Seed tree for read_only + tmpfs overlays (conf.d / snippets / includes / generated).
RUN mkdir -p /usr/share/bastion-nginx/seed \
    && cp -a /etc/nginx/conf.d /usr/share/bastion-nginx/seed/conf.d \
    && cp -a /etc/nginx/snippets /usr/share/bastion-nginx/seed/snippets \
    && cp -a /etc/nginx/includes /usr/share/bastion-nginx/seed/includes \
    && cp -a /etc/nginx/modsecurity/generated /usr/share/bastion-nginx/seed/generated \
    && chmod -R a+rX /usr/share/bastion-nginx/seed

RUN chmod +x /docker-entrypoint-portal.sh /sync-exports-to-confd.sh \
         /sync-acme-tls.sh /sync-public-proxy-tls.sh /watch-exports-reload.sh \
         /export-waf-snapshot.sh /fix-nginx-logs.sh \
    && sed -i 's/\r$//' /docker-entrypoint-portal.sh /sync-exports-to-confd.sh \
         /sync-acme-tls.sh /sync-public-proxy-tls.sh /watch-exports-reload.sh \
         /export-waf-snapshot.sh /fix-nginx-logs.sh \
    && find /etc/nginx/templates-portal /etc/nginx/snippets /etc/nginx/includes \
         /etc/nginx/modsecurity -type f -exec sed -i 's/\r$//' {} + \
    && sed -i 's/\r$//' /etc/logrotate.d/modsecurity

ARG BASTION_NGINX_IMAGE_TAG=local
ENV BASTION_NGINX_IMAGE_TAG=${BASTION_NGINX_IMAGE_TAG}
ENV NGINX_WAF_SNAPSHOT_PATH=/var/log/nginx/apps/nginx-waf-snapshot.json
ENV BASTION_NGINX_SEED=/usr/share/bastion-nginx/seed

EXPOSE 80 443 8080

ENTRYPOINT ["/docker-entrypoint-portal.sh"]
CMD ["nginx", "-g", "daemon off;"]

# Stay root for entrypoint: ACME PEMs on the host volume are often root:600
# (acme.sh). Entrypoint mirrors them into ssl-local then drops to nginx via
# su-exec (see docker-entrypoint.sh). Compose also sets user: "0:0".
USER root
