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

# Image defaults to USER nginx; our entrypoint writes conf.d + sync scripts.
USER root

RUN apk add --no-cache bash gettext wget jq findutils openssl logrotate \
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
COPY errors/ /var/www/nginx-errors/

RUN chmod +x /docker-entrypoint-portal.sh /sync-exports-to-confd.sh \
         /sync-acme-tls.sh /sync-public-proxy-tls.sh /watch-exports-reload.sh \
    && sed -i 's/\r$//' /docker-entrypoint-portal.sh /sync-exports-to-confd.sh \
         /sync-acme-tls.sh /sync-public-proxy-tls.sh /watch-exports-reload.sh \
    && find /etc/nginx/templates-portal /etc/nginx/snippets /etc/nginx/includes \
         /etc/nginx/modsecurity -type f -exec sed -i 's/\r$//' {} + \
    && sed -i 's/\r$//' /etc/logrotate.d/modsecurity

EXPOSE 80 443 8080

ENTRYPOINT ["/docker-entrypoint-portal.sh"]
CMD ["nginx", "-g", "daemon off;"]
