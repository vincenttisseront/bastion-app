# Bastion nginx — Topologie A (HTTP interne derrière nginx host DMZ)
# + TLS :8443 pour public_proxy (certs ACME montés en lecture seule)
FROM nginx:1.27-alpine

RUN apk add --no-cache bash gettext wget jq findutils \
    && rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /etc/nginx/snippets /etc/nginx/includes /var/lib/sso-portal/exports \
    && mkdir -p /var/www/nginx-errors /var/log/nginx/apps /etc/nginx/ssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/ /etc/nginx/conf.d/
COPY snippets/ /etc/nginx/snippets/
COPY includes/ /etc/nginx/includes/
COPY templates/ /etc/nginx/templates-portal/
COPY docker-entrypoint.sh /docker-entrypoint-portal.sh
COPY sync-exports-to-confd.sh /sync-exports-to-confd.sh
COPY sync-public-proxy-tls.sh /sync-public-proxy-tls.sh
COPY watch-exports-reload.sh /watch-exports-reload.sh
COPY errors/ /var/www/nginx-errors/

RUN chmod +x /docker-entrypoint-portal.sh /sync-exports-to-confd.sh \
         /sync-public-proxy-tls.sh /watch-exports-reload.sh \
    && sed -i 's/\r$//' /docker-entrypoint-portal.sh /sync-exports-to-confd.sh \
         /sync-public-proxy-tls.sh /watch-exports-reload.sh \
    && find /etc/nginx/templates-portal /etc/nginx/snippets /etc/nginx/includes \
         -type f -exec sed -i 's/\r$//' {} +

EXPOSE 8080 8443

ENTRYPOINT ["/docker-entrypoint-portal.sh"]
CMD ["nginx", "-g", "daemon off;"]
