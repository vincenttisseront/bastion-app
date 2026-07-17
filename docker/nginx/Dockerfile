# Bastion nginx — Topologie A (HTTP interne derrière nginx host DMZ)
FROM nginx:1.27-alpine

RUN apk add --no-cache bash gettext wget \
    && rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /etc/nginx/snippets /etc/nginx/includes /var/lib/sso-portal/exports \
    && mkdir -p /var/www/nginx-errors

COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/ /etc/nginx/conf.d/
COPY snippets/ /etc/nginx/snippets/
COPY includes/ /etc/nginx/includes/
COPY templates/ /etc/nginx/templates-portal/
COPY docker-entrypoint.sh /docker-entrypoint-portal.sh
COPY errors/ /var/www/nginx-errors/

RUN chmod +x /docker-entrypoint-portal.sh

EXPOSE 8080

ENTRYPOINT ["/docker-entrypoint-portal.sh"]
CMD ["nginx", "-g", "daemon off;"]
