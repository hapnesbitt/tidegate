# A small recursive resolver for Rspamd: DNS blocklists refuse queries that come through big public resolvers.
FROM alpine:3.22
RUN apk add --no-cache unbound dns-root-hints \
 && install -d -o unbound -g unbound /var/lib/unbound
COPY unbound.conf /etc/unbound/unbound.conf
EXPOSE 53/udp 53/tcp
CMD ["sh", "-c", "unbound-anchor -a /var/lib/unbound/root.key; chown unbound:unbound /var/lib/unbound/root.key; exec unbound -d -c /etc/unbound/unbound.conf"]
