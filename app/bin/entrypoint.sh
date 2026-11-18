#!/bin/sh
set -eu
role="${1:-mta}"
case "$role" in
  mta)
    install -d -o tidegate -g tidegate -m 0750 /data
    install -d -o tidegate -g tidegate -m 0700 /data/quarantine
    if [ ! -f /certs/fullchain.pem ] && [ ! -f /var/lib/tidegate-tls/selfsigned.pem ]; then
      install -d -m 0700 /var/lib/tidegate-tls
      openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$(hostname)" \
        -keyout /var/lib/tidegate-tls/selfsigned.key -out /var/lib/tidegate-tls/selfsigned.pem 2>/dev/null
    fi
    python3 -I -m tidegate.render_postfix
    # The filter runs as the tidegate user: it must be able to read the config, and the database must be its own.
    runuser -u tidegate -- python3 -I -m tidegate.cli check-config >/dev/null
    rm -f /var/spool/postfix/pid/master.pid
    postfix check
    exec postfix start-fg
    ;;
  web) exec python3 -I -m tidegate.web ;;
  scheduler) exec python3 -I -m tidegate.scheduler ;;
  cli) shift; exec python3 -I -m tidegate.cli "$@" ;;
  *) exec "$@" ;;
esac
