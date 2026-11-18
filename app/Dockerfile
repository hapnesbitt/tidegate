# Tidegate's own image: Postfix plus the Python filter, web console and scheduler (Debian packages only, no pip).
FROM debian:trixie-slim
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends postfix ca-certificates openssl tini \
      python3 python3-flask python3-jinja2 python3-waitress \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1500 tidegate \
 && useradd --system --uid 1500 --gid 1500 --home-dir /data --no-create-home --shell /usr/sbin/nologin tidegate
COPY tidegate /usr/lib/python3/dist-packages/tidegate
COPY bin/ /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/tidegate-filter \
 && python3 -m compileall -q /usr/lib/python3/dist-packages/tidegate
EXPOSE 25 8080
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["mta"]
