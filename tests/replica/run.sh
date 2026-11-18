#!/usr/bin/env bash
# Replica test: Tidegate behind an existing Postfix (the edge container). Needs the lab stack up.
set -euo pipefail
cd "$(dirname "$0")/../.."
cp tests/lab/lab.env tests/replica/replica.env
sed -i 's|^TIDEGATE_CONFIG_DIR=.*|TIDEGATE_CONFIG_DIR=./tests/replica/config|' tests/replica/replica.env
DC=(docker compose --env-file tests/replica/replica.env -f docker-compose.yml -f tests/lab/compose.lab.yml -f tests/replica/compose.replica.yml)
"${DC[@]}" up -d mta web scheduler edge
sleep 8
status=0
python3 tests/replica/replica.py || status=$?
# Put the lab back the way it was.
"${DC[@]}" rm -sf edge >/dev/null
docker compose --env-file tests/lab/lab.env -f docker-compose.yml -f tests/lab/compose.lab.yml up -d mta web scheduler >/dev/null
exit $status
