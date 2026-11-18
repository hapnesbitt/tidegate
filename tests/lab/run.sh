#!/usr/bin/env bash
# The lab: build Tidegate, start it with Mailpit behind it, run the unit tests and the mail scenarios.
#   tests/lab/run.sh up      build and start (first run writes tests/lab/lab.env with fresh secrets)
#   tests/lab/run.sh test    unit tests + scenarios
#   tests/lab/run.sh down    stop and delete the lab's containers and volumes
set -euo pipefail
cd "$(dirname "$0")/../.."
ENV=tests/lab/lab.env
DC=(docker compose --env-file "$ENV" -f docker-compose.yml -f tests/lab/compose.lab.yml)

new_env() {
  local pw hash
  cp tests/lab/lab.env.example "$ENV"
  pw=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')
  hash=$(python3 - "$pw" <<'PY'
import base64, hashlib, secrets, sys
b = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=").decode()
salt = secrets.token_bytes(16)
key = hashlib.scrypt(sys.argv[1].encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
print(f"scrypt:{2**15}:8:1:{b(salt)}:{b(key)}")
PY
)
  {
    echo "TIDEGATE_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
    echo "TIDEGATE_ADMIN_PASSWORD_HASH=$hash"
    echo "LAB_ADMIN_PASSWORD=$pw"
  } >> "$ENV"
  chmod 600 "$ENV"
}

wait_healthy() {
  local id status
  id=$("${DC[@]}" ps -q clamav)
  for _ in $(seq 1 120); do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$id" 2>/dev/null || echo starting)
    [ "$status" = healthy ] && { echo "clamav is ready"; return 0; }
    sleep 5
  done
  echo "clamav did not become healthy in 10 minutes" >&2
  return 1
}

case "${1:-test}" in
  up)
    [ -f "$ENV" ] || new_env
    "${DC[@]}" build
    "${DC[@]}" up -d
    wait_healthy
    ;;
  test)
    docker run --rm --network none -v "$PWD/app/tests:/tests:ro" --entrypoint python3 tidegate:0.1.0 \
      -m unittest discover -s /tests
    python3 tests/lab/scenarios.py --env-file "$ENV" --admin-password "$(grep '^LAB_ADMIN_PASSWORD=' "$ENV" | cut -d= -f2-)"
    ;;
  down)
    "${DC[@]}" down -v
    ;;
  *)
    echo "usage: $0 up|test|down" >&2
    exit 2
    ;;
esac
