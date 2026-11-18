"""Background jobs: the digests at the configured hours, and nightly removal of old quarantine items and log rows."""
from __future__ import annotations

import sys
import time
import traceback

from . import config, digest
from .store import Store


def tick(cfg, store: Store, secret: bytes, now: float) -> None:
    local = time.localtime(now)
    today = time.strftime("%Y-%m-%d", local)
    for hour in sorted(cfg.digest.hours):
        key = f"digest_slot:{today}:{hour:02d}"
        if local.tm_hour >= hour and not store.state_get(key):
            store.state_set(key, "running")
            sent = digest.run(cfg, store, secret, now)
            store.state_set(key, f"sent {sent}")
            store.state_set("digest_run", f"{time.strftime('%Y-%m-%d %H:%M', local)}: {sent} digest(s) sent")
            print(f"tidegate scheduler: digest slot {today} {hour:02d}:00 sent {sent}", flush=True)
    if store.state_get("cleanup_day") != today and local.tm_hour >= 3:
        held, logs = store.cleanup(cfg.retention.quarantine_days, cfg.retention.log_days, now)
        store.state_set("cleanup_day", today)
        print(f"tidegate scheduler: cleanup removed {held} quarantine item(s) and {logs} log row(s)", flush=True)


def main() -> None:
    cfg = config.load()
    secret = config.secret_key()
    store = Store(cfg.paths.data)
    print("tidegate scheduler: started", flush=True)
    while True:
        try:
            tick(cfg, store, secret, time.time())
        except Exception:
            traceback.print_exc(file=sys.stderr)
        time.sleep(60)


if __name__ == "__main__":
    main()
