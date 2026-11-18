"""Command line tools: `python3 -m tidegate.cli <command>` inside the web container (docker compose exec web ...)."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
import time

from . import config, digest, impostor, links
from .store import Store
from .web import hash_password


def stats(store: Store, hours: int, now: float | None = None) -> dict:
    """What monitoring may see: counts, and the sender DOMAINS of held mail. Never addresses, names or subjects."""
    since = int((now or time.time()) - hours * 3600)
    results = {"delivered": 0, "tagged": 0, "warned": 0, "unscanned": 0, "observed": 0, "held": 0}
    held = {c: 0 for c in config.CATEGORIES}
    domains: set[str] = set()
    for row in store.messages(since, limit=1_000_000):
        verdict = row["verdict"] or ""
        if verdict.startswith("quarantine:"):
            category = verdict.split(":", 1)[1]
            results["held"] += 1
            held[category] = held.get(category, 0) + 1
            senders = impostor.addresses(row["from_header"]) if row["from_header"] else []
            address = senders[0][1] if senders else (row["sender"] or "")
            domains.add(impostor.domain_of(address) if "@" in address else "(none)")
            continue
        parts = verdict.split("+")
        results["delivered"] += 1
        results["tagged"] += "tag" in parts
        results["warned"] += "warn" in parts
        results["unscanned"] += "unscanned" in parts
        results["observed"] += any(p.startswith("observe-") for p in parts)
    return {"hours": hours, "results": results, "held_by_category": held,
            "held_sender_domains": sorted(domains)[:20], "held_now": sum(store.held_count().values())}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tidegate")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("passwd", help="print a password hash for TIDEGATE_ADMIN_PASSWORD_HASH")
    m = sub.add_parser("messages", help="recent log rows as JSON")
    m.add_argument("--minutes", type=int, default=60)
    m.add_argument("--query", default="")
    q = sub.add_parser("quarantine", help="quarantine items as JSON")
    q.add_argument("--status", default="held")
    lk = sub.add_parser("link", help="print a release link for a quarantine item")
    lk.add_argument("id", type=int)
    sub.add_parser("digest", help="send digests now for everything due")
    sp = sub.add_parser("stats", help="counts for monitoring, as JSON: no addresses, names or subjects")
    sp.add_argument("--hours", type=int, default=24)
    pa = sub.add_parser("policy-add", help="add an allow or block entry")
    pa.add_argument("kind", choices=["allow", "block"])
    pa.add_argument("pattern")
    pa.add_argument("--recipient", default="")
    sub.add_parser("check-config", help="load tidegate.toml and report problems")
    args = p.parse_args(argv)

    if args.cmd == "passwd":
        first = getpass.getpass("New admin password: ")
        if len(first) < 12:
            print("Use at least 12 characters.", file=sys.stderr)
            return 1
        if getpass.getpass("Again: ") != first:
            print("The two entries differ.", file=sys.stderr)
            return 1
        print(hash_password(first))
        return 0

    cfg = config.load()
    if args.cmd == "check-config":
        print(f"OK: filtering {', '.join(cfg.gateway.domains)}; quarantining {', '.join(cfg.filter.quarantine_categories)}")
        return 0
    store = Store(cfg.paths.data)
    if args.cmd == "messages":
        rows = store.messages(int(time.time()) - args.minutes * 60, args.query, limit=10000)
        print(json.dumps([dict(r) for r in rows], indent=1))
    elif args.cmd == "quarantine":
        print(json.dumps([dict(r) for r in store.quarantine_list(status=args.status, limit=10000)], indent=1))
    elif args.cmd == "link":
        item = store.quarantine_get(args.id)
        if item is None:
            print("no such item", file=sys.stderr)
            return 1
        token = links.sign(config.secret_key(), "release", [item["id"], item["recipient"]], cfg.digest.link_days)
        print(f"{cfg.digest.public_url.rstrip('/')}/r/{token}")
    elif args.cmd == "digest":
        print(f"{digest.run(cfg, store, config.secret_key())} digest(s) sent")
    elif args.cmd == "stats":
        print(json.dumps(stats(store, args.hours)))
    elif args.cmd == "policy-add":
        store.policy_add(args.kind, args.pattern, args.recipient, note="added from the command line", by="cli")
        print(f"{args.kind} {args.pattern} added")
    return 0


if __name__ == "__main__":
    sys.exit(main())
