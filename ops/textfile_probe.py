#!/usr/bin/env python3
"""Tidegate health for Prometheus (node-exporter textfile collector), plus one summary line for a status board.

Run it from cron every 5 minutes on the Docker host, as a user allowed to run docker (and postqueue, which any user
may run). It never changes anything. It writes the metrics file atomically and prints one line that starts with
OK, REVIEW, HELD, STUCK or DOWN.

  python3 ops/textfile_probe.py --textfile /var/lib/node_exporter/textfile/tidegate.prom \\
      [--project tidegate] [--inbound-domain example.com ...] [--front-postfix]

--front-postfix: Tidegate sits behind this host's own Postfix (docs/existing-postfix.md). The probe then reports
whether that Postfix sends mail through Tidegate yet (tidegate_in_mail_path), and how old the oldest message for
--inbound-domain waiting in that Postfix's queue is. Mail stuck there never reaches the mailbox either.
Only counts and the sender DOMAINS of held mail are reported: never addresses, names or subjects.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

STUCK_AFTER = 900   # seconds; the alert rules use the same 15 minutes
QUEUES = ("incoming", "active", "deferred", "hold", "maildrop")
CATEGORIES = ("virus", "phish", "impostor", "blocked", "spam")


def tool(name: str) -> str:
    return shutil.which(name) or next((p for p in (f"/usr/sbin/{name}", f"/usr/bin/{name}") if os.path.exists(p)), name)


def run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None


def queue(cmd: list[str]) -> list[dict] | None:
    """postqueue -j output as a list, or None when the command failed."""
    out = run(cmd)
    if out is None or out.returncode != 0:
        return None
    items = []
    for line in out.stdout.splitlines():
        if line.startswith("{"):
            try:
                items.append(json.loads(line))
            except ValueError:
                pass
    return items


def oldest_age(items: list[dict], now: float) -> float:
    times = [i.get("arrival_time") for i in items if isinstance(i.get("arrival_time"), (int, float))]
    return max(0.0, now - min(times)) if times else 0.0


def for_domains(items: list[dict], domains: list[str]) -> list[dict]:
    def match(address: str) -> bool:
        d = address.rpartition("@")[2].lower()
        return any(d == x or d.endswith("." + x) for x in domains)
    return [i for i in items if any(match(r.get("address", "")) for r in i.get("recipients", []))]


def probe(a, now: float) -> tuple[list[str], str]:
    m: list[str] = []

    def metric(name: str, help_text: str, samples: list[tuple[str, float]]) -> None:
        m.append(f"# HELP {name} {help_text}")
        m.append(f"# TYPE {name} gauge")
        m.extend(f"{name}{labels} {value:.15g}" for labels, value in samples)   # full precision: timestamps are 10 digits

    in_path = 1
    host_items: list[dict] | None = []
    if a.front_postfix:
        out = run([tool("postconf"), "-h", "smtpd_recipient_restrictions"])
        in_path = int(bool(out) and "tidegate_filter" in out.stdout)
        host_items = queue([tool("postqueue"), "-j"])
    metric("tidegate_in_mail_path", "1 when mail from outside goes through Tidegate.", [("", in_path)])

    docker = tool("docker")
    tg_items = queue([docker, "exec", f"{a.project}-mta-1", "postqueue", "-j"])
    up = int(tg_items is not None)
    metric("tidegate_up", "1 when Tidegate's mta container answered this probe.", [("", up)])
    stuck = []
    if tg_items is not None:
        counts = {q: 0 for q in QUEUES}
        for item in tg_items:
            counts[item.get("queue_name", "?")] = counts.get(item.get("queue_name", "?"), 0) + 1
        age = oldest_age(tg_items, now)
        metric("tidegate_queue_messages", "Messages in Tidegate's own Postfix queue.",
               [(f'{{queue="{q}"}}', n) for q, n in sorted(counts.items())])
        metric("tidegate_queue_oldest_age_seconds", "Age of the oldest message in Tidegate's queue (0 when empty).",
               [("", age)])
        if age > STUCK_AFTER:
            stuck.append(f"{len(tg_items)} in Tidegate's queue, oldest {age / 60:.0f} min")
    if a.front_postfix and host_items is not None:
        inbound = for_domains(host_items, a.inbound_domain)
        age = oldest_age(inbound, now)
        metric("tidegate_host_inbound_messages", "Messages for the inbound domains waiting in the front Postfix's queue.",
               [("", len(inbound))])
        metric("tidegate_host_inbound_oldest_age_seconds", "Age of the oldest of those messages (0 when none).",
               [("", age)])
        if age > STUCK_AFTER:
            stuck.append(f"{len(inbound)} inbound waiting in this server's Postfix, oldest {age / 60:.0f} min")

    stats = None
    if up:
        out = run([docker, "exec", f"{a.project}-web-1", "python3", "-I", "-m", "tidegate.cli", "stats", "--hours", "24"])
        try:
            stats = json.loads(out.stdout) if out and out.returncode == 0 else None
        except ValueError:
            stats = None
    if stats:
        r, held = stats["results"], stats["held_by_category"]
        metric("tidegate_messages_24h", "Messages handled in the last 24 hours, by result.",
               [(f'{{result="{k}"}}', v) for k, v in sorted(r.items())])
        metric("tidegate_held_24h", "Messages held in the last 24 hours, by category.",
               [(f'{{category="{c}"}}', held.get(c, 0)) for c in CATEGORIES])
        metric("tidegate_held_now", "Messages in the quarantine now.", [("", stats["held_now"])])
    metric("tidegate_probe_timestamp_seconds", "When this probe last ran.", [("", int(now))])

    if stats:
        held_text = ", ".join(f"{c} {n}" for c, n in held.items() if n)
        flow = (f"{r['delivered']} delivered ({r['tagged']} tagged as spam, {r['observed']} would be held in observe mode, "
                f"{r['unscanned']} unscanned)")
    where = "in the mail path" if in_path else "standing by, not in the mail path yet"
    if in_path and not up:
        line = "DOWN: Tidegate's mta container is not answering; new mail goes around it (fail-open), mail inside it waits"
    elif stuck:
        line = "STUCK: " + "; ".join(stuck)
    elif stats and r["held"]:
        line = (f"HELD: {r['held']} held in 24 h ({held_text}) from {', '.join(stats['held_sender_domains']) or '?'}; "
                f"{flow}; {where}")
    elif stats and r["observed"]:
        # Observe mode let something through that the settings would hold (filter.quarantine_categories): not OK, so a
        # person compares it with the mail that matters before holding is turned on.
        line = f"REVIEW: {r['observed']} in 24 h would have been held (observe mode); {flow}; {where}"
    elif stats:
        line = f"OK: {where}; 24 h: {flow}; nothing held; queue empty"
    else:
        line = f"OK: {where}; Tidegate is not running" if not in_path else "DOWN: no statistics from Tidegate"
    return m, line


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--textfile", required=True)
    p.add_argument("--project", default="tidegate")
    p.add_argument("--inbound-domain", action="append", default=[])
    p.add_argument("--front-postfix", action="store_true")
    a = p.parse_args(argv)
    a.inbound_domain = [d.lower() for d in a.inbound_domain]
    lines, summary = probe(a, time.time())
    folder = os.path.dirname(os.path.abspath(a.textfile))
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".tidegate.", suffix=".tmp")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, a.textfile)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
