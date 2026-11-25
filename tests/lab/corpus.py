#!/usr/bin/env python3
"""Run public spam, phishing and normal mail through a running lab stack and count what Tidegate did with each set.

  python3 tests/lab/corpus.py --set ham=DIR --set spam=DIR --set phish=MBOX [--limit 500] [--seed 1]

Each message goes to the lab gateway unchanged, to <set>-<run>-<n>@example.com, so the results can be matched; the
lab delivers example.com to Mailpit and nothing leaves the lab. It comes from the lab network, so Rspamd treats the
client as local: the results measure content, headers and links, not the original senders' long-gone IP addresses.
"""
from __future__ import annotations

import argparse
import json
import mailbox
import os
import random
import smtplib
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

COMPOSE = ["docker", "compose", "--env-file", "tests/lab/lab.env", "-f", "docker-compose.yml", "-f",
           "tests/lab/compose.lab.yml"]


def load(spec: str, limit: int, rng: random.Random) -> tuple[str, list[bytes]]:
    name, _, path = spec.partition("=")
    if os.path.isdir(path):
        files = sorted(f for f in os.listdir(path) if not f.startswith(".") and f != "cmds")
        rng.shuffle(files)
        msgs = []
        for f in files[:limit]:
            with open(os.path.join(path, f), "rb") as fh:
                msgs.append(fh.read())
    else:
        msgs = [m.as_bytes() for m in mailbox.mbox(path)]
        rng.shuffle(msgs)
        msgs = msgs[:limit]
    return name, msgs


def send(raw: bytes, rcpt: str, host: str, port: int) -> str:
    data = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    opts = ["BODY=8BITMIME"] if any(b > 127 for b in data) else []
    try:
        with smtplib.SMTP(host, port, timeout=120) as s:
            s.ehlo("corpus.lab-sender.test")
            s.sendmail("corpus@lab-sender.test", [rcpt], data, mail_options=opts)
        return "sent"
    except smtplib.SMTPException as e:
        return f"refused: {str(e)[:80]}"


def log_rows(minutes: int) -> list[dict]:
    out = subprocess.run(COMPOSE + ["exec", "-T", "web", "python3", "-I", "-m", "tidegate.cli", "messages", "--minutes",
                                    str(minutes)], capture_output=True, text=True, stdin=subprocess.DEVNULL)
    return json.loads(out.stdout or "[]")


def bucket(verdict: str) -> str:
    if verdict.startswith("quarantine:"):
        return "held " + verdict.split(":", 1)[1]
    parts = verdict.split("+")
    if "tag" in parts:
        return "delivered, tagged as possible spam"
    if "warn" in parts:
        return "delivered with a warning"
    return "delivered clean"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--set", action="append", required=True, help="name=DIR (one message per file) or name=MBOX")
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--host", default="172.31.241.25")
    p.add_argument("--port", type=int, default=25)
    p.add_argument("--out", default="")
    a = p.parse_args()
    rng = random.Random(a.seed)
    run = time.strftime("%H%M%S")
    started = time.time()
    sets = dict(load(s, a.limit, rng) for s in a.set)
    sent: dict[str, dict[str, str]] = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        for name, msgs in sets.items():
            rcpts = [f"{name}-{run}-{i}@example.com" for i in range(len(msgs))]
            sent[name] = dict(zip(rcpts, pool.map(lambda m_r: send(m_r[0], m_r[1], a.host, a.port), zip(msgs, rcpts))))
            print(f"{name}: sent {sum(v == 'sent' for v in sent[name].values())} of {len(msgs)}", flush=True)
    want = {r for d in sent.values() for r, v in d.items() if v == "sent"}
    seen: dict[str, dict] = {}
    deadline = time.time() + 3600
    while time.time() < deadline:
        minutes = int((time.time() - started) / 60) + 5
        seen = {r["recipient"]: r for r in log_rows(minutes) if r["recipient"] in want}
        if len(seen) >= len(want):
            break
        print(f"  waiting: {len(seen)} of {len(want)} filtered", flush=True)
        time.sleep(30)
    results = {}
    for name, d in sent.items():
        counts: dict[str, int] = {}
        for rcpt, status in d.items():
            key = bucket(seen[rcpt]["verdict"]) if rcpt in seen else ("refused by Postfix" if status != "sent" else "not filtered in time")
            counts[key] = counts.get(key, 0) + 1
        scores = sorted(seen[r]["score"] for r in d if r in seen)
        results[name] = {"messages": len(d), "counts": dict(sorted(counts.items())),
                         "median_score": scores[len(scores) // 2] if scores else None}
        print(f"\n{name} ({len(d)} messages, median score {results[name]['median_score']}):")
        for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"  {v:5d}  {100 * v / len(d):5.1f}%  {k}")
    if a.out:
        with open(a.out, "w") as fh:
            json.dump({"run": run, "seconds": round(time.time() - started), "sets": results}, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
