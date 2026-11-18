#!/usr/bin/env python3
"""Replica checks: Tidegate behind an existing Postfix (the edge container). Run by tests/replica/run.sh."""
from __future__ import annotations

import json
import os
import re
import smtplib
import subprocess
import sys
import time
from email.message import EmailMessage

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
RUN = time.strftime("%H%M%S")
BASE = ["docker", "compose", "--env-file", "tests/replica/replica.env", "-f", "docker-compose.yml", "-f",
        "tests/lab/compose.lab.yml", "-f", "tests/replica/compose.replica.yml"]
# The test a mail client on the real server uses to recognize "a local program submitted this" (Callback's
# LOCAL_SUBMIT), with the replica's host name. Mail from outside must never match it, on any path.
LOCAL_SUBMIT = re.compile(r"^by mail\.arc-codex\.test \(Postfix, from userid \d+\)|"
                          r"^from \S+ \(localhost \[127\.0\.0\.1\]\) by mail\.arc-codex\.test ", re.I)
READER = r"""
import json, os
from email import policy
from email.parser import BytesParser
out = []
for sub in ("new", "cur"):
    d = "/home/ross/Maildir/" + sub
    for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        with open(os.path.join(d, name), "rb") as fh:
            m = BytesParser(policy=policy.default).parsebytes(fh.read(65536), headersonly=True)
        rec = m.get_all("Received") or [""]
        out.append({"subject": str(m["Subject"] or ""), "top": " ".join(str(rec[0]).split()),
                    "verdicts": [str(v) for v in m.get_all("X-Tidegate-Verdict") or []],
                    "delivered_to": str(m["Delivered-To"] or "")})
print(json.dumps(out))
"""
results: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}{'  - ' + detail if detail else ''}", flush=True)
    return ok


def dc(*args: str, env: dict | None = None, data: str | None = None) -> str:
    out = subprocess.run(BASE + list(args), capture_output=True, text=True, input=data,
                         stdin=None if data is not None else subprocess.DEVNULL, env={**os.environ, **(env or {})})
    if out.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {out.stderr.strip()[-300:]}")
    return out.stdout


def send(subject: str, to: str, *, attach: bytes | None = None, pad: int = 0) -> str:
    subject = f"{subject} {RUN}"
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "Alice Example <alice@example.net>", to, subject
    m["Message-ID"] = f"<{abs(hash(subject))}@tester.example.net>"
    m.set_content("Hello Ross,\n\nA message for the replica test.\n" + ("x" * 75 + "\n") * (pad // 76))
    if attach:
        m.add_attachment(attach, maintype="application", subtype="octet-stream", filename="file.com")
    with smtplib.SMTP("172.31.241.20", 25, timeout=60) as s:   # the edge, on the lab network
        s.ehlo("tester.example.net")
        code, resp = s.docmd("XCLIENT", "ADDR=203.0.113.20 NAME=mail.example.net HELO=mail.example.net")
        if code != 220:
            raise RuntimeError(f"XCLIENT refused: {code} {resp!r}")
        s.ehlo("mail.example.net")
        s.send_message(m, from_addr="alice@example.net", to_addrs=[to])
    return subject


def maildir() -> list[dict]:
    return json.loads(dc("exec", "-T", "edge", "python3", "-c", READER))


def wait_for(subject: str, timeout: int = 90) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        for m in maildir():
            if m["subject"] == subject:
                return m
        time.sleep(3)
    return None


def main() -> int:
    # 1. Mail from outside goes through Tidegate exactly once and comes back into the Maildir.
    for to in ("ross@arc-codex.test", "hap@arc-codex.test"):
        subject = send("clean", to)
        m = wait_for(subject)
        if check(f"outside mail to {to} delivered", m is not None):
            check(f"  passed Tidegate exactly once ({to})", len(m["verdicts"]) == 1, str(m["verdicts"]))
            check(f"  top Received is Tidegate's delivery ({to})", "172.31.241.25" in m["top"], m["top"][:120])
            check(f"  does not look like a local submission ({to})", not LOCAL_SUBMIT.search(m["top"]))
            check(f"  Delivered-To is ross ({to})", m["delivered_to"] == "ross@arc-codex.test", m["delivered_to"])
    rows = json.loads(dc("exec", "-T", "web", "python3", "-I", "-m", "tidegate.cli", "messages", "--minutes", "30"))
    ips = {r["client_ip"] for r in rows if RUN in (r["subject"] or "")}
    check("Tidegate saw the original client address (XFORWARD)", ips == {"203.0.113.20"}, str(ips))

    # 2. A virus is held in Tidegate and never reaches the Maildir.
    subject = send("virus", "ross@arc-codex.test", attach=EICAR.encode())
    time.sleep(25)
    check("virus not delivered", not any(m["subject"] == subject for m in maildir()))
    held = json.loads(dc("exec", "-T", "web", "python3", "-I", "-m", "tidegate.cli", "quarantine"))
    check("virus held in Tidegate's quarantine", any(q["subject"] == subject and q["category"] == "virus" for q in held))

    # 3. Local programs' mail skips Tidegate (sendmail, and SMTP from localhost).
    dc("exec", "-T", "edge", "sh", "-c",
       f"printf 'From: ross@arc-codex.test\\nTo: ross@arc-codex.test\\nSubject: local sendmail {RUN}\\n\\nhi\\n' | "
       "runuser -u ross -- /usr/sbin/sendmail -t -oi -f ross@arc-codex.test")
    dc("exec", "-T", "edge", "python3", "-c",
       "import smtplib; s = smtplib.SMTP('127.0.0.1', 25); "
       f"s.sendmail('ross@arc-codex.test', ['ross@arc-codex.test'], 'Subject: local smtp {RUN}\\r\\n\\r\\nhi\\r\\n'); s.quit()")
    for kind in ("local sendmail", "local smtp"):
        m = wait_for(f"{kind} {RUN}", 30)
        if check(f"{kind} delivered", m is not None):
            check(f"  {kind} skipped Tidegate", m["verdicts"] == [], str(m["verdicts"]))
            check(f"  {kind} still looks like a local submission", bool(LOCAL_SUBMIT.search(m["top"])), m["top"][:100])

    # 4. A refusal from Tidegate (here: a message over its size limit) never bounces: the edge delivers it through
    #    the fail-open path instead (unscanned, and still not looking like a local submission).
    subject = send("too large", "ross@arc-codex.test", pad=300_000)
    m = wait_for(subject, 120)
    queue = dc("exec", "-T", "edge", "postqueue", "-j")
    entries = [json.loads(line) for line in queue.splitlines() if line.strip()]
    check("a message Tidegate refused is delivered by the fail-open path", m is not None and m["verdicts"] == [],
          f"queued: {[e['recipients'][0].get('delay_reason', '')[:80] for e in entries]}")
    check("  and it does not look like a local submission", m is not None and not LOCAL_SUBMIT.search(m["top"]),
          m["top"][:120] if m else "")
    check("no bounce was generated", not any(e.get("sender") == "" for e in entries))
    dc("exec", "-T", "edge", "postsuper", "-d", "ALL")

    # 5. Tidegate down: mail goes straight in (fail-open), and still doesn't look like a local submission.
    dc("stop", "mta")
    dc("exec", "-T", "edge", "sh", "-c", "kill $(cat /run/forward.pid)")   # the published port goes away with the container
    try:
        subject = send("tidegate down", "ross@arc-codex.test")
        m = wait_for(subject, 150)
        if check("with Tidegate down, mail still arrives", m is not None):
            check("  it skipped Tidegate", m["verdicts"] == [], str(m["verdicts"]))
            check("  it does not look like a local submission", not LOCAL_SUBMIT.search(m["top"]), m["top"][:120])
            check("  it came in through 127.0.0.2", "[127.0.0.2]" in m["top"], m["top"][:120])
    finally:
        dc("start", "mta")
        dc("exec", "-d", "edge", "python3", "/edge/forward.py")
        time.sleep(8)

    # 6. Rspamd down: Tidegate delivers unscanned and says so (fail_mode = "open").
    dc("stop", "rspamd")
    try:
        subject = send("rspamd down", "ross@arc-codex.test")
        m = wait_for(subject, 90)
        check("with Rspamd down, mail arrives marked unscanned", m is not None and m["verdicts"] and
              "unscanned" in m["verdicts"][0], str(m["verdicts"] if m else None))
    finally:
        dc("start", "rspamd")

    # 7. Rollback: the edge without the three changes delivers directly again.
    dc("up", "-d", "edge", env={"EDGE_MODE": "before"})
    time.sleep(6)
    subject = send("after rollback", "ross@arc-codex.test")
    m = wait_for(subject, 60)
    check("after rollback, mail arrives without Tidegate", m is not None and m["verdicts"] == [])

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} of {len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
