"""The daily quarantine digest: one email per person listing what was held for them, with release links."""
from __future__ import annotations

import os
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import links, mailer

LABELS = {"spam": "Spam", "phish": "Phishing", "virus": "Virus", "impostor": "Possible impostor", "blocked": "Blocked sender"}

_env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")),
                   autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)


def build(cfg, secret: bytes, recipient: str, items: list, now: float | None = None) -> EmailMessage:
    now = now or time.time()
    base = cfg.digest.public_url.rstrip("/")
    days = cfg.digest.link_days
    rows = []
    for item in items:
        releasable = item["category"] in cfg.filter.user_release
        rows.append({
            "when": time.strftime("%b %d, %H:%M", time.localtime(item["ts"])),
            "sender": item["from_header"] or item["sender"] or "(no sender)",
            "subject": item["subject"] or "(no subject)",
            "label": LABELS.get(item["category"], item["category"]),
            "release": f"{base}/r/{links.sign(secret, 'release', [item['id'], recipient], days, now)}" if releasable else "",
        })
    page = f"{base}/u/{links.sign(secret, 'user', [recipient], days, now)}"
    ctx = {"rows": rows, "page": page, "recipient": recipient, "days": days, "count": len(rows)}
    msg = EmailMessage()
    msg["From"] = cfg.digest.sender
    msg["To"] = recipient
    msg["Subject"] = f"{len(rows)} message{'s' if len(rows) != 1 else ''} held for you"
    msg["Date"] = formatdate(now, localtime=True)
    msg["Message-ID"] = make_msgid(domain=cfg.gateway.hostname)
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Tidegate-Digest"] = "1"
    msg.set_content(_env.get_template("digest.txt").render(**ctx))
    msg.add_alternative(_env.get_template("digest.html").render(**ctx), subtype="html")
    return msg


def due(cfg, store, now: float | None = None) -> dict[str, list]:
    """Held items per recipient that came in since that person's last digest (or the last day, for a first digest)."""
    now = now or time.time()
    out: dict[str, list] = {}
    for item in store.quarantine_list(status="held", since=int(now - 86400 * 7), limit=100000):
        if item["category"] not in cfg.filter.user_release:
            continue
        last = float(store.state_get(f"digest:{item['recipient']}", "0") or 0)
        if item["ts"] > max(last, now - 86400):
            out.setdefault(item["recipient"], []).append(item)
    return out


def run(cfg, store, secret: bytes, now: float | None = None, send=mailer.reinject) -> int:
    if not (cfg.digest.enabled and cfg.digest.sender and cfg.digest.public_url):
        return 0
    now = now or time.time()
    sent = 0
    for recipient, items in sorted(due(cfg, store, now).items()):
        items.sort(key=lambda i: i["ts"], reverse=True)
        msg = build(cfg, secret, recipient, items[:200], now)
        sender_addr = msg["From"].addresses[0].addr_spec
        send(msg.as_bytes(), sender_addr, [recipient], cfg.smtp.reinject_host, cfg.smtp.reinject_port)
        store.state_set(f"digest:{recipient}", str(now))
        sent += 1
    return sent
