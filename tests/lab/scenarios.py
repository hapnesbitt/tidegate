#!/usr/bin/env python3
"""Lab checks: send test messages through a running lab stack and check where each one ended up.

Run from the repository root after `tests/lab/run.sh up`. Uses only the standard library. Every message goes to
example.com addresses, which the lab delivers to Mailpit; the lab gateway sends nothing anywhere else.
"""
from __future__ import annotations

import argparse
import base64
import http.cookiejar
import json
import re
import smtplib
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage

# Industry-standard test strings, built at run time so this file itself never looks like a threat to a scanner.
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
GTUBE_TAIL = "JS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
GTUBE_REJECT, GTUBE_ADD_HEADER = "X" + GTUBE_TAIL, "Y" + GTUBE_TAIL

RUN = time.strftime("%H%M%S")
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}{'  - ' + detail if detail else ''}", flush=True)
    return ok


class Lab:
    def __init__(self, args):
        self.a = args
        self.compose = ["docker", "compose", "--env-file", args.env_file, "-f", "docker-compose.yml", "-f",
                        "tests/lab/compose.lab.yml"]
        self.jar = http.cookiejar.CookieJar()
        self.http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    # --- plumbing --------------------------------------------------------------------------------------------
    def dc(self, *args: str, check_rc: bool = True) -> str:
        out = subprocess.run(self.compose + list(args), capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if check_rc and out.returncode != 0:
            raise RuntimeError(f"docker compose {' '.join(args)} failed: {out.stderr.strip()[-400:]}")
        return out.stdout

    def cli(self, *args: str):
        out = self.dc("exec", "-T", "web", "python3", "-I", "-m", "tidegate.cli", *args)
        return json.loads(out) if args[0] in ("messages", "quarantine") else out.strip()

    def send(self, msg: EmailMessage | bytes, sender: str, rcpts: list[str], ip: str | None = "203.0.113.10",
             helo: str = "mail.example.net", port: int | None = None) -> None:
        with smtplib.SMTP(self.a.smtp_host, port or self.a.smtp_port, timeout=60) as s:
            s.ehlo("tester.example.net")
            if ip:
                code, resp = s.docmd("XCLIENT", f"ADDR={ip} NAME={helo} HELO={helo}")
                if code != 220:
                    raise RuntimeError(f"XCLIENT refused: {code} {resp!r}")
                s.ehlo(helo)
            if isinstance(msg, bytes):
                s.sendmail(sender, rcpts, msg)
            else:
                s.send_message(msg, from_addr=sender, to_addrs=rcpts)

    def wait_log(self, rcpts: list[str], timeout: int = 180) -> dict[str, dict]:
        want = {r.lower() for r in rcpts}
        deadline = time.time() + timeout
        seen: dict[str, dict] = {}
        while time.time() < deadline:
            for row in self.cli("messages", "--minutes", "120"):
                if row["recipient"] in want and row["recipient"] not in seen:
                    seen[row["recipient"]] = row
            if len(seen) == len(want):
                break
            time.sleep(3)
        return seen

    def mailpit(self, path: str):
        with urllib.request.urlopen(self.a.mailpit + path, timeout=30) as r:
            return json.load(r)

    def inbox(self, rcpt: str, timeout: int = 60) -> list[dict]:
        deadline = time.time() + timeout
        while True:
            found = [m for m in self.mailpit("/api/v1/messages?limit=1000")["messages"]
                     if any(t["Address"].lower() == rcpt.lower() for t in m["To"] or [])]
            if found or time.time() > deadline:
                return found
            time.sleep(2)

    def web(self, path: str, data: dict | None = None) -> tuple[int, str]:
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(self.a.web + path, data=body)
        try:
            with self.http.open(req, timeout=30) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")


def message(sender_header: str, to: str, subject: str, body: str, **headers) -> EmailMessage:
    m = EmailMessage()
    m["From"] = sender_header
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S -0700")
    m["Message-ID"] = f"<{subject.replace(' ', '-').lower()}-{RUN}@tester.example.net>"
    for k, v in headers.items():
        m[k.replace("_", "-")] = v
    m.set_content(body)
    return m


def rcpt(name: str) -> str:
    return f"{name}-{RUN}@example.com"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--env-file", default="tests/lab/lab.env")
    # The lab publishes no host ports: these are the containers' fixed addresses on the lab network.
    p.add_argument("--smtp-host", default="172.31.241.25")
    p.add_argument("--smtp-port", type=int, default=25)
    p.add_argument("--web", default="http://172.31.241.30:8080")
    p.add_argument("--mailpit", default="http://172.31.241.40:8025")
    p.add_argument("--admin-password", default="")
    p.add_argument("--skip-outage", action="store_true")
    a = p.parse_args()
    lab = Lab(a)

    # 1. Mail of each kind, sent from addresses on TEST-NET-3 (203.0.113.0/24), which no real server uses.
    cases = {}
    # Sender domains under .test have no DNS records, so no SPF or DMARC result skews the score.
    cases["clean"] = (message("Alice Example <alice@lab-sender.test>", rcpt("clean"), "Lunch on Friday",
                              "Hi Bob,\n\nAre we still on for lunch on Friday at noon?\n\nAlice\n"), "alice@lab-sender.test")
    cases["gtube"] = (message("Promo <deals@example.net>", rcpt("gtube"), "Spam test", f"Test spam.\n{GTUBE_REJECT}\n"),
                      "deals@example.net")
    cases["tag"] = (message("Promo <deals@example.net>", rcpt("tag"), "Possible spam test",
                            f"Probably spam.\n{GTUBE_ADD_HEADER}\n"), "deals@example.net")
    virus = message("Scanner Test <files@example.net>", rcpt("virus"), "Invoice attached", "See the attached file.\n")
    virus.add_attachment(EICAR.encode(), maintype="application", subtype="octet-stream", filename="invoice.com")
    cases["virus"] = (virus, "files@example.net")
    cases["spoof"] = (message("CEO <ceo@example.com>", rcpt("spoof"), "Urgent wire transfer",
                              "Please send the wire today and keep it quiet.\n"), "ceo@example.com")
    cases["vip"] = (message("Jane Smith <jane.smith.office@gmail.com>", rcpt("vip"), "Quick favor",
                            "Are you at your desk? I need you to buy gift cards for a client.\n"), "jane.smith.office@gmail.com")
    cases["lookalike"] = (message("Billing <billing@examp1e.test>", rcpt("lookalike"), "Meeting notes",
                                  "Here are the notes from Tuesday's meeting.\n"), "billing@examp1e.test")
    cases["partner"] = (message("Partner Bank <alerts@partner-banks.com>", rcpt("partner"), "Account notice",
                                "Please confirm your account details.\n"), "alerts@partner-banks.com")
    cases["blocked"] = (message("Newsletter <news@blocked-sender.example.org>", rcpt("blocked"), "Weekly news",
                                "This week's news.\n"), "news@blocked-sender.example.org")
    cases["digest"] = (message("Promo <deals@example.net>", rcpt("digest"), "Digest test",
                               f"Spam for the digest.\n{GTUBE_REJECT}\n"), "deals@example.net")

    lab.cli("policy-add", "block", "blocked-sender.example.org")
    for name, (msg, sender) in cases.items():
        lab.send(msg, sender, [msg["To"]])
    log = lab.wait_log([m["To"] for m, _ in cases.values()])

    expect = {"clean": "deliver", "gtube": "quarantine:spam", "tag": "deliver+tag", "virus": "quarantine:virus",
              "spoof": "quarantine:impostor", "vip": "quarantine:impostor", "lookalike": "deliver+warn",
              "partner": "deliver+warn", "blocked": "quarantine:blocked", "digest": "quarantine:spam"}
    for name, want in expect.items():  # "deliver" accepts any delivery; "deliver+warn" needs the warning
        row = log.get(rcpt(name).lower())
        got = row["verdict"] if row else "(not in the log)"
        ok = bool(row) and (got == want if want.startswith("quarantine") else got.startswith("deliver") and
                           all(part in got.split("+") for part in want.split("+")[1:]))
        check(f"verdict {name}", ok, f"want {want}, got {got}; score {row['score'] if row else '-'}; "
                                     f"{'; '.join(json.loads(row['reasons'] or '[]'))[:160] if row else ''}")

    # 2. Delivered mail carries Tidegate's headers; the look-alike warning reaches the body (banner on in the lab).
    clean = lab.inbox(rcpt("clean"))
    if check("clean message delivered to the mail server", len(clean) == 1):
        hdrs = lab.mailpit(f"/api/v1/message/{clean[0]['ID']}/headers")
        check("delivered message has X-Tidegate-Verdict", "X-Tidegate-Verdict" in hdrs, str(hdrs.get("X-Tidegate-Verdict")))
        check("delivered message has Authentication-Results from Rspamd", "Authentication-Results" in hdrs)
    tagged = lab.inbox(rcpt("tag"))
    check("possible spam delivered with X-Spam-Flag: YES", bool(tagged) and
          lab.mailpit(f"/api/v1/message/{tagged[0]['ID']}/headers").get("X-Spam-Flag") == ["YES"])
    look = lab.inbox(rcpt("lookalike"))
    check("look-alike message shows the warning banner", bool(look) and
          "may be from an impostor" in lab.mailpit(f"/api/v1/message/{look[0]['ID']}").get("Text", ""))
    for name in ("gtube", "virus", "spoof", "vip", "blocked"):
        check(f"held message not delivered: {name}", not lab.inbox(rcpt(name), timeout=1))

    # 3. Release from a link: opening it must not release anything (link scanners open every link); the button must.
    held = {q["recipient"]: q for q in lab.cli("quarantine")}
    item = held.get(rcpt("gtube").lower())
    if check("spam is in the quarantine", item is not None):
        link = lab.cli("link", str(item["id"]))
        path = urllib.parse.urlparse(link).path
        code, page = lab.web(path)
        check("release link opens a confirmation page", code == 200 and "Release this message?" in page, f"HTTP {code}")
        still = {q["id"] for q in lab.cli("quarantine")}
        check("opening the link released nothing", item["id"] in still)
        code, page = lab.web(path, {"form": "wrong"})
        check("a release without the form value is refused", item["id"] in {q["id"] for q in lab.cli("quarantine")})
        form = re.search(r'name="form" value="([^"]+)"', page)
        code, page = lab.web(path, {"form": form.group(1) if form else ""})
        check("the release button works", code == 200 and "Released" in page, f"HTTP {code}")
        got = lab.inbox(rcpt("gtube"))
        check("released message reached the mail server", len(got) == 1 and
              "X-Tidegate-Released" in lab.mailpit(f"/api/v1/message/{got[0]['ID']}/headers"))
        code, page = lab.web(path, {"form": form.group(1) if form else ""})
        check("a second release does nothing", "already" in page)
        bad = path[:-3] + ("AAA" if not path.endswith("AAA") else "BBB")
        code, _ = lab.web(bad)
        check("a tampered link is refused", code == 403, f"HTTP {code}")
    virus_item = held.get(rcpt("virus").lower())
    if virus_item:
        code, page = lab.web(urllib.parse.urlparse(lab.cli("link", str(virus_item["id"]))).path)
        check("a virus can't be released from an end-user link", code == 404, f"HTTP {code}")

    # 4. The digest: one email per person, whose Release link works end to end.
    out = lab.cli("digest")
    check("digest run", "digest(s) sent" in out, out)
    dig = [m for m in lab.inbox(rcpt("digest")) if "held for you" in m["Subject"]]
    if check("digest delivered", len(dig) == 1, dig[0]["Subject"] if dig else "none"):
        text = lab.mailpit(f"/api/v1/message/{dig[0]['ID']}").get("Text", "")
        m = re.search(r"Release: (\S+)", text)
        if check("digest has a release link", bool(m)):
            path = urllib.parse.urlparse(m.group(1)).path
            code, page = lab.web(path)
            form = re.search(r'name="form" value="([^"]+)"', page)
            code, page = lab.web(path, {"form": form.group(1) if form else ""})
            check("release from the digest works", "Released" in page and
                  any("Digest test" in x["Subject"] for x in lab.inbox(rcpt("digest"))))

    # 5. The admin console.
    if a.admin_password:
        code, page = lab.web("/admin/login")
        token = re.search(r'name="csrf" value="([^"]+)"', page)
        code, page = lab.web("/admin/login", {"csrf": token.group(1) if token else "", "username": "admin", "password": "wrong"})
        check("wrong admin password refused", code == 401, f"HTTP {code}")
        code, page = lab.web("/admin/login", {"csrf": token.group(1) if token else "", "username": "admin",
                                              "password": a.admin_password})
        check("admin sign-in works", code == 200 and "Overview" in page, f"HTTP {code}")
        code, page = lab.web("/admin/messages?days=1")
        check("message log lists the test mail", rcpt("clean") in page)
        code, page = lab.web("/admin/quarantine")
        check("quarantine page lists held mail", rcpt("virus") in page)

    # 6. A scanner outage with fail_mode "closed": mail waits in the queue, then arrives once Rspamd is back.
    if not a.skip_outage:
        lab.dc("stop", "rspamd")
        try:
            lab.send(message("Alice Example <alice@lab-sender.test>", rcpt("outage"), "Sent during an outage", "Hello.\n"),
                     "alice@lab-sender.test", [rcpt("outage")])
            time.sleep(15)
            check("during the outage the message waits (not delivered)", not lab.inbox(rcpt("outage"), timeout=1))
            queue = lab.dc("exec", "-T", "mta", "postqueue", "-j")
            check("during the outage the message is in Postfix's queue", rcpt("outage") in queue)
        finally:
            lab.dc("start", "rspamd")
        time.sleep(10)
        lab.dc("exec", "-T", "mta", "postqueue", "-f")
        check("after the outage the message is delivered", len(lab.inbox(rcpt("outage"), timeout=120)) == 1)

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} of {len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
