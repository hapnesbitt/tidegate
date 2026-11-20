"""Postfix pipe(8) content filter. Postfix runs it once per message and recipient and passes the message on stdin.

Exit 0 means Tidegate took care of the message (delivered or quarantined it); exit 75 means "try again later", and
Postfix keeps the message and retries. Every unexpected error is a 75: Tidegate never loses mail through its own fault.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import traceback
from email import policy
from email.parser import BytesParser

from . import banner, config, headers, impostor, mailer, rspamd, verdict
from .store import Store

EX_TEMPFAIL = 75
OUR_HEADERS = {"x-tidegate-verdict", "x-tidegate-warning", "x-tidegate-released", "x-spam-flag", "x-spamd-result",
               "x-spam-status", "x-virus"}


def log(line: str) -> None:
    """One line in the mail log (the mta container's output), through Postfix's own logger."""
    try:
        # Full path: pipe(8) starts the filter with a bare environment (no PATH), so "postlog" alone is never found.
        subprocess.run(["/usr/sbin/postlog", "-t", "postfix/tidegate", "-p", "info", line[:900]], timeout=5, check=False,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _text(value) -> str:
    text = str(value) if value is not None else ""
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def summary(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.compat32).parsebytes(raw, headersonly=True)
    from_raw = _text(msg.get("From"))
    return {
        "from_raw": from_raw,
        "from_display": impostor.decode(from_raw)[:300],
        "reply_to": _text(msg.get("Reply-To")),
        "subject": impostor.decode(_text(msg.get("Subject")))[:300],
        "message_id": _text(msg.get("Message-ID")).strip()[:300],
    }


def prepare(raw: bytes, result: dict, v: verdict.Verdict, cfg) -> bytes:
    add, remove = rspamd.milter_changes(result)
    ours = [("X-Tidegate-Verdict", f"{v.label}; score={float(result.get('score') or 0):.2f}")]
    if v.tag:
        ours.append(("X-Spam-Flag", "YES"))
    ours += [("X-Tidegate-Warning", w) for w in v.warnings[:5]]
    out = headers.edit(raw, add=ours + add, remove=remove | OUR_HEADERS)
    if v.warnings and cfg.impostor.banner:
        out = banner.add(out, v.warnings) or out
    return out


def process(raw: bytes, args) -> int:
    cfg = config.load()
    st = Store(cfg.paths.data)
    rcpt = args.recipient.lower()
    sender = args.sender
    info = summary(raw)

    failed = None
    try:
        result = rspamd.check(cfg.rspamd.url, raw, ip=args.client_address, helo=args.client_helo,
                              hostname=args.client_hostname, sender=sender, rcpt=rcpt, queue_id=args.queue_id,
                              timeout=cfg.rspamd.timeout)
    except rspamd.RspamdError as e:
        if cfg.filter.fail_mode != "open":
            log(f"{args.queue_id}: rspamd did not answer, deferred: {e}")
            print(f"tidegate: scanner unavailable ({e}), will retry")
            return EX_TEMPFAIL
        failed = str(e)
        result = {"action": "no action", "score": 0.0, "symbols": {}}

    senders = impostor.addresses(info["from_raw"])
    from_addr = senders[0][1] if senders else ""
    findings = []
    if cfg.impostor.enabled and not failed:
        findings = impostor.analyze(from_header=info["from_raw"], reply_to=info["reply_to"], symbols=result["symbols"].keys(),
                                    own_domains=cfg.gateway.domains, protected_domains=cfg.impostor.protected_domains,
                                    vip_names=cfg.impostor.vip_names, extra_freemail=cfg.impostor.freemail_domains)
    hits = st.policy_hits({"envelope": sender, "from": from_addr}, rcpt)
    v = verdict.decide(result, findings, hits, cfg, envelope_domain=impostor.domain_of(sender),
                       from_domain=impostor.domain_of(from_addr))
    if failed:
        v.unscanned = True
        v.reasons.append(f"Rspamd did not answer ({failed[:120]}); delivered unscanned because fail_mode is open")
    if v.action == "defer":
        log(f"{args.queue_id}: deferred: {'; '.join(v.reasons)}")
        print(f"tidegate: {'; '.join(v.reasons)}, will retry")
        return EX_TEMPFAIL

    score = float(result.get("score") or 0.0)
    row = dict(queue_id=args.queue_id, client_ip=args.client_address, helo=args.client_helo, sender=sender,
               recipient=rcpt, from_header=info["from_display"], subject=info["subject"], message_id=info["message_id"],
               size=len(raw), score=score, rspamd_action=result.get("action"), verdict=v.label, category=v.category,
               reasons=v.reasons, symbols=rspamd.top_symbols(result))

    if v.action == "quarantine":
        qid = st.quarantine_add(raw, sender=sender, recipient=rcpt, from_header=info["from_display"],
                                subject=info["subject"], category=v.category, score=score, reasons=v.reasons,
                                symbols=row["symbols"])
        try:
            st.log_message(**row, quarantine_id=qid)
        except Exception as e:      # the message is safely held; a missing log row is no reason to retry
            log(f"{args.queue_id}: log write failed: {e!r}")
        log(f"{args.queue_id}: to=<{rcpt}> verdict={v.label} score={score:.2f} held as #{qid}")
        return 0

    try:
        st.log_message(**row)
    except Exception as e:
        log(f"{args.queue_id}: log write failed: {e!r}")
    mailer.reinject(prepare(raw, result, v, cfg), sender, [rcpt], cfg.smtp.reinject_host, cfg.smtp.reinject_port)
    log(f"{args.queue_id}: to=<{rcpt}> verdict={v.label} score={score:.2f}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Tidegate's Postfix content filter (reads one message on stdin)")
    p.add_argument("--sender", default="")
    p.add_argument("--recipient", required=True)
    p.add_argument("--client-address", default="")
    p.add_argument("--client-helo", default="")
    p.add_argument("--client-hostname", default="")
    p.add_argument("--queue-id", default="")
    args = p.parse_args(argv)
    raw = sys.stdin.buffer.read()
    try:
        return process(raw, args)
    except Exception as e:
        log(f"{args.queue_id}: filter error, deferred: {e!r}")
        traceback.print_exc(file=sys.stderr)
        print(f"tidegate: temporary error ({type(e).__name__}), will retry")
        return EX_TEMPFAIL


if __name__ == "__main__":
    sys.exit(main())
