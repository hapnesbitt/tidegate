"""Optional warning banner at the top of the message body. Off by default: changing the body breaks DKIM signatures."""
from __future__ import annotations

import email
import email.policy
import html
import re

SIGNED_OR_SEALED = {"multipart/signed", "multipart/encrypted", "application/pkcs7-mime", "application/x-pkcs7-mime"}
TITLE = "Caution: this message may be from an impostor."
ADVICE = "Check with the sender another way (phone, chat) before you send money, data or passwords."


def _plain(warnings: list[str]) -> str:
    lines = [TITLE] + [f"- {w}" for w in warnings] + [ADVICE, "-" * 60, ""]
    return "\n".join(lines) + "\n"


def _html(warnings: list[str]) -> str:
    items = "".join(f"<br>&bull; {html.escape(w)}" for w in warnings)
    return ('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;'
            'margin:0 0 16px 0"><tr><td style="background:#fff4e5;border-left:4px solid #b45309;padding:10px 14px;'
            'font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.45;color:#3b2a10">'
            f"<strong>{html.escape(TITLE)}</strong>{items}<br>{html.escape(ADVICE)}</td></tr></table>")


def add(raw: bytes, warnings: list[str]) -> bytes | None:
    """RAW with the banner in its first plain-text and HTML parts, or None when the message can't safely be changed."""
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        if msg.get_content_type() in SIGNED_OR_SEALED:
            return None
        text_part = html_part = None
        for part in msg.walk():
            if part.is_multipart() or part.get_content_disposition() == "attachment":
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain" and text_part is None:
                text_part = part
            elif ctype == "text/html" and html_part is None:
                html_part = part
        if text_part is None and html_part is None:
            return None
        if text_part is not None:
            text_part.set_content(_plain(warnings) + text_part.get_content(), subtype="plain", charset="utf-8")
        if html_part is not None:
            body = html_part.get_content()
            m = re.search(r"<body[^>]*>", body, re.I)
            body = body[:m.end()] + _html(warnings) + body[m.end():] if m else _html(warnings) + body
            html_part.set_content(body, subtype="html", charset="utf-8")
        return msg.as_bytes(policy=email.policy.SMTP)
    except Exception:
        return None
