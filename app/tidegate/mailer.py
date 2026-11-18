"""Hand a message back to Postfix's re-injection port, which delivers it without filtering it again."""
from __future__ import annotations

import smtplib

from . import headers


def reinject(raw: bytes, sender: str, recipients: list[str], host: str, port: int, timeout: float = 60) -> None:
    data = headers.to_crlf(raw)
    mail_options = []
    if any(b > 127 for b in data):
        mail_options.append("BODY=8BITMIME")
    if not all(a.isascii() for a in [sender] + recipients):
        mail_options.append("SMTPUTF8")
    with smtplib.SMTP(host, port, timeout=timeout) as smtp:
        smtp.ehlo("tidegate")
        refused = smtp.sendmail(sender, recipients, data, mail_options=mail_options)
    if refused:
        raise smtplib.SMTPRecipientsRefused(refused)
