"""Signed, expiring links for the digest. A link is the credential, so it names exactly what it allows."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(secret: bytes, purpose: str, fields: list, days: float, now: float | None = None) -> str:
    expires = int((now or time.time()) + days * 86400)
    payload = json.dumps([purpose, expires] + list(fields), separators=(",", ":")).encode()
    mac = hmac.new(secret, b"tidegate-link:" + payload, hashlib.sha256).digest()[:20]
    return _b64(payload) + "." + _b64(mac)


def verify(secret: bytes, token: str, purpose: str, now: float | None = None) -> list | None:
    """The fields of a valid, unexpired token for PURPOSE, or None."""
    try:
        body, mac = token.split(".", 1)
        payload = _unb64(body)
        expected = hmac.new(secret, b"tidegate-link:" + payload, hashlib.sha256).digest()[:20]
        if not hmac.compare_digest(expected, _unb64(mac)):
            return None
        data = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, list) or len(data) < 2 or data[0] != purpose:
        return None
    if not isinstance(data[1], int) or data[1] < (now or time.time()):
        return None
    return data[2:]


def form_token(secret: bytes, token: str) -> str:
    """A second value the release form must post back, derived from the link."""
    return _b64(hmac.new(secret, b"tidegate-form:" + token.encode(), hashlib.sha256).digest()[:16])
