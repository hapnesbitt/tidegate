"""Ask Rspamd's normal worker (/checkv2) for a verdict on one message."""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class RspamdError(Exception):
    pass


def _header_value(value: str) -> str:
    # http.client sends header values as Latin-1; pass UTF-8 addresses through byte for byte.
    return value.encode("utf-8", "surrogateescape").decode("latin-1")


def check(url: str, raw: bytes, *, ip: str = "", helo: str = "", hostname: str = "", sender: str = "",
          rcpt: str = "", queue_id: str = "", timeout: float = 60) -> dict:
    headers = {"Content-Type": "application/octet-stream"}
    for name, value in (("IP", ip), ("Helo", helo), ("Hostname", hostname), ("From", sender), ("Rcpt", rcpt),
                        ("Queue-Id", queue_id)):
        if value and value != "unknown":
            headers[name] = _header_value(value)
    req = urllib.request.Request(url.rstrip("/") + "/checkv2", data=raw, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.load(resp)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise RspamdError(str(e)) from e
    if not isinstance(result, dict) or "action" not in result:
        raise RspamdError(f"unexpected answer: {str(result)[:200]}")
    return result


def ping(url: str, timeout: float = 5) -> bool:
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/ping", timeout=timeout) as resp:
            return resp.read().strip().startswith(b"pong")
    except (urllib.error.URLError, OSError):
        return False


def milter_changes(result: dict) -> tuple[list[tuple[str, str]], set[str]]:
    """Headers Rspamd wants added and header names it wants removed (its milter_headers module)."""
    milter = result.get("milter") or {}
    remove = {name.lower() for name in (milter.get("remove_headers") or {})}
    add: list[tuple[str, str]] = []
    for name, spec in (milter.get("add_headers") or {}).items():
        items = spec if isinstance(spec, list) else [spec]
        for item in items:
            value = item.get("value") if isinstance(item, dict) else item
            if isinstance(value, str):
                add.append((name, " ".join(value.replace("\r", "").split("\n")).strip()))
    return add, remove


def top_symbols(result: dict, limit: int = 15) -> list[dict]:
    syms = result.get("symbols") or {}
    rows = [{"name": name, "score": round(float(s.get("score", 0.0)), 2), "options": (s.get("options") or [])[:3]}
            for name, s in syms.items()]
    rows.sort(key=lambda r: (-abs(r["score"]), r["name"]))
    return rows[:limit]
