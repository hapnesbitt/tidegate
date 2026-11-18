"""Edit the header block of a raw message while leaving the body bytes exactly as they were."""
from __future__ import annotations

from email.header import Header


def _split(raw: bytes) -> tuple[bytes, bytes, bytes]:
    """(header block including its last line ending, line ending used, rest starting at the blank line)."""
    eol = b"\r\n" if raw.find(b"\r\n") != -1 and raw.find(b"\r\n") <= raw.find(b"\n") else b"\n"
    best = -1
    for sep in (b"\r\n\r\n", b"\n\n", b"\r\n\n", b"\n\r\n"):   # the earliest blank line ends the header block
        i = raw.find(sep)
        if i != -1 and (best == -1 or i < best):
            best = i
    first = len(raw) if best == -1 else best + (2 if raw[best:best + 2] == b"\r\n" else 1)
    head, rest = raw[:first], raw[first:]
    if head and not head.endswith(b"\n"):
        head += eol
    return head, eol, rest


def _fields(head: bytes) -> list[bytes]:
    fields: list[bytes] = []
    for line in head.splitlines(keepends=True):
        if line[:1] in (b" ", b"\t") and fields:
            fields[-1] += line
        else:
            fields.append(line)
    return fields


def _name(field: bytes) -> str:
    return field.split(b":", 1)[0].strip().decode("latin-1").lower()


def encode(name: str, value: str, eol: bytes = b"\n") -> bytes:
    value = " ".join(value.splitlines())
    if value.isascii():
        text = f"{name}: {value}"
        if len(text) <= 998:
            return text.encode("ascii") + eol
    folded = Header(value, "utf-8", header_name=name).encode(linesep=eol.decode())
    return f"{name}: ".encode("ascii") + folded.encode("ascii") + eol


def edit(raw: bytes, add: list[tuple[str, str]] = (), remove: set[str] = frozenset()) -> bytes:
    """Remove every field whose lower-case name is in REMOVE, then put ADD on top of the header block."""
    head, eol, rest = _split(raw)
    kept = [f for f in _fields(head) if _name(f) not in remove]
    new = [encode(name, value, eol) for name, value in add]
    return b"".join(new + kept) + rest


def get(raw: bytes, name: str) -> list[str]:
    head, _, _ = _split(raw)
    name = name.lower()
    out = []
    for field in _fields(head):
        if _name(field) == name:
            value = field.split(b":", 1)[1] if b":" in field else b""
            out.append(" ".join(value.decode("utf-8", "replace").split()))
    return out


def to_crlf(raw: bytes) -> bytes:
    return raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
