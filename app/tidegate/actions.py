"""Release and delete, shared by the admin pages, the end-user links and the command line."""
from __future__ import annotations

import time

from . import headers, impostor, mailer


class ActionError(Exception):
    pass


def release(cfg, store, item, by: str, allow_sender: bool = False) -> None:
    if not store.claim(item["id"], by):
        raise ActionError("This message was already released or removed.")
    try:
        raw = store.read_raw(item)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S %z")
        raw = headers.edit(raw, add=[("X-Tidegate-Released", f"{stamp} by {by}")], remove={"x-tidegate-released"})
        mailer.reinject(raw, item["sender"] or "", [item["recipient"]], cfg.smtp.reinject_host, cfg.smtp.reinject_port)
    except Exception as e:
        store.set_status(item["id"], "held", by)
        raise ActionError(f"Delivery failed, the message is still held: {e}") from e
    store.set_status(item["id"], "released", by)
    if allow_sender:
        senders = impostor.addresses(item["from_header"]) if item["from_header"] else []
        address = senders[0][1] if senders else (item["sender"] or "")
        if address:
            store.policy_add("allow", address, item["recipient"], note=f"released #{item['id']}", by=by)


def delete(store, item, by: str) -> None:
    if item["status"] not in ("held",):
        raise ActionError("Only held messages can be deleted.")
    store.delete_file(item)
    store.set_status(item["id"], "deleted", by)
