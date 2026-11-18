"""The message log, the quarantine index and the policy lists live in SQLite; held messages are files under quarantine/."""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  queue_id TEXT, client_ip TEXT, helo TEXT,
  sender TEXT, recipient TEXT, from_header TEXT, subject TEXT, message_id TEXT,
  size INTEGER, score REAL, rspamd_action TEXT,
  verdict TEXT NOT NULL, category TEXT, reasons TEXT, symbols TEXT,
  quarantine_id INTEGER
);
CREATE INDEX IF NOT EXISTS messages_ts ON messages(ts);
CREATE INDEX IF NOT EXISTS messages_rcpt ON messages(recipient, ts);
CREATE TABLE IF NOT EXISTS quarantine (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  sender TEXT, recipient TEXT NOT NULL, from_header TEXT, subject TEXT,
  category TEXT NOT NULL, score REAL, reasons TEXT, symbols TEXT,
  path TEXT NOT NULL, size INTEGER,
  status TEXT NOT NULL DEFAULT 'held', status_ts INTEGER, status_by TEXT
);
CREATE INDEX IF NOT EXISTS quarantine_rcpt ON quarantine(recipient, status, ts);
CREATE INDEX IF NOT EXISTS quarantine_ts ON quarantine(ts);
CREATE TABLE IF NOT EXISTS policy (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('allow', 'block')),
  pattern TEXT NOT NULL,
  recipient TEXT NOT NULL DEFAULT '',
  note TEXT, created_ts INTEGER, created_by TEXT,
  UNIQUE (kind, pattern, recipient)
);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
"""


def normalize_pattern(pattern: str) -> str:
    """An allow/block entry: a full address, a domain, or *.domain for the domain and its subdomains."""
    p = pattern.strip().lower()
    if p.startswith("@"):
        p = p[1:]
    if not p or any(c.isspace() for c in p) or p.count("@") > 1:
        raise ValueError("enter one address, domain or *.domain")
    return p


def pattern_matches(pattern: str, address: str) -> bool:
    address = address.lower()
    domain = address.rpartition("@")[2]
    if "@" in pattern:
        return address == pattern
    if pattern.startswith("*."):
        base = pattern[2:]
        return domain == base or domain.endswith("." + base)
    return domain == pattern


class Store:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.qdir = os.path.join(data_dir, "quarantine")
        self.db_path = os.path.join(data_dir, "tidegate.db")
        os.makedirs(self.qdir, mode=0o700, exist_ok=True)
        with self.connect() as con:
            con.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=30000")
        con.execute("PRAGMA synchronous=FULL")
        return con

    # --- message log ---------------------------------------------------------------------------------------------
    def log_message(self, **row) -> int:
        row.setdefault("ts", int(time.time()))
        for key in ("reasons", "symbols"):
            if key in row and not isinstance(row[key], str):
                row[key] = json.dumps(row[key], ensure_ascii=False)
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        with self.connect() as con:
            return con.execute(f"INSERT INTO messages ({cols}) VALUES ({marks})", tuple(row.values())).lastrowid

    def messages(self, since: int, query: str = "", verdict: str = "", limit: int = 200) -> list[sqlite3.Row]:
        sql = "SELECT * FROM messages WHERE ts >= ?"
        args: list = [since]
        if query:
            like = f"%{query}%"
            sql += " AND (sender LIKE ? OR recipient LIKE ? OR subject LIKE ? OR from_header LIKE ? OR queue_id = ? OR client_ip = ?)"
            args += [like, like, like, like, query, query]
        if verdict:
            sql += " AND verdict LIKE ?"
            args.append(verdict + "%")
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(limit)
        with self.connect() as con:
            return con.execute(sql, args).fetchall()

    def counts(self, since: int) -> dict[str, int]:
        with self.connect() as con:
            rows = con.execute("SELECT verdict, count(*) FROM messages WHERE ts >= ? GROUP BY verdict", (since,)).fetchall()
        return {r[0]: r[1] for r in rows}

    # --- quarantine ------------------------------------------------------------------------------------------------
    def _write_file(self, raw: bytes) -> str:
        day = time.strftime("%Y/%m/%d", time.gmtime())
        folder = os.path.join(self.qdir, day)
        os.makedirs(folder, mode=0o700, exist_ok=True)
        name = secrets.token_hex(16) + ".eml"
        path = os.path.join(folder, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        dfd = os.open(folder, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return os.path.join(day, name)

    def quarantine_add(self, raw: bytes, **meta) -> int:
        """Save RAW durably first, then index it: the caller reports success to Postfix only after this returns."""
        path = self._write_file(raw)
        meta.update(path=path, size=len(raw), ts=meta.get("ts") or int(time.time()), status="held")
        for key in ("reasons", "symbols"):
            if key in meta and not isinstance(meta[key], str):
                meta[key] = json.dumps(meta[key], ensure_ascii=False)
        cols = ", ".join(meta)
        marks = ", ".join("?" for _ in meta)
        with self.connect() as con:
            return con.execute(f"INSERT INTO quarantine ({cols}) VALUES ({marks})", tuple(meta.values())).lastrowid

    def quarantine_get(self, qid: int) -> sqlite3.Row | None:
        with self.connect() as con:
            return con.execute("SELECT * FROM quarantine WHERE id = ?", (qid,)).fetchone()

    def quarantine_list(self, status: str = "held", category: str = "", recipient: str = "", query: str = "",
                        since: int = 0, limit: int = 300) -> list[sqlite3.Row]:
        sql = "SELECT * FROM quarantine WHERE ts >= ?"
        args: list = [since]
        if status:
            sql += " AND status = ?"
            args.append(status)
        if category:
            sql += " AND category = ?"
            args.append(category)
        if recipient:
            sql += " AND recipient = ?"
            args.append(recipient.lower())
        if query:
            like = f"%{query}%"
            sql += " AND (sender LIKE ? OR recipient LIKE ? OR subject LIKE ? OR from_header LIKE ?)"
            args += [like, like, like, like]
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(limit)
        with self.connect() as con:
            return con.execute(sql, args).fetchall()

    def read_raw(self, item) -> bytes:
        path = os.path.normpath(os.path.join(self.qdir, item["path"]))
        if not path.startswith(self.qdir + os.sep):
            raise ValueError("quarantine path escapes the store")
        with open(path, "rb") as fh:
            return fh.read()

    def claim(self, qid: int, by: str) -> bool:
        """Move a held item to 'releasing' so two clicks can't deliver it twice."""
        with self.connect() as con:
            cur = con.execute("UPDATE quarantine SET status = 'releasing', status_ts = ?, status_by = ? "
                              "WHERE id = ? AND status = 'held'", (int(time.time()), by, qid))
            return cur.rowcount == 1

    def set_status(self, qid: int, status: str, by: str) -> None:
        with self.connect() as con:
            con.execute("UPDATE quarantine SET status = ?, status_ts = ?, status_by = ? WHERE id = ?",
                        (status, int(time.time()), by, qid))

    def delete_file(self, item) -> None:
        try:
            os.unlink(os.path.join(self.qdir, item["path"]))
        except FileNotFoundError:
            pass

    def held_count(self) -> dict[str, int]:
        with self.connect() as con:
            rows = con.execute("SELECT category, count(*) FROM quarantine WHERE status = 'held' GROUP BY category").fetchall()
        return {r[0]: r[1] for r in rows}

    # --- policy --------------------------------------------------------------------------------------------------
    def policy_add(self, kind: str, pattern: str, recipient: str = "", note: str = "", by: str = "") -> None:
        with self.connect() as con:
            con.execute("INSERT OR IGNORE INTO policy (kind, pattern, recipient, note, created_ts, created_by) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (kind, normalize_pattern(pattern), recipient.lower(), note, int(time.time()), by))

    def policy_remove(self, pid: int) -> None:
        with self.connect() as con:
            con.execute("DELETE FROM policy WHERE id = ?", (pid,))

    def policy_list(self) -> list[sqlite3.Row]:
        with self.connect() as con:
            return con.execute("SELECT * FROM policy ORDER BY kind, recipient, pattern").fetchall()

    def policy_hits(self, addresses: dict[str, str], recipient: str) -> list[dict]:
        """Entries that match. ADDRESSES maps where an address came from ('envelope', 'from') to the address."""
        recipient = recipient.lower()
        with self.connect() as con:
            rows = con.execute("SELECT kind, pattern, recipient FROM policy WHERE recipient IN ('', ?)", (recipient,)).fetchall()
        hits = []
        for row in rows:
            for via, address in addresses.items():
                if address and pattern_matches(row["pattern"], address):
                    hits.append({"kind": row["kind"], "pattern": row["pattern"], "scope": row["recipient"] or "everyone",
                                 "via": via})
        return hits

    # --- state and housekeeping ---------------------------------------------------------------------------------
    def state_get(self, key: str, default: str | None = None) -> str | None:
        with self.connect() as con:
            row = con.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def state_set(self, key: str, value: str) -> None:
        with self.connect() as con:
            con.execute("INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (key, value))

    def cleanup(self, quarantine_days: int, log_days: int, now: float | None = None) -> tuple[int, int]:
        now = now or time.time()
        q_cut = int(now - quarantine_days * 86400)
        with self.connect() as con:
            old = con.execute("SELECT id, path FROM quarantine WHERE ts < ?", (q_cut,)).fetchall()
        for item in old:
            self.delete_file(item)
        with self.connect() as con:
            con.execute("DELETE FROM quarantine WHERE ts < ?", (q_cut,))
            removed = con.execute("DELETE FROM messages WHERE ts < ?", (int(now - log_days * 86400),)).rowcount
        return len(old), removed
