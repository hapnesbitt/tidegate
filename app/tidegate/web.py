"""Web pages: the admin console (sign-in required) and the digest's release pages (the signed link is the key).

Message content is only ever shown as escaped text. HTML from a message is never rendered and its links are never fetched.
"""
from __future__ import annotations

import base64
import email
import email.policy
import functools
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import threading
import time

from flask import Flask, Response, abort, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from . import __version__, actions, config, links, rspamd
from .digest import LABELS
from .store import Store, normalize_pattern

PREVIEW_BYTES = 3_000_000
PREVIEW_CHARS = 8000


# --- admin password (scrypt; ':' separators so the value is safe in a Docker Compose .env file) --------------------
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = 2 ** 15, 8, 1
    key = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt:{n}:{r}:{p}:{_b64(salt)}:{_b64(key)}"


def check_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, key = stored.split(":")
        if scheme != "scrypt":
            return False
        got = hashlib.scrypt(password.encode(), salt=_unb64(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=64 * 1024 * 1024, dklen=len(_unb64(key)))
        return hmac.compare_digest(got, _unb64(key))
    except (ValueError, TypeError):
        return False


class Throttle:
    """At most LIMIT failed sign-ins per address in WINDOW seconds."""

    def __init__(self, limit: int = 5, window: int = 900):
        self.limit, self.window = limit, window
        self.failures: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def blocked(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            recent = [t for t in self.failures.get(key, []) if t > now - self.window]
            self.failures[key] = recent
            return len(recent) >= self.limit

    def failed(self, key: str) -> None:
        with self.lock:
            self.failures.setdefault(key, []).append(time.time())

    def reset(self, key: str) -> None:
        with self.lock:
            self.failures.pop(key, None)


# --- message preview ----------------------------------------------------------------------------------------------
def html_to_text(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style|head)\b.*?</\1\s*>", " ", markup)
    markup = re.sub(r"(?i)<br\s*/?>|</p\s*>|</div\s*>|</tr\s*>|</h[1-6]\s*>|</li\s*>", "\n", markup)
    text = html.unescape(re.sub(r"(?s)<[^>]+>", " ", markup))
    lines = [" ".join(line.split()) for line in text.splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def preview(raw: bytes) -> dict:
    head_end = min([i for i in (raw.find(b"\n\n"), raw.find(b"\r\n\r\n")) if i >= 0] or [len(raw)])
    out = {"header_block": raw[:head_end].decode("utf-8", "replace"), "headers": {}, "text": "", "attachments": []}
    try:
        msg = email.message_from_bytes(raw[:PREVIEW_BYTES], policy=email.policy.default)
        for name in ("From", "Reply-To", "To", "Cc", "Subject", "Date", "Message-ID", "Return-Path"):
            if msg.get(name):
                out["headers"][name] = str(msg.get(name))
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype, name = part.get_content_type(), part.get_filename()
            if part.get_content_disposition() == "attachment" or (name and not ctype.startswith("text/")):
                payload = part.get_payload(decode=True) or b""
                out["attachments"].append({"name": name or "(no name)", "type": ctype, "size": len(payload)})
                continue
            if out["text"] or ctype not in ("text/plain", "text/html"):
                continue
            try:
                body = part.get_content()
            except Exception:
                body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            out["text"] = body if ctype == "text/plain" else html_to_text(body)
    except Exception as e:
        out["text"] = f"(could not read this message: {type(e).__name__})"
    if len(out["text"]) > PREVIEW_CHARS:
        out["text"] = out["text"][:PREVIEW_CHARS] + "\n\n[... cut ...]"
    return out


def summarize(counts: dict[str, int]) -> dict:
    s = {"total": 0, "clean": 0, "tagged": 0, "warned": 0, "observed": 0, "unscanned": 0, "held": {}}
    for label, n in counts.items():
        s["total"] += n
        if label.startswith("quarantine:"):
            cat = label.split(":", 1)[1]
            s["held"][cat] = s["held"].get(cat, 0) + n
            continue
        parts = label.split("+")
        s["clean"] += n if parts == ["deliver"] else 0
        s["tagged"] += n if "tag" in parts else 0
        s["warned"] += n if "warn" in parts else 0
        s["unscanned"] += n if "unscanned" in parts else 0
        s["observed"] += n if any(p.startswith("observe-") for p in parts) else 0
    return s


def create_app(cfg=None, store: Store | None = None, secret: bytes | None = None) -> Flask:
    cfg = cfg or config.load()
    secret = secret or config.secret_key()
    store = store or Store(cfg.paths.data)
    admin_user = cfg.web.admin_user
    admin_hash = os.environ.get("TIDEGATE_ADMIN_PASSWORD_HASH", "")
    throttle = Throttle()

    app = Flask(__name__)
    app.config.update(SECRET_KEY=hashlib.sha256(b"tidegate-session:" + secret).digest(),
                      SESSION_COOKIE_NAME="tidegate_session", SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=bool(cfg.web.secure_cookies),
                      PERMANENT_SESSION_LIFETIME=8 * 3600, MAX_CONTENT_LENGTH=64 * 1024)
    if cfg.web.trust_proxy:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @app.template_filter("when")
    def _when(ts):
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(ts or 0)))

    @app.template_filter("fromjson")
    def _fromjson(text):
        try:
            return json.loads(text or "[]")
        except ValueError:
            return []

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return session["csrf"]

    @app.context_processor
    def _globals():
        return {"csrf_token": csrf_token, "version": __version__, "labels": LABELS, "is_admin": bool(session.get("admin"))}

    @app.before_request
    def _check_csrf():
        if request.method == "POST" and request.path.startswith("/admin"):
            sent = request.form.get("csrf", "")
            if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
                abort(400, "This form expired. Go back, reload the page and try again.")

    @app.after_request
    def _security_headers(resp: Response) -> Response:
        resp.headers["Content-Security-Policy"] = ("default-src 'none'; style-src 'self'; img-src 'self'; "
                                                   "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if not request.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def admin_required(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("admin"):
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def who() -> str:
        return f"admin {session.get('admin')}"

    # --- health and sign-in ------------------------------------------------------------------------------------
    @app.get("/healthz")
    def healthz():
        store.state_get("health")
        return "ok\n", 200, {"Content-Type": "text/plain"}

    @app.get("/")
    def index():
        return redirect(url_for("dashboard"))

    @app.route("/admin/login", methods=["GET", "POST"])
    def login():
        error = ""
        if not admin_hash:
            error = "Admin sign-in is off. Set TIDEGATE_ADMIN_PASSWORD_HASH (see the README)."
        elif request.method == "POST":
            key = request.remote_addr or "?"
            if throttle.blocked(key):
                error = "Too many failed attempts. Wait 15 minutes and try again."
            elif hmac.compare_digest(request.form.get("username", ""), admin_user) and \
                    check_password(request.form.get("password", ""), admin_hash):
                throttle.reset(key)
                session.clear()
                session.permanent = True
                session["admin"] = admin_user
                session["csrf"] = secrets.token_urlsafe(24)
                return redirect(url_for("dashboard"))
            else:
                throttle.failed(key)
                time.sleep(0.5)
                error = "That user name and password don't match."
        return render_template("login.html", error=error), (200 if not error or request.method == "GET" else 401)

    @app.post("/admin/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # --- admin pages --------------------------------------------------------------------------------------------
    @app.get("/admin")
    @admin_required
    def dashboard():
        now = int(time.time())
        return render_template("dashboard.html", day=summarize(store.counts(now - 86400)),
                               week=summarize(store.counts(now - 7 * 86400)), held=store.held_count(),
                               rspamd_ok=rspamd.ping(cfg.rspamd.url), cfg=cfg,
                               last_digest=store.state_get("digest_run"), recent=store.messages(now - 86400, limit=12))

    @app.get("/admin/messages")
    @admin_required
    def messages():
        q = request.args.get("q", "").strip()[:200]
        verdict = request.args.get("verdict", "").strip()[:40]
        days = max(1, min(int(request.args.get("days", "7") or 7), 90))
        rows = store.messages(int(time.time()) - days * 86400, q, verdict, limit=500)
        return render_template("messages.html", rows=rows, q=q, verdict=verdict, days=days)

    @app.get("/admin/quarantine")
    @admin_required
    def quarantine():
        status = request.args.get("status", "held")
        status = status if status in ("held", "released", "deleted", "") else "held"
        category = request.args.get("category", "")
        category = category if category in LABELS else ""
        q = request.args.get("q", "").strip()[:200]
        rows = store.quarantine_list(status=status, category=category, query=q, limit=500)
        return render_template("quarantine.html", rows=rows, status=status, category=category, q=q)

    def load_item(qid: int):
        item = store.quarantine_get(qid)
        if item is None:
            abort(404)
        return item

    @app.get("/admin/quarantine/<int:qid>")
    @admin_required
    def item(qid: int):
        it = load_item(qid)
        try:
            pv = preview(store.read_raw(it)) if it["status"] == "held" else None
        except OSError:
            pv = None
        return render_template("item.html", item=it, pv=pv, user_release=cfg.filter.user_release)

    @app.post("/admin/quarantine/<int:qid>/release")
    @admin_required
    def admin_release(qid: int):
        it = load_item(qid)
        try:
            actions.release(cfg, store, it, who(), allow_sender=request.form.get("allow") == "1")
            note = "Released. The message is on its way to " + it["recipient"] + "."
        except actions.ActionError as e:
            note = str(e)
        return render_template("result.html", note=note, back=url_for("quarantine"))

    @app.post("/admin/quarantine/<int:qid>/delete")
    @admin_required
    def admin_delete(qid: int):
        it = load_item(qid)
        try:
            actions.delete(store, it, who())
            note = "Deleted."
        except actions.ActionError as e:
            note = str(e)
        return render_template("result.html", note=note, back=url_for("quarantine"))

    @app.get("/admin/quarantine/<int:qid>/download")
    @admin_required
    def download(qid: int):
        it = load_item(qid)
        if it["status"] != "held":
            abort(410)
        return Response(store.read_raw(it), mimetype="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="tidegate-{qid}.eml.txt"'})

    @app.route("/admin/policy", methods=["GET", "POST"])
    @admin_required
    def policy():
        error = ""
        if request.method == "POST":
            kind = request.form.get("kind")
            try:
                if kind not in ("allow", "block"):
                    raise ValueError("choose allow or block")
                recipient = request.form.get("recipient", "").strip().lower()
                if recipient and "@" not in recipient:
                    raise ValueError("the person must be a full email address, or empty for everyone")
                store.policy_add(kind, request.form.get("pattern", ""), recipient,
                                 note=request.form.get("note", "")[:200], by=who())
                return redirect(url_for("policy"))
            except ValueError as e:
                error = str(e)
        return render_template("policy.html", rows=store.policy_list(), error=error, cfg=cfg)

    @app.post("/admin/policy/<int:pid>/delete")
    @admin_required
    def policy_delete(pid: int):
        store.policy_remove(pid)
        return redirect(url_for("policy"))

    # --- end-user pages (from the digest) -------------------------------------------------------------------------
    @app.get("/u/<token>")
    def user_page(token: str):
        fields = links.verify(secret, token, "user")
        if not fields:
            return render_template("result.html", note="This link has expired or is not valid."), 403
        recipient = fields[0]
        rows = store.quarantine_list(status="held", recipient=recipient, since=int(time.time()) - 30 * 86400)
        return render_template("user.html", rows=rows, recipient=recipient, token=token,
                               form=links.form_token(secret, token), user_release=cfg.filter.user_release)

    @app.post("/u/<token>/release/<int:qid>")
    def user_release(token: str, qid: int):
        fields = links.verify(secret, token, "user")
        if not fields or not hmac.compare_digest(request.form.get("form", ""), links.form_token(secret, token)):
            return render_template("result.html", note="This link has expired or is not valid."), 403
        it = store.quarantine_get(qid)
        if it is None or it["recipient"] != fields[0] or it["category"] not in cfg.filter.user_release:
            abort(404)
        try:
            actions.release(cfg, store, it, f"user {fields[0]}", allow_sender=request.form.get("allow") == "1")
            note = "Released. Look for the message in your inbox in a minute or two."
        except actions.ActionError as e:
            note = str(e)
        return render_template("result.html", note=note, back=url_for("user_page", token=token))

    @app.route("/r/<token>", methods=["GET", "POST"])
    def release_link(token: str):
        fields = links.verify(secret, token, "release")
        if not fields:
            return render_template("result.html", note="This link has expired or is not valid."), 403
        qid, recipient = fields
        it = store.quarantine_get(int(qid))
        if it is None or it["recipient"] != recipient or it["category"] not in cfg.filter.user_release:
            return render_template("result.html", note="This message is no longer in the quarantine."), 404
        form = links.form_token(secret, token)
        if request.method == "GET" or not hmac.compare_digest(request.form.get("form", ""), form):
            # A GET only shows the button: link scanners that open every link can't release anything.
            return render_template("confirm.html", item=it, token=token, form=form)
        try:
            actions.release(cfg, store, it, f"user {recipient}", allow_sender=request.form.get("allow") == "1")
            note = "Released. Look for the message in your inbox in a minute or two."
        except actions.ActionError as e:
            note = str(e)
        return render_template("result.html", note=note)

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(410)
    def _error(e):
        return render_template("result.html", note=getattr(e, "description", "Something went wrong.")), e.code

    return app


def main() -> None:
    from waitress import serve
    cfg = config.load()
    host, _, port = cfg.web.listen.rpartition(":")
    serve(create_app(cfg), host=host or "0.0.0.0", port=int(port), threads=8, ident="tidegate")


if __name__ == "__main__":
    main()
