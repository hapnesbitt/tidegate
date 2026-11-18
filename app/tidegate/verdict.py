"""Turn Rspamd's result, the impostor findings and the policy lists into one decision per recipient."""
from __future__ import annotations

from dataclasses import dataclass, field

AUTH_FROM = "DMARC_POLICY_ALLOW"     # the From domain is authenticated and aligned
AUTH_ENVELOPE = "R_SPF_ALLOW"        # the envelope sender's domain authorized the sending server


@dataclass
class Verdict:
    action: str                       # "deliver", "quarantine" or "defer"
    category: str | None = None       # virus, phish, impostor, blocked, spam
    reasons: list[str] = field(default_factory=list)
    tag: bool = False                 # deliver with X-Spam-Flag: YES
    warnings: list[str] = field(default_factory=list)
    would_quarantine: str | None = None   # category that observe mode let through
    unscanned: bool = False

    @property
    def label(self) -> str:
        if self.action == "quarantine":
            return f"quarantine:{self.category}"
        if self.action == "defer":
            return "defer"
        parts = ["deliver"]
        if self.unscanned:
            parts.append("unscanned")
        if self.would_quarantine:
            parts.append(f"observe-{self.would_quarantine}")
        if self.tag:
            parts.append("tag")
        if self.warnings:
            parts.append("warn")
        return "+".join(parts)


def allow_honored(hit: dict, symbols: set[str], envelope_domain: str, from_domain: str) -> bool:
    """An allow entry counts only for a sender who proved who they are, so a faked address can't use it."""
    if hit["via"] == "from":
        return AUTH_FROM in symbols
    return AUTH_ENVELOPE in symbols and (envelope_domain == from_domain or AUTH_FROM in symbols)


def decide(result: dict, findings: list, hits: list[dict], cfg, *, envelope_domain: str = "", from_domain: str = "") -> Verdict:
    f = cfg.filter
    syms = set((result.get("symbols") or {}).keys())
    score = float(result.get("score") or 0.0)
    action = result.get("action") or "no action"
    held = set(f.quarantine_categories)

    def outcome(category: str, reasons: list[str]) -> Verdict | None:
        if category in held:
            return Verdict("quarantine", category, reasons)
        return None

    if syms & set(f.scanner_failure_symbols):
        if f.fail_mode == "closed":
            return Verdict("defer", reasons=["the virus scanner did not answer"])
        unscanned = True
    else:
        unscanned = False

    virus = sorted(syms & set(f.virus_symbols))
    if virus:
        names = []
        for name in virus:
            names += (result["symbols"][name].get("options") or [name])
        return Verdict("quarantine", "virus", [f"virus found: {', '.join(map(str, names[:3]))}"])

    observed: str | None = None
    observed_reasons: list[str] = []

    phish = sorted(syms & set(f.phish_symbols))
    if phish:
        reasons = [f"link listed by a phishing feed ({', '.join(phish)})"]
        v = outcome("phish", reasons)
        if v:
            return v
        observed, observed_reasons = "phish", reasons

    blocks = [h for h in hits if h["kind"] == "block"]
    if blocks:
        reasons = [f"sender is on the block list ({blocks[0]['pattern']}, for {blocks[0]['scope']})"]
        v = outcome("blocked", reasons)
        if v:
            return v
        observed, observed_reasons = observed or "blocked", observed_reasons or reasons

    allowed = [h for h in hits if h["kind"] == "allow" and allow_honored(h, syms, envelope_domain, from_domain)]
    ignored = [h for h in hits if h["kind"] == "allow" and h not in allowed]
    warnings = [x.text for x in findings if x.severity == "medium"]
    if allowed:
        reasons = [f"sender is on the allow list ({allowed[0]['pattern']}) and proved its identity"]
        return Verdict("deliver", reasons=reasons + observed_reasons, warnings=warnings, unscanned=unscanned,
                       would_quarantine=observed)

    note = ["allow list entry ignored: the sender did not pass SPF or DMARC"] if ignored else []
    high = [x.text for x in findings if x.severity == "high"]
    if high:
        v = outcome("impostor", high + note)
        if v:
            return v
        warnings = high + warnings
        observed, observed_reasons = observed or "impostor", observed_reasons or high

    spam = action == "reject" or score >= f.quarantine_score
    if spam:
        reasons = [f"spam score {score:.1f} (quarantine at {f.quarantine_score:g})"] + note
        v = outcome("spam", reasons)
        if v:
            return v
        observed, observed_reasons = observed or "spam", observed_reasons or reasons

    tag = spam or action in ("add header", "rewrite subject") or score >= f.tag_score
    reasons = observed_reasons + note + ([f"possible spam, score {score:.1f}"] if tag and not spam else [])
    return Verdict("deliver", reasons=reasons, tag=tag, warnings=warnings, would_quarantine=observed, unscanned=unscanned)
