"""Impostor checks (business email compromise): a borrowed name, a look-alike domain, or your own domain faked.

Each finding is "high" (hold the message) or "medium" (deliver it with a warning). The checks use the From and Reply-To
headers plus Rspamd's SPF, DKIM and DMARC results; they never look anything up themselves.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from email.header import decode_header, make_header
from email.utils import getaddresses

FREEMAIL = frozenset("""
gmail.com googlemail.com yahoo.com yahoo.co.uk ymail.com rocketmail.com outlook.com hotmail.com live.com msn.com aol.com
icloud.com me.com mac.com proton.me protonmail.com pm.me gmx.com gmx.net gmx.de web.de mail.com email.com zoho.com
zohomail.com yandex.com yandex.ru mail.ru inbox.ru tutanota.com tuta.io fastmail.com hushmail.com qq.com 163.com
""".split())

# Second-level suffixes under which the organization's name is the third label (a short list, not the Public Suffix List).
MULTI_SUFFIXES = frozenset("""
co.uk org.uk ac.uk gov.uk me.uk com.au net.au org.au co.nz org.nz co.jp ne.jp co.in co.kr com.br com.mx com.ar
co.za com.sg com.hk com.tr com.cn com.tw
""".split())

# Letters from other scripts that look Latin, and digits used as letters. Both sides of a comparison go through this.
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "χ": "x", "υ": "u", "ε": "e",
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "4": "a", "8": "b", "9": "g",
})

EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
DMARC_FAIL = frozenset({"DMARC_POLICY_REJECT", "DMARC_POLICY_QUARANTINE", "DMARC_POLICY_SOFTFAIL"})
SPF_FAIL = frozenset({"R_SPF_FAIL", "R_SPF_SOFTFAIL"})


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str   # "high" or "medium"
    text: str


def decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def addresses(value: str | None) -> list[tuple[str, str]]:
    """(display name, address) pairs from a From or Reply-To header; names decoded, addresses lower-cased."""
    if not value:
        return []
    out = []
    for name, addr in getaddresses([value]):
        if addr and "@" in addr:
            out.append((decode(name).strip(), addr.strip().lower()))
    return out


def domain_of(address: str) -> str:
    return address.rpartition("@")[2].lower().rstrip(".")


def split_domain(domain: str) -> tuple[str, str]:
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return domain, ""


def skeleton(label: str) -> str:
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except UnicodeError:
            pass
    s = unicodedata.normalize("NFKC", label).lower().translate(HOMOGLYPHS)
    s = "".join(ch for ch in unicodedata.normalize("NFKD", s) if not unicodedata.combining(ch))
    s = s.replace("rn", "m").replace("vv", "w")
    return s.replace("-", "").replace("_", "")


def osa_distance(a: str, b: str) -> int:
    """Edit distance counting one swap of neighbouring letters as one edit."""
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]


def same_org(domain: str, protected: set[str]) -> bool:
    return any(domain == p or domain.endswith("." + p) for p in protected)


def lookalike(domain: str, protected: set[str], freemail: frozenset = FREEMAIL) -> str | None:
    """The protected domain that DOMAIN imitates, or None."""
    if not domain or domain in freemail or same_org(domain, protected):
        return None
    core, suffix = split_domain(domain)
    core_sk = skeleton(core)
    for p in sorted(protected):
        p_core, p_suffix = split_domain(p)
        if len(p_core) < 4:
            continue
        p_sk = skeleton(p_core)
        if core == p_core and suffix != p_suffix:
            return p          # same name, different ending: example.co for example.com
        if core_sk == p_sk:
            return p          # look-alike characters: examp1e.com, exarnple.com
        if osa_distance(core_sk, p_sk) <= (1 if len(p_sk) <= 8 else 2):
            return p          # a letter or two off
        if len(p_sk) >= 5 and p_sk in core_sk:
            return p          # your name plus extra words: example-billing.com
    return None


def name_tokens(text: str) -> list[str]:
    text = "".join(ch for ch in unicodedata.normalize("NFKD", text) if not unicodedata.combining(ch)).lower()
    return [t for t in re.split(r"[^a-z0-9]+", text) if t]


def analyze(*, from_header: str | None, reply_to: str | None, symbols: set[str] | list[str], own_domains: list[str],
            protected_domains: list[str] = (), vip_names: list[str] = (), extra_freemail: list[str] = ()) -> list[Finding]:
    syms = set(symbols)
    freemail = FREEMAIL | {d.lower() for d in extra_freemail}
    own = {d.lower() for d in own_domains}
    protected = own | {d.lower() for d in protected_domains}
    findings: list[Finding] = []

    senders = addresses(from_header)
    if not senders:
        return findings
    if len(senders) > 1:
        findings.append(Finding("many_from", "medium", "The message names more than one sender in its From line."))
    display, addr = senders[0]
    from_domain = domain_of(addr)
    from_is_own = same_org(from_domain, own)
    dmarc_pass = "DMARC_POLICY_ALLOW" in syms

    # 1. Your own domain, faked: DMARC failed, or SPF failed with no DKIM or DMARC pass to vouch for it.
    if from_is_own and (syms & DMARC_FAIL or (syms & SPF_FAIL and not dmarc_pass and "R_DKIM_ALLOW" not in syms)):
        findings.append(Finding("own_domain_spoof", "high",
                                f"The sender claims to be {addr}, your own domain, but the domain's sender checks failed."))

    # 2. A protected person's name on mail from outside.
    tokens = set(name_tokens(display))
    vip_hit = None
    if display and not from_is_own:
        for vip in vip_names:
            vip_tokens = name_tokens(vip)
            if vip_tokens and set(vip_tokens) <= tokens:
                vip_hit = vip
                findings.append(Finding("vip_name_external", "high",
                                        f'The sender uses the name "{vip}" but wrote from {addr}, outside your organization.'))
                break

    # 3. An address written into the display name that is not the real one.
    shown = EMAIL_IN_TEXT.search(display or "")
    if shown and shown.group(0).lower() != addr:
        shown_domain = domain_of(shown.group(0))
        severe = same_org(shown_domain, protected) and not from_is_own and not dmarc_pass
        findings.append(Finding("display_name_address", "high" if severe else "medium",
                                f"The name shows {shown.group(0)}, but the real address is {addr}."))

    # 4. Look-alike domains in From and Reply-To.
    replies = addresses(reply_to)
    for label, dom in [("From", from_domain)] + [("Reply-To", domain_of(a)) for _, a in replies]:
        target = lookalike(dom, protected, freemail)
        if target:
            findings.append(Finding("lookalike_" + label.lower().replace("-", "_"), "high" if vip_hit else "medium",
                                    f"The {label} domain {dom} looks like {target} but is a different domain."))

    # 5. Replies diverted to a free mailbox while the From line claims your organization or a protected person.
    for _, reply_addr in replies:
        reply_domain = domain_of(reply_addr)
        if reply_domain != from_domain and reply_domain in freemail and (from_is_own or vip_hit):
            findings.append(Finding("reply_to_freemail", "medium",
                                    f"Replies would go to {reply_addr}, a free email account, not to {addr}."))
            break
    return findings
