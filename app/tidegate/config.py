"""Settings: /etc/tidegate/tidegate.toml merged over built-in defaults. Secrets come from the environment only."""
from __future__ import annotations

import copy
import ipaddress
import os
import re
import tomllib
from types import SimpleNamespace

CONFIG_PATH = os.environ.get("TIDEGATE_CONFIG", "/etc/tidegate/tidegate.toml")

CATEGORIES = ("virus", "phish", "impostor", "blocked", "spam")

DEFAULTS: dict = {
    "gateway": {
        "hostname": "mx.example.com",
        "domains": [],
        "next_hop": "",
        "routes": {},                 # per-domain next hop, e.g. {"example.org" = "[10.0.0.9]:25"}
        "valid_recipients": [],       # optional: only these addresses are accepted (stops backscatter)
        "outbound": "bounces",        # "bounces": Postfix may send non-delivery reports; "none": nothing leaves for other domains
        "soft_bounce": False,         # true: never bounce, keep undeliverable mail queued (use when another MTA sits in front)
        "xclient_hosts": [],          # test labs only: clients allowed to claim another address with XCLIENT
        "xforward_hosts": [],         # an MTA in front that forwards the original client's address with XFORWARD
        "message_size_limit": 26214400,
        "internal_subnet": os.environ.get("TIDEGATE_SUBNET", "172.31.240.0/24"),
        "filter_processes": 4,
    },
    "rspamd": {"url": "http://rspamd:11333", "timeout": 60},
    "filter": {
        "quarantine_score": 10.0,     # at or above this Rspamd score, a message is spam
        "tag_score": 6.0,             # at or above this, it is delivered with X-Spam-Flag: YES
        "quarantine_categories": list(CATEGORIES),   # categories held back; the rest are delivered, tagged and logged
        "user_release": ["spam"],     # categories end users may release from their digest
        "fail_mode": "closed",        # "closed": defer mail while a scanner is down; "open": deliver it unscanned, marked
        "virus_symbols": ["CLAM_VIRUS"],
        "scanner_failure_symbols": ["CLAM_VIRUS_FAIL"],
        "phish_symbols": ["PHISHED_OPENPHISH", "PHISHED_PHISHTANK", "PHISHED_GENERIC_SERVICE", "DBL_PHISH",
                          "DBL_ABUSE_PHISH", "URLHAUS_ABUSE_CH", "SURBL_PHISH"],
    },
    "impostor": {
        "enabled": True,
        "protected_domains": [],      # partners and brands to protect, in addition to your own domains
        "vip_names": [],              # names attackers might borrow, e.g. your CEO's
        "freemail_domains": [],       # added to the built-in list
        "banner": False,              # add a visible warning to the message body (breaks DKIM; see README)
    },
    "digest": {
        "enabled": True,
        "hours": [8],                 # local hours (TZ) when digests go out
        "sender": "",                 # e.g. "Tidegate Quarantine <quarantine@example.com>"
        "public_url": "",             # where users reach the release pages, e.g. https://quarantine.example.com
        "link_days": 14,
    },
    "retention": {"quarantine_days": 30, "log_days": 30},
    "web": {"admin_user": "admin", "secure_cookies": True, "trust_proxy": False, "listen": "0.0.0.0:8080"},
    "paths": {"data": "/data"},
    "smtp": {"reinject_host": os.environ.get("TIDEGATE_REINJECT_HOST", "127.0.0.1"), "reinject_port": 10025},
}

# Values in these sections are plain mappings (their keys are domain names, not settings).
_MAPPINGS = {("gateway", "routes")}

_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
_NEXT_HOP = re.compile(r"^(\[[A-Za-z0-9.:-]+\]|[A-Za-z0-9.-]+)(:\d{1,5})?$")


class ConfigError(Exception):
    pass


def _merge(base: dict, extra: dict, path: tuple = ()) -> dict:
    out = copy.deepcopy(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict) and path + (key,) not in _MAPPINGS:
            out[key] = _merge(out[key], value, path + (key,))
        else:
            out[key] = value
    return out


def _namespace(d: dict, path: tuple = ()) -> SimpleNamespace:
    ns = SimpleNamespace()
    for key, value in d.items():
        if isinstance(value, dict) and path + (key,) not in _MAPPINGS:
            value = _namespace(value, path + (key,))
        setattr(ns, key, value)
    return ns


def _validate(cfg: SimpleNamespace) -> None:
    g = cfg.gateway
    g.domains = [d.strip().lower().rstrip(".") for d in g.domains]
    if not g.domains:
        raise ConfigError("gateway.domains is empty: list the domains whose mail Tidegate filters")
    for d in g.domains + [h.lower() for h in [g.hostname]] + list(g.routes):
        if not _DOMAIN.match(d.lower()):
            raise ConfigError(f"not a valid domain or host name: {d!r}")
    for hop in [g.next_hop] + list(g.routes.values()):
        if hop and not _NEXT_HOP.match(hop):
            raise ConfigError(f"not a valid next hop (use host, [host], [host]:port): {hop!r}")
    missing = [d for d in g.domains if not (g.routes.get(d) or g.next_hop)]
    if missing:
        raise ConfigError(f"no next hop for {', '.join(missing)}: set gateway.next_hop or gateway.routes")
    if g.outbound not in ("bounces", "none"):
        raise ConfigError('gateway.outbound must be "bounces" or "none"')
    for net in [g.internal_subnet] + list(g.xclient_hosts) + list(g.xforward_hosts):
        try:
            ipaddress.ip_network(net, strict=False)
        except ValueError as e:
            raise ConfigError(f"not an IP address or network: {net!r}") from e
    f = cfg.filter
    if not 0 < f.tag_score <= f.quarantine_score:
        raise ConfigError("filter.tag_score must be above 0 and not above filter.quarantine_score")
    if f.fail_mode not in ("open", "closed"):
        raise ConfigError('filter.fail_mode must be "open" or "closed"')
    bad = [c for c in list(f.quarantine_categories) + list(f.user_release) if c not in CATEGORIES]
    if bad:
        raise ConfigError(f"unknown categories {bad}; known: {', '.join(CATEGORIES)}")
    for h in cfg.digest.hours:
        if not (isinstance(h, int) and 0 <= h <= 23):
            raise ConfigError("digest.hours must be whole hours from 0 to 23")


def load(path: str | None = None) -> SimpleNamespace:
    path = path or CONFIG_PATH
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError as e:
        raise ConfigError(f"config file not found: {path}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from e
    cfg = _namespace(_merge(DEFAULTS, data))
    _validate(cfg)
    return cfg


def secret_key() -> bytes:
    key = os.environ.get("TIDEGATE_SECRET_KEY", "")
    if len(key) < 32:
        raise ConfigError("TIDEGATE_SECRET_KEY must be set to a random value of at least 32 characters (see .env.example)")
    return key.encode()


def own_domain(domain: str, cfg: SimpleNamespace) -> bool:
    domain = domain.lower().rstrip(".")
    return any(domain == d or domain.endswith("." + d) for d in cfg.gateway.domains)
