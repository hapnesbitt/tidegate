<p align="center"><img src="app/tidegate/static/logo.svg" width="96" alt="Tidegate logo"></p>

# Tidegate

**A free, open-source email security gateway you run yourself.** Tidegate sits in front of your mail server (Microsoft 365, Google Workspace, Exchange, Postfix or anything else that speaks SMTP). It checks every incoming message for spam, viruses, phishing links and impostors, holds the bad ones in a quarantine, and sends each person a daily digest so they can release their own false positives with one click.

It is built from proven open-source parts: [Postfix](https://www.postfix.org/) receives the mail, [Rspamd](https://rspamd.com/) scores it, [ClamAV](https://www.clamav.net/) scans attachments, and a small Python service (this repository) makes the decisions, keeps the quarantine and serves the web pages. Everything runs from one Docker Compose file.

> **Not affiliated with Proofpoint.** Tidegate is an independent project. It is not affiliated with, endorsed by, sponsored by or connected to Proofpoint, Inc. or any other email security vendor. It contains no code, documentation or designs from any vendor. All trademarks belong to their owners.

Status: **0.1, first release.** It works and is tested (see [Testing](#testing)), but it is young. Try it on a test domain first.

## What it does

- **Filters incoming mail** with Rspamd (hundreds of spam rules, SPF, DKIM, DMARC, DNS blocklists, Bayes learning) and ClamAV.
- **Quarantine with a daily digest.** Held spam is listed in one email per person per day. Each entry has a **Release** button. Opening a link only shows a confirmation page, so the link scanners in many mail systems can't release mail by accident.
- **Impostor warnings** (business email compromise):
  - your own domain faked (DMARC or SPF failed),
  - a protected person's name (your CEO, say) used on mail from outside,
  - look-alike domains (`examp1e.com`, `exarnple.com`, `example-billing.com`, `example.co`, and lookalikes in other alphabets),
  - an address written into the display name,
  - replies diverted to a free mailbox.

  Clear cases are held. Doubtful ones are delivered with a warning header and, if you turn it on, a warning banner.
- **Simple policy:** allow and block lists for everyone or one person. An allowed sender skips the spam checks only after proving who it is (DMARC, or SPF for the envelope sender), so a forged address can't use an allow entry.
- **Message log:** every message, its score, the result and the reasons, searchable for 30 days.
- **Observe mode:** let spam through tagged (`X-Spam-Flag: YES`) while you watch what would have been held, then turn holding on.
- **Fail-closed or fail-open:** if a scanner stops answering, mail either waits in the queue (the default) or is delivered unscanned and marked.

### Not in 0.1 yet

DMARC aggregate-report dashboard (planned next; [parsedmarc](https://github.com/domainaware/parsedmarc) does this well today), link checks at click time, outbound filtering and DKIM signing, attachment sandboxing, removing mail that was already delivered, multiple organizations in one install.

## How it works

```
 Internet ──25──▶  mta (Postfix) ──pipe──▶ Tidegate filter ──HTTP──▶ Rspamd ──▶ ClamAV
                        ▲                        │                     │
                        │ 10025 (re-injection)   ├─ clean / tagged / warned ──▶ back to Postfix ──▶ your mail server
                        │                        └─ held ──▶ quarantine (files + SQLite)
                        │                                          │
                   web (release pages, admin console) ◀────────────┘      scheduler: digests, clean-up
```

1. Postfix accepts mail for your domains and queues it on disk.
2. For each recipient it runs Tidegate's filter, which asks Rspamd (and through it ClamAV) for a verdict, adds its own impostor checks and your allow/block lists, and decides: deliver, deliver tagged, deliver with a warning, or hold.
3. Delivered mail goes back to Postfix on an internal port and on to your mail server. Held mail is written to disk before Postfix is told "done", so nothing is lost if a container restarts.

Containers: `mta`, `web`, `scheduler` (all from `app/`), `rspamd`, `clamav`, `valkey` (Rspamd's Redis-compatible store) and `unbound` (a private DNS resolver; DNS blocklists refuse queries from big public resolvers).

## Requirements

- A Linux host with Docker Engine and the Compose plugin.
- About **2.5 GB of RAM** (ClamAV alone uses about 1.3 GB) and 5 GB of disk.
- Port 25 reachable from the internet, a DNS name for the gateway, and (for the digest) a web address people can reach over HTTPS.

## Install

```bash
git clone https://github.com/hapnesbitt/tidegate.git
cd tidegate
cp .env.example .env
cp config/tidegate.toml.example config/tidegate.toml
```

1. Put a random secret in `.env`:
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
   Paste it after `TIDEGATE_SECRET_KEY=`.
2. Edit `config/tidegate.toml`: your domains, your mail server (`next_hop`), the digest sender and the public URL of the release pages.
3. Build, then make the admin password:
   ```bash
   docker compose build
   docker compose run --rm --no-deps web cli passwd
   ```
   Paste the printed line after `TIDEGATE_ADMIN_PASSWORD_HASH=` in `.env`.
4. Optional: put a real TLS certificate for the gateway's name in `certs/fullchain.pem` and `certs/privkey.pem`. Without one, Postfix uses a self-signed certificate, which is normal for mail between servers.
5. Start it. The first start takes a few minutes while ClamAV downloads its signatures.
   ```bash
   docker compose up -d
   docker compose ps
   ```
6. Open the admin console through an SSH tunnel (it listens on 127.0.0.1 only):
   ```bash
   ssh -L 8080:127.0.0.1:8080 your-gateway-host
   ```
   Then browse to <http://127.0.0.1:8080>.
7. Send a test message, check it in **Message log**, then point your MX record at the gateway.

### Point your mail at it

- **Any mail server:** set your domain's MX record to the gateway. On your mail server, accept mail from the gateway's IP address, and later refuse direct connections from elsewhere so nobody can go around the filter.
- **Microsoft 365:** create an inbound connector for mail from the gateway's IP address, and turn on *Enhanced Filtering for Connectors* so Microsoft sees the original sender's address instead of the gateway's.
- **Google Workspace:** add the gateway's IP address as an inbound gateway in the Gmail spam settings.

### Already running Postfix?

You can keep your Postfix as the front door and hand mail to Tidegate after it is queued. See [docs/existing-postfix.md](docs/existing-postfix.md): three settings, a tested fail-open path, and a one-command rollback.

### Release pages over HTTPS

The digest's links point at `public_url`. Put a TLS reverse proxy in front of the `web` container and expose only the release pages, not the admin console. With Caddy:

```
quarantine.example.com {
    @release path /r/* /u/* /static/*
    handle @release {
        reverse_proxy 127.0.0.1:8080
    }
    respond 404
}
```

Set `trust_proxy = true` in the `[web]` section when a proxy sits in front.

## Settings

Everything about filtering is in [`config/tidegate.toml.example`](config/tidegate.toml.example), with each default shown. The main choices:

| Setting | Default | What it does |
|---|---|---|
| `filter.quarantine_score` | 10 | Rspamd score at which a message counts as spam |
| `filter.tag_score` | 6 | Score at which it is delivered with `X-Spam-Flag: YES` |
| `filter.quarantine_categories` | all five | Which categories are held; the rest are delivered, tagged and logged (observe mode) |
| `filter.user_release` | `["spam"]` | What people may release themselves; viruses, phishing and impostors need an admin |
| `filter.fail_mode` | `closed` | `open` delivers unscanned (and marked) while a scanner is down |
| `impostor.vip_names` | none | Names attackers might borrow |
| `impostor.banner` | off | Visible warning in the message body (see the DKIM note below) |

Rspamd's own settings are in `rspamd/local.d/`. Anything in Rspamd's documentation can go there.

## Testing

Two test suites run on any Docker host. They never send mail outside the lab.

```bash
tests/lab/run.sh up      # builds and starts a lab copy, with Mailpit as the mail server behind it
tests/lab/run.sh test    # unit tests, then end-to-end checks
tests/replica/run.sh     # Tidegate behind an existing Postfix: once-only filtering, fail-open, rollback
tests/lab/run.sh down
```

The end-to-end checks use the standard GTUBE and EICAR test strings and made-up impostor messages. They cover verdicts, headers, release links (opening a link must not release anything; tampered links are refused), the digest, the admin console and a scanner outage. Results from public spam and phishing samples are in [docs/testing.md](docs/testing.md).

## Monitoring

`ops/textfile_probe.py` reads Tidegate's queue, the last day's results and held mail. It writes Prometheus metrics for node-exporter's textfile collector and prints one status line (OK, HELD, STUCK or DOWN), which you can send to a status board. Run it from cron every 5 minutes on the Docker host. Alert on `tidegate_queue_oldest_age_seconds` (mail waiting inside Tidegate) and `tidegate_up`. Behind an existing Postfix, `--front-postfix` also watches that Postfix's queue for your domains. It reports only counts and the sender domains of held mail: never addresses, names or subjects.

## Security notes

- **The admin console listens on 127.0.0.1 only.** Reach it through SSH or a VPN. Sign-in uses a scrypt password hash, and failed attempts are throttled. Cookies are `HttpOnly` and `SameSite=Strict`, and every form has a CSRF token.
- **Release links are the credential.** They are HMAC-signed, expire after `link_days` (14 by default), name one message and one person, and only release on a button press. Viruses, phishing and impostor messages can't be released from a link.
- **Message content is never rendered.** The console shows held mail as plain text and never fetches its links or images. Pages send a strict Content-Security-Policy and `Referrer-Policy: no-referrer`.
- **Nothing is lost on errors.** Any filter error makes Postfix retry later. Held mail is synced to disk before Postfix is told it is done.
- **What leaves the server:** DNS lookups of sender addresses, IPs and link domains against blocklists (standard for every spam filter), daily ClamAV signature downloads, and the OpenPhish feed download. Rspamd's public fuzzy-hash check is **off**, so no hashes of message text are sent anywhere.
- **Banners change messages.** A banner (and any change to the body or subject) breaks the sender's DKIM signature. Leave `impostor.banner` off unless your mail server trusts the gateway (Microsoft 365: Enhanced Filtering for Connectors; or ARC sealing in Rspamd). Warning headers alone don't affect DKIM.
- **Secrets** live only in `.env` (git-ignored). Rotate `TIDEGATE_SECRET_KEY` to cancel every outstanding link.
- **Report a vulnerability** privately; see [SECURITY.md](SECURITY.md).

## Screenshots

| Overview | Message log | A held message |
|---|---|---|
| ![Overview](docs/screenshots/overview.png) | ![Message log](docs/screenshots/messages.png) | ![Held message](docs/screenshots/item.png) |

## License

Tidegate's own code is under the [Apache License 2.0](LICENSE). It runs these projects, unchanged, as separate containers under their own licenses: Postfix (IBM Public License 1.0 / Eclipse Public License 2.0), Rspamd (Apache-2.0), ClamAV (GPL-2.0), Valkey (BSD-3-Clause), Unbound (BSD-3-Clause), Debian and Alpine packages (various free licenses), and, for tests only, Mailpit (MIT). Flask, Jinja2 and Waitress (BSD-style and ZPL) come from Debian packages.

**Why Apache-2.0:** it matches Rspamd, the engine Tidegate is built on. It lets companies run and change Tidegate without legal hurdles, and it includes a patent grant that protects users and contributors.

## Not affiliated

Tidegate is an independent, community project by Ross Nesbitt. It is not affiliated with, endorsed by, sponsored by or connected to Proofpoint, Inc., Microsoft, Google or any other company. Product names are mentioned only to say what Tidegate works with. All trademarks belong to their owners.
