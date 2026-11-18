# Tidegate behind an existing Postfix

Keep your Postfix as the front door. It queues mail from outside, hands it to Tidegate, and gets it back filtered.
Mail that local programs send (cron, alerts, your own scripts) does not go through Tidegate.

```
Internet ─25─▶ your Postfix ─(FILTER, after queueing)─▶ Tidegate 127.0.0.1:2525 ─▶ back to your Postfix ─▶ mailboxes
```

This layout was tested on a copy of such a Postfix: see [tests/replica](../tests/replica/README.md).

## 1. Start Tidegate on the same server

In `.env`:

```
SMTP_BIND=127.0.0.1
SMTP_PORT=2525
```

In `config/tidegate.toml` (the Docker addresses are the defaults from `.env.example`):

```toml
[gateway]
hostname = "tidegate.internal"
domains = ["example.com"]
next_hop = "[172.31.240.1]:25"    # your Postfix, reached from the container through the Docker bridge
outbound = "none"                 # Tidegate sends nothing to other domains
soft_bounce = true                # never bounce: anything undeliverable stays queued
xforward_hosts = ["172.31.240.1"] # your Postfix passes on the original sender's address (XFORWARD)

[filter]
fail_mode = "open"                # your choice: deliver unscanned (marked) if Rspamd or ClamAV stops answering
quarantine_categories = ["virus", "phish", "impostor"]   # start by holding only clear threats; spam is tagged
```

## 2. Change three things in Postfix

Back up first:

```bash
sudo cp -n /etc/postfix/main.cf /etc/postfix/main.cf.bak-tidegate
sudo cp -n /etc/postfix/master.cf /etc/postfix/master.cf.bak-tidegate
```

**The filter table** says which domains' mail from outside goes through Tidegate:

```bash
echo 'example.com FILTER tidegate:[127.0.0.1]:2525' | sudo tee /etc/postfix/tidegate_filter
```

**The return table** lets Tidegate's deliveries back in without sending them through Tidegate again (the `mta`
container's fixed address):

```bash
echo '172.31.240.25/32 OK' | sudo tee /etc/postfix/tidegate_return.cidr
```

**The transport** in `master.cf`:

```
tidegate  unix  -       -       y       -       4       smtp
  -o syslog_name=postfix/tidegate
  -o myhostname=tidegate-handoff.localdomain
  -o smtp_bind_address=127.0.0.2
  -o smtp_send_xforward_command=yes
  -o smtp_tls_security_level=none
  -o smtp_sasl_auth_enable=no
  -o smtp_fallback_relay=[127.0.0.2]:25
  -o soft_bounce=yes
```

- `smtp_fallback_relay` is the **fail-open path**: if Tidegate can't be reached (or refuses a message), Postfix
  delivers it straight in through 127.0.0.2, unscanned. Why 127.0.0.2: Postfix never uses one of its own listening
  addresses as a fallback ("loops back to myself"), and 127.0.0.2 isn't one; it is inside `mynetworks` (127.0.0.0/8),
  so the mail isn't sent to Tidegate again; and it isn't 127.0.0.1, which some mail tools read as "a local user sent
  this". `smtp_bind_address` makes the connection come from 127.0.0.2 too. Leave both lines out if you prefer
  fail-closed (mail waits in the queue until Tidegate is back).
- `myhostname` here is only the name this transport uses in its greeting; it keeps Postfix's other loop check quiet.
- `soft_bounce=yes` turns any refusal from Tidegate into a retry, so a mistake never bounces a stranger's mail.

**The restriction** in `main.cf`: insert the two checks right after `permit_mynetworks`:

```
smtpd_recipient_restrictions = permit_mynetworks,
    check_client_access cidr:/etc/postfix/tidegate_return.cidr,
    check_recipient_access texthash:/etc/postfix/tidegate_filter,
    reject_unauth_destination
```

Then check and reload:

```bash
sudo postfix check && sudo systemctl reload postfix
```

If a firewall on the server filters port 25, it must let the `mta` container (172.31.240.25) reach it.

## 3. Check it

- New mail from outside carries an `X-Tidegate-Verdict` header, and appears in Tidegate's message log.
- `docker compose logs mta` shows `postfix/tidegate` lines; your Postfix's log shows `relay=127.0.0.1[127.0.0.1]:2525`.
- Mail sent by local programs has no `X-Tidegate-Verdict` header.

## Roll back

Restore `main.cf` and reload. Leave the `tidegate` transport in `master.cf`: mail already queued for Tidegate still
uses it, and its fallback delivers that mail directly if Tidegate is gone.

```bash
sudo cp /etc/postfix/main.cf.bak-tidegate /etc/postfix/main.cf && sudo postfix check && sudo systemctl reload postfix
```

Before removing Tidegate itself, let its queue empty: `docker compose exec mta postqueue -f`, then wait until
`docker compose exec mta postqueue -p` says the queue is empty.
