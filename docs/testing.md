# Testing

Everything below ran on a home-lab server (Debian, Docker 29) on 2026-11-18, with Tidegate 0.1, Rspamd 4.3,
ClamAV 1.5, Postfix 3.10 and Python 3.13. The tests send mail only to example.com and *.test addresses inside a
private Docker network. Nothing leaves the lab.

## Unit tests: 16 of 16

`python3 -m unittest discover -s app/tests` covers:
- look-alike domains, faked own domain, borrowed names, an address in the display name, replies to free mail
- the order of decisions, observe mode, fail-open versus fail-closed
- allow entries that require proof, header edits that keep the body byte for byte
- signed links, the quarantine store, the warning banner

## Lab: 40 of 40 checks

`tests/lab/run.sh up && tests/lab/run.sh test` starts Tidegate with Mailpit standing in for the mail server and sends:

| Message | Result |
|---|---|
| ordinary mail | delivered, with `X-Tidegate-Verdict` and Rspamd's `Authentication-Results` |
| GTUBE (spam test string) | held as spam |
| GTUBE "add header" variant | delivered with `X-Spam-Flag: YES` |
| EICAR (antivirus test file) | held as a virus |
| your own domain, faked (SPF fails) | held as an impostor |
| "Jane Smith" (a protected name) from a free-mail address | held as an impostor |
| look-alike domains (`examp1e.test`, `partner-banks.com`) | delivered with a warning and the banner |
| a sender on the block list | held as blocked |

Also checked:
- **Release link:** opening it shows a confirmation page and releases nothing. Only the button releases.
- **Bad releases fail:** a second release does nothing, a tampered link gets 403, and a virus can't be released from a link.
- **Digest:** it is delivered, and its Release link works end to end.
- **Admin console:** a wrong password is refused, and the log and quarantine pages list the test mail.
- **Scanner outage:** with Rspamd stopped, mail waits in Postfix's queue and arrives once it is back.

## Behind an existing Postfix: 28 of 28 checks

`tests/replica/run.sh` puts Tidegate behind a copy of a working Postfix server (local Maildir delivery, aliases), as in
[existing-postfix.md](existing-postfix.md):
- **Once only:** mail from outside passes Tidegate exactly once, aliases included.
- **Real sender address:** XFORWARD carries the original client's address to Rspamd.
- **Local mail skips it:** mail from local programs (sendmail, SMTP from localhost) skips Tidegate and still looks local.
- **Nothing bounces:**
  - A message Tidegate refuses is delivered by the fail-open path, and no bounce goes to the sender.
  - With Tidegate stopped, mail still arrives, through 127.0.0.2.
  - With Rspamd stopped, mail arrives marked `unscanned` (`fail_mode = "open"`).
- **Rollback:** undoing the Postfix change restores direct delivery.

## What testing changed

- **Fail-open path:** Postfix refuses to use one of its own addresses as a fallback relay ("mail for … loops back to
  myself"), so a LAN-address fallback can't work. The fallback is 127.0.0.2, which is local but isn't one of Postfix's
  own addresses. It also isn't 127.0.0.1, which some mail tools treat as "a local user sent this".
- **Trusted front server:** Tidegate trusts the server in front of it fully. Otherwise a message Tidegate refused
  (say, for a malformed sender address) would go around the filter by the fail-open path.
- **Rspamd hardening:** Rspamd's defaults let anything on the network ask it to scan a file path, so that is now off,
  and its controller and proxy listen inside the container only. Its task timeout was raised above the virus-scan timeout.
- **Test data:** a "clean" test message from example.net scored 9.8. example.net's real SPF and DMARC records reject
  mail from the test address, so the score was correct and the test data was wrong. The tests now use .test domains,
  which have no DNS records.

## Next

Detection rates on public spam and phishing sample sets (the SpamAssassin public corpus and a public phishing corpus)
will be added here.
