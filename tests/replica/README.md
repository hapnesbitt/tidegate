# Replica test: Tidegate behind an existing Postfix

This is the "existing Postfix in front" layout from docs/existing-postfix.md, tested on a copy of that Postfix
(the `edge` container) instead of a live mail server. `edge` copies the settings that matter: local delivery to a
Maildir, aliases, `mynetworks`, and the three changes that send outside mail through Tidegate and back.

    tests/replica/run.sh     # needs the lab stack up (tests/lab/run.sh up)

What it proves: mail from outside passes Tidegate exactly once; local programs' mail skips it; if Tidegate is down,
mail goes straight in (fail-open) without looking like a local submission; a refusal from Tidegate never becomes a
bounce; and undoing the three changes restores the old path.
