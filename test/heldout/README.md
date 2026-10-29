# Held-out set

`heldout.json`: 10 attacks and 10 harmless lookalikes, committed (f9708a9) before the 0.2.0 rules were finished and never used to tune them. It is scored once per rules release, by hand, and is not a test: a test would get tuned to.

| Rules | Attacks stopped | Harmless not stopped | Scored |
|---|---|---|---|
| 0.2.0 | 10 / 10 | 10 / 10 | 2026-10-29 |

The same person wrote the rules and this set, so it checks the rules against new wording, not against an outside attacker. The independent check is `npm run check-pages` on real sites.
