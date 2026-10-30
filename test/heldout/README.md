# Held-out sets

A held-out set is written **before** the rules it tests, by someone (or a separate agent) that doesn't see those rules, and is scored **once**. After that it has been seen, so it moves into the scorecard (`test/scorecard/`), which every test run checks, and the next rules change needs a new set.

| Set | Written | Rules scored | Attacks flagged | Harmless stopped | Notes |
|---|---|---|---|---|---|
| `heldout.json` | 2026-10-29, before the 0.2 rules were finished | 0.2.0 | 10 / 10 (stop) | 0 / 10 | Same author as the rules |
| `heldout-0.3.json` | 2026-10-30 by a separate agent that saw neither the rules nor the case that prompted them; sha256 `14f66ce7…69c9b63`, hashed before the rules were written | first draft of the 0.3 rules | 5 / 30 (0.2.0: 2 / 30) | **3 / 30** | The draft was dropped: it stopped ordinary text such as "drop whatever you're working on Friday". The 0.3.0 rules were then written with this set in view, so their score on it (21 / 30 attacks stopped, 0 / 30 harmless flagged; see the scorecard) is not a held-out result. |

The independent checks, by people other than the rule author: `npm run check-pages` on real sites, `node scripts/injecagent.mjs` on a public benchmark, and `npm run drift` on any folder of ordinary documents.
