# Contributing to firstwatch

Thanks for helping. The most useful contributions, in order:

1. **An attack firstwatch missed.** Open a [missed attack](https://github.com/dave8172/firstwatch/issues/new?template=missed-attack.yml) issue with the text and where it hid. Even without a fix, this is the work that matters most.
2. **A false alarm.** An ordinary page that firstwatch stopped. Open a [false alarm](https://github.com/dave8172/firstwatch/issues/new?template=false-alarm.yml) issue with the URL.
3. **A new rule or a fix to one.** See below.
4. **An adapter** for another agent's hooks (Codex, Cursor, Gemini CLI, OpenCode…) or for another detector's output. Open an issue first so we can agree on the shape.

## Setup

```bash
git clone https://github.com/dave8172/firstwatch && cd firstwatch
npm test                                   # Node tests (no install needed: zero dependencies)
python3 python/tests/test_firstwatch.py    # Python tests (no install needed)
```

Node 20 or later, Python 3.9 or later.

## How the code is laid out

| Path | What |
|---|---|
| `rules/rules.json` | **The detection rules.** One file, used by both the Node and the Python package |
| `src/` | Node: `scan.js` (pure scanner), `capture.js` (records), `redact.js`, `claude-code.js` (hook adapter), `index.js` (API) |
| `python/src/firstwatch/` | Python: the same modules, kept line for line in step with `src/` |
| `test/fixtures/` + `test/expected.json` | Pages both test suites run, and the result each must give |
| `skills/firstwatch/SKILL.md`, `RULE.md` | The rule for the model, as a skill and as paste-in text |
| `SPEC.md`, `schema/` | The capture format |

## Adding or changing a rule

1. Edit `rules/rules.json`. Patterns must work the same in JavaScript and Python: stick to `\b`, `\s`, `\w`, `[...]`, `(?:...)`, lazy quantifiers and lookbehind. No named groups, no `\p{...}`.
2. Run `npm run sync-rules` to copy the file into the Python package.
3. Add **two fixtures** to `test/fixtures/`: one attack the rule must catch, and one harmless page it must not stop. Add both to `test/expected.json`.
4. Run both test suites.
5. Run the false-alarm check on real pages: `npm run check-pages`. Ordinary pages must stay `clean` or `note`. Put any new stop in your PR description, with a reason.

How levels work:
- Every rule has a `visible` level (people can see the text) and a `hidden` level.
- Hidden text raises a match to `stop`.
- A visible match inside quotes or a code block drops to `note`, because it's someone writing *about* an attack.
- A page that discusses prompt injection at length has its visible stops dropped to notes. Its hidden text still stops.

Keep a rule narrow. A rule that stops ordinary pages gets switched off by users, and then it protects nobody.

## Changing the capture format

Change `SPEC.md`, `schema/capture.schema.json`, and `SPEC` in both `src/capture.js` and `python/src/firstwatch/capture.py` together. Until 1.0, a change that breaks readers bumps the minor version.

## Pull requests

- One change per PR, with tests.
- Zero dependencies in both packages. A PR that adds one needs a very good reason.
- A hook must never break the agent: on bad input or an internal error it exits 0 and prints nothing.
- Numbers in docs are measured, with what they were measured on and the date.
- Plain, short sentences in docs and messages.

By contributing you agree your work is released under the MIT license, and you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
