# firstwatch: notes for maintainers

Public repo. This file ships with it: nothing personal, no project names, no machine paths.

**What it is:** first line of defence for AI agents. Scans tool results for attacks aimed at agents, records each as a capture (SPEC.md), and gates outward actions after one. Two packages from one repo: npm (Node library + CLI + Claude Code hooks + plugin + skill) and PyPI (Python library + CLI).

**What it owns / what the user owns:** firstwatch owns the rules, the capture format and the gate decision. The user owns where captures go and whether any capture leaves the machine.

## Layout

| Path | What |
|---|---|
| `rules/rules.json` | **the only place rules live.** Both packages load it. After editing: `npm run sync-rules` (copies it into the Python package, regenerates `docs/rules.md`) |
| `src/` | Node: `scan.js` (pure), `capture.js`, `redact.js`, `claude-code.js` (hook adapter), `index.js` (API), `rules.js` (loader) |
| `python/src/firstwatch/` | Python: the same modules, line for line. A change to one side is a change to both |
| `test/fixtures/` + `test/expected.json` | shared by both test suites |
| `test/scorecard/` | every labelled text (`cases.json`) and its accepted level (`baseline.json`), checked by both suites. `npm run scorecard` shows changes; `-- --update` accepts them and refuses anything worse |
| `test/heldout/` | held-out sets: written before the rules they test, by someone who doesn't see them, scored once, then moved into the scorecard. Its README keeps the scores |
| `test/self.test.js` | the repo checks itself: no invisible characters, rules copy in sync, rules doc current |
| `skills/firstwatch/SKILL.md` · `RULE.md` | the rule for the model. Keep them in step |
| `hooks/hooks.json` · `.claude-plugin/` | Claude Code plugin + marketplace |
| `SPEC.md` · `schema/` | the format. Change both together, and `SPEC` in both packages |
| `scripts/check-pages.mjs` + `pages.txt` | false-alarm check on real sites. Run before every release |
| `scripts/drift.mjs` | the last release vs the working tree on the same texts: `npm run drift -- <tag> <folders of ordinary docs>`. Every changed text gets a look |
| `scripts/injecagent.mjs` | outside benchmark (InjecAgent, pinned commit), last release vs working tree |

## Rules for changes

- **Zero dependencies** in both packages.
- **A hook must never break the agent.** Bad input or an internal error → exit 0, no output.
- **Every rule change:** an attack fixture + a harmless fixture, both suites green, `npm run check-pages` reviewed.
- **Don't tune on the test.** Before a rules change, get a new held-out set written by someone (or a separate agent) who sees neither the rules nor the case that prompted them; hash it, then write the rules, then score it once. A good score on texts the rules were written from proves nothing: the 0.3 first draft scored 29/30 on its own examples and stopped 3 of 30 harmless texts in the held-out set.
- **Scorecard changes are deliberate.** A rule or scanner change that moves any scorecard case fails the tests; `npm run scorecard -- --update` accepts the new levels and refuses changes for the worse unless `--allow-worse` (say why in the commit).
- **The warning text is pinned** by a test to the text the agent study measured. New wording: re-run the study first, then update the hash.
- **Never type `\uXXXX` escapes straight into a file.** They can land as the real invisible characters. Build them from `chr(92)`/`String.fromCharCode(92)`. `test/self.test.js` catches it.
- **Numbers in README and docs are measured,** dated, with what they were measured on.

## Release

1. Bump the version in `package.json`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `python/pyproject.toml`, `VERSION` in `src/capture.js` and `python/src/firstwatch/capture.py`, and `rules/rules.json` if the rules changed. Then update CHANGELOG.md.
2. Both test suites, `npm run check-pages`, `npm run drift -- <last tag> <a folder of ordinary docs>`, `npm run injecagent`, `claude plugin validate .`. Every changed result gets a look; put the numbers in CHANGELOG.md.
3. Tag `vX.Y.Z`, push, publish a GitHub release. `publish-pypi.yml` (trusted publishing) and `publish-npm.yml` (trusted publishing + provenance) run from it, and both skip a version that's already out.

## Status

0.3.0, 2026-10-30. Releases go out through GitHub Actions trusted publishing on both registries.
