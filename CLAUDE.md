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
| `test/self.test.js` | the repo checks itself: no invisible characters, rules copy in sync, rules doc current |
| `skills/firstwatch/SKILL.md` · `RULE.md` | the rule for the model. Keep them in step |
| `hooks/hooks.json` · `.claude-plugin/` | Claude Code plugin + marketplace |
| `SPEC.md` · `schema/` | the format. Change both together, and `SPEC` in both packages |
| `scripts/check-pages.mjs` + `pages.txt` | false-alarm check on real sites. Run before every release |

## Rules for changes

- **Zero dependencies** in both packages.
- **A hook must never break the agent.** Bad input or an internal error → exit 0, no output.
- **Every rule change:** an attack fixture + a harmless fixture, both suites green, `npm run check-pages` reviewed.
- **Never type `\uXXXX` escapes straight into a file.** They can land as the real invisible characters. Build them from `chr(92)`/`String.fromCharCode(92)`. `test/self.test.js` catches it.
- **Numbers in README and docs are measured,** dated, with what they were measured on.

## Release

1. Bump the version in `package.json`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `python/pyproject.toml`, `VERSION` in `src/capture.js` and `python/src/firstwatch/capture.py`, and `rules/rules.json` if the rules changed. Then update CHANGELOG.md.
2. Both test suites, `npm run check-pages`, `claude plugin validate .`.
3. Tag `vX.Y.Z`, push, publish a GitHub release. `publish-pypi.yml` (trusted publishing) and `publish-npm.yml` (trusted publishing + provenance) run from it, and both skip a version that's already out.

## Status

0.1.1, 2026-10-29. Releases go out through GitHub Actions trusted publishing on both registries.
