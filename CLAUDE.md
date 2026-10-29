# firstwatch: notes for maintainers

Public repo. This file ships with it: nothing personal, no project names, no machine paths.

**What it is:** first line of defence for AI agents. Scans tool results for attacks aimed at agents, records each as a capture (SPEC.md), and gates outward actions after one. Claude Code hooks + a skill + a paste-in rule + a CLI.

**What it owns / what the user owns:** firstwatch owns the rules, the capture format and the gate decision. The user owns where captures go and whether any capture leaves the machine.

## Layout

| Path | What |
|---|---|
| `src/rules.js` | detection rules, ATLAS + OWASP IDs |
| `src/scan.js` | splits input into seen/hidden segments, runs rules. Pure, no I/O |
| `src/redact.js` | masks secrets (and emails outside the payload) |
| `src/capture.js` | builds, validates, writes captures; OTLP export; session gate state |
| `src/claude-code.js` | Claude Code hook adapter (PostToolUse scan, PreToolUse gate) |
| `bin/firstwatch.js` | CLI |
| `skills/firstwatch/SKILL.md` · `RULE.md` | the rule for the model: skill form, paste-in form. Keep them in step |
| `hooks/hooks.json` · `.claude-plugin/` | Claude Code plugin + marketplace |
| `SPEC.md` · `schema/capture.schema.json` | the format. Change both together |

## Rules for changes

- **Zero dependencies.** Node built-ins only.
- **A hook must never break the agent.** Bad input or an internal error → exit 0, no output.
- **Every new rule comes with a fixture that triggers it and one harmless page that must not** (`test/fixtures`). Re-run the real-page check before release: raw HTML of ordinary sites must not stop.
- **Hidden text escalates; visible quoted examples downgrade.** A visible match only stops when it is an attack in its own right, not a description of one.
- **Numbers in README are measured,** with what they were measured on and the date.
- **Format changes:** bump `SPEC` in `src/capture.js`, SPEC.md and the schema together. Draft until 1.0.
- Test: `npm test`. Check: `node --check` every file (importing the CLI runs it). Plugin: `claude plugin validate .`.

## Status

0.1.0, built 2026-10-29. Not published yet (no GitHub remote, not on npm).
