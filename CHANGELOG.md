# Changelog

All notable changes. Versions follow [semantic versioning](https://semver.org); until 1.0, a minor bump can break the capture format or the API.

## 0.2.0 — 2026-10-29

- **Three new rules** for requests written to a person, the kind an agent meets in mail and messages: `request-secrets` (reply with or send back passwords, keys, codes, card numbers), `request-all-files` (send the contents of every file, email or document), `bulk-delete` (delete everything). A sentence that says *never* or *don't* is skipped, so "we will never ask you to reply with your password" stays clean. Rules version 0.2.0.
- **`firstwatch/scan` runs in browsers and bundlers:** the rules now ship as a generated module (`src/rules-data.js`), so the scanner needs no file access. Base64 decoding uses `atob` instead of Node's `Buffer`: in a browser, text hidden in base64 was silently skipped.
- **The Claude Code warning no longer stops the agent's work.** 0.1's warning ("outward actions in this session need their approval") made agents drop the user's whole task after an attack: in a measured email agent, the task went from 93% done without firstwatch to 29%. 0.2's warning refuses only what the hostile text asks, says the user's task still stands, and leaves the asking to the gate: 99% done, against 92% for the same agent without firstwatch, 0 harmful attempts either way ([docs/agent-study.md](docs/agent-study.md)). The warning and the risky-verb list now live in `src/gate.js` (`firstwatch/gate`), browser-safe.
- Measured on the same 18 real sites as 0.1: still one stop, the same real attack. A held-out set (`test/heldout/`) written before the rules were finished: 10 of 10 attacks stopped, 10 of 10 harmless lookalikes not stopped.

## 0.1.1 — 2026-10-29

- OTLP export sets `observedTimeUnixNano` (the collector showed 1970 without it).
- Docs: OTLP export tested against a live OpenTelemetry Collector.

## 0.1.0 — 2026-10-29

First release.

- **Scanner** (Node and Python, same rules file): instruction overrides, role hijacks, hidden-from-user orders, requests to send secrets out, requests to reveal instructions, `curl | sh` in hidden text, markdown image data leaks, edits to the agent's own setup, orders to AI assistants. Finds text hidden in HTML comments, CSS (display, visibility, tiny, white, off-screen, zero-size), `hidden` and `aria-hidden`, alt/title/meta attributes, Unicode tag characters, zero-width characters and base64.
- **Capture format** `firstwatch/0.1` (SPEC.md, JSON Schema): OpenTelemetry attribute names, MITRE ATLAS and OWASP LLM Top 10 (2025) IDs, OTLP/JSON export.
- **Claude Code plugin:** PostToolUse hook scans results and warns the agent; PreToolUse hook gates non-read actions after an attack, and always asks for MCP tools that send, pay, delete, share or grant.
- **Skill** and **RULE.md** for any agent.
- **CLI** (`firstwatch` on npm and PyPI): scan, capture, list, validate, export otlp, clear.
- **Library:** `scan()` and `watch()` in Node and Python.
