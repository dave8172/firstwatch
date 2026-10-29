# Changelog

All notable changes. Versions follow [semantic versioning](https://semver.org); until 1.0, a minor bump can break the capture format or the API.

## 0.1.0 — 2026-10-29

First release.

- **Scanner** (Node and Python, same rules file): instruction overrides, role hijacks, hidden-from-user orders, requests to send secrets out, requests to reveal instructions, `curl | sh` in hidden text, markdown image data leaks, edits to the agent's own setup, orders to AI assistants. Finds text hidden in HTML comments, CSS (display, visibility, tiny, white, off-screen, zero-size), `hidden` and `aria-hidden`, alt/title/meta attributes, Unicode tag characters, zero-width characters and base64.
- **Capture format** `firstwatch/0.1` (SPEC.md, JSON Schema): OpenTelemetry attribute names, MITRE ATLAS and OWASP LLM Top 10 (2025) IDs, OTLP/JSON export.
- **Claude Code plugin:** PostToolUse hook scans results and warns the agent; PreToolUse hook gates non-read actions after an attack, and always asks for MCP tools that send, pay, delete, share or grant.
- **Skill** and **RULE.md** for any agent.
- **CLI** (`firstwatch` on npm and PyPI): scan, capture, list, validate, export otlp, clear.
- **Library:** `scan()` and `watch()` in Node and Python.
