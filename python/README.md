# firstwatch

**First line of defence for AI agents.** Scans pages, files and tool results for attacks aimed at agents (in the text people see and the text they don't), and records each one as evidence in an open, OpenTelemetry-ready format with MITRE ATLAS and OWASP IDs.

No dependencies. Python 3.9+.

```bash
pip install firstwatch
```

```python
from firstwatch import scan, watch

scan(page_html)
# {"level": "stop", "findings": [{"rule": "exfiltrate-secrets", "hidden": True,
#   "hidden_how": ["css:tiny-text"], "atlas": ["AML.T0086", ...], ...}]}

result = watch(page_html, url=url, tool="fetch")   # scan + save a capture on a stop
if result["level"] == "stop":
    ...  # don't hand the page to the model as instructions; tell the user
```

Command line:

```bash
firstwatch scan page.html
firstwatch list
firstwatch export otlp security-captures/<folder>/capture.json
```

It catches instruction overrides, role hijacks, orders to hide things from the user, requests to send secrets out, requests to reveal the system prompt, `curl | sh` in hidden text, markdown image data leaks, edits to the agent's own setup, and orders aimed at AI assistants. It looks in HTML comments, CSS-hidden elements, attributes, invisible Unicode tag characters, zero-width characters and base64.

The Node package (`npm install firstwatch`) uses the same rules and format, and adds Claude Code hooks that block actions after an attack.

**Docs, examples and the capture format:** https://github.com/dave8172/firstwatch

MIT licensed. Made by [@dave8172](https://x.com/dave8172).
