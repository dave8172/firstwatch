# Examples

| Example | What it shows |
|---|---|
| [`capture/`](capture/) | A real capture folder, made by running firstwatch on [`test/fixtures/white-text.html`](../test/fixtures/white-text.html): the README a person reads, the `capture.json` a tool reads, and the page source saved as `.txt` |
| [`python_fetch_tool.py`](python_fetch_tool.py) | A fetch tool for your own Python agent: scans every page and hands the model a warning when the page carries an attack |
| [`node-fetch-tool.mjs`](node-fetch-tool.mjs) | The same tool for a Node agent |
| [`agents/`](agents/) | firstwatch in LangChain and LangGraph, the OpenAI Agents SDK, CrewAI and a plain Python loop: scan every tool result, then hold actions after an attack. Guide: [docs/frameworks.md](../docs/frameworks.md) |
| [`claude-code-settings.json`](claude-code-settings.json) | The Claude Code hooks without the plugin, for `.claude/settings.json` |
| [`opentelemetry/`](opentelemetry/) | Send captures to an OpenTelemetry Collector, and from there to your observability backend |

Try one without installing anything:

```bash
PYTHONPATH=python/src python3 examples/python_fetch_tool.py test/fixtures/white-text.html
node examples/node-fetch-tool.mjs test/fixtures/white-text.html
```
