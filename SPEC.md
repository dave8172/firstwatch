# The firstwatch capture format, version 0.1

One attack on an AI agent, recorded so that anyone can read it, reproduce it and load it into their own tools. Spec ID: `firstwatch/0.1`. JSON Schema: [`schema/capture.schema.json`](schema/capture.schema.json).

**Status: draft.** Field names may still change before 1.0. A change that breaks readers bumps the minor version until 1.0, then the major.

## Why a format

Detectors and guards already exist. Each one logs what it finds in its own shape, or not at all, so attacks seen in one tool can't be compared with attacks seen in another. This format is the shared record: what the attack said, where it hid, what it tried, what happened, how to reproduce it. Any detector, hook or agent can write one.

## Where a capture lives

A **stop** is a folder:

```
security-captures/
  2026-10-29-shop-example-exfiltrate-secrets/
    README.md        for people: summary, exact text, findings, steps to reproduce
    capture.json     the record below
    raw.html.txt     optional evidence; page source is always saved as .txt
  index.jsonl        one line per stop capture
  notes.jsonl        one line per note (no folder)
```

Folder name: `<YYYY-MM-DD>-<host or file or tool>-<main rule>`, with `-2`, `-3` … if taken.

## Levels

| Level | Meaning | What the agent does |
|---|---|---|
| `stop` | Tries to make the agent act, reveal, send, pay, sign up, grant access or install | Does not follow it, stops that line of work, captures it in full, tells its owner |
| `note` | Suspicious but asks for nothing the agent could do | Does not follow it, records one line, carries on |

## Fields

| Field | Type | Required | Meaning |
|---|---|---|---|
| `spec` | string | yes | Always `firstwatch/0.1` |
| `id` | string | yes | Unique ID, e.g. `fw_20261029T140639_f6af8b` |
| `time` | string | yes | When it was seen. ISO 8601 with a UTC offset |
| `level` | `stop` \| `note` | yes | See above |
| `summary` | string | yes | One line for people |
| `source.kind` | string | yes | `web`, `file`, `command`, `tool`, `search`, `message`, `email`, `other` |
| `source.url` | string \| null | | Full URL, when there is one |
| `source.file` | string \| null | | File path, when there is one |
| `source.tool` | string \| null | | The tool whose result carried it, e.g. `WebFetch`, `mcp__mail__read` |
| `source.where` | string \| null | | Where in the content: `HTML comment`, `hidden <div>`, `alt attribute`, `visible text` … |
| `payload.text` | string | yes | The exact text, word for word (secrets masked) |
| `payload.hidden` | boolean | yes | Was it hidden from people? |
| `payload.hidden_how` | string[] | | How: `html-comment`, `css:display-none`, `css:tiny-text`, `css:white-or-transparent-text`, `css:off-screen`, `attr:hidden`, `attribute:alt`, `unicode-tag-characters`, `zero-width-characters`, `base64` … |
| `findings` | object[] | yes | What each rule found (below). May be empty when an agent records an attack no rule knows |
| `intent` | string | | What it tried to make the agent do |
| `outcome` | string | yes | `blocked`, `followed`, `partial`, `unknown`. Honest beats flattering: a partial follow is the most useful capture |
| `caught_by` | string | yes | `hook`, `agent`, `scanner`, `owner` |
| `trace.task` | string | | The agent's task, one line |
| `trace.steps` | object[] | | The steps before it: `{ tool, summary }` |
| `repro` | string[] | yes | Steps someone else can follow to see it |
| `evidence` | string[] | | Files in the folder, e.g. `raw.html.txt` |
| `redactions` | number | | How many values were masked before saving |
| `notes` | string | | Anything else |
| `attributes` | object | | Flat attributes for telemetry (below) |

### A finding

| Field | Meaning |
|---|---|
| `rule` | Rule ID, e.g. `exfiltrate-secrets`, `override-instructions`, `unicode-tag-smuggling` |
| `what` | The rule in plain words |
| `level` | `stop` or `note` |
| `hidden`, `hidden_how`, `where` | As above, for this finding |
| `excerpt` | The matching text with a little context |
| `atlas` | MITRE ATLAS technique IDs, e.g. `AML.T0051.001` (LLM Prompt Injection: Indirect) |
| `owasp` | OWASP Top 10 for LLM Applications 2025 IDs, e.g. `LLM01:2025` |
| `context` | Optional, e.g. `page discusses attacks` when a visible example was downgraded to a note |

## Telemetry attributes

`attributes` is flat, so a capture becomes one OpenTelemetry log record with no mapping table (`firstwatch export otlp capture.json` prints it as OTLP/JSON, ready to POST to a collector's `/v1/logs`).

Where OpenTelemetry has a convention, the capture uses it:

| Attribute | From |
|---|---|
| `gen_ai.conversation.id` | the agent session |
| `gen_ai.operation.name` | `execute_tool` when a tool result carried the attack |
| `gen_ai.tool.name`, `gen_ai.tool.call.id` | the tool and the call |
| `gen_ai.agent.name` | the agent, when known |
| `url.full`, `server.address` | the source URL and host |
| `event.name` | `firstwatch.capture` |

OpenTelemetry's generative AI conventions are still in development, and they have no attributes for attacks yet. Those live under `firstwatch.*`: `firstwatch.level`, `firstwatch.outcome`, `firstwatch.caught_by`, `firstwatch.hidden`, `firstwatch.rules`, `firstwatch.atlas.techniques`, `firstwatch.owasp.ids`, `firstwatch.capture.id`, `firstwatch.spec`. If a convention appears, the capture will carry both names for one minor version, then the standard one.

## Privacy

- Secrets (API keys, tokens, private keys, `password=` values, bearer tokens) are masked everywhere before saving.
- Email addresses are masked in the trace. They are kept in the payload and raw evidence, because an attacker's address is evidence.
- Captures are written locally and never sent anywhere by firstwatch. Sharing one is the owner's decision, per capture.
- Raw page source is saved as `.txt`, so it can't run if someone opens it.
