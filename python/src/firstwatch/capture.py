"""Build, check and write capture records (format: SPEC.md, firstwatch/0.1). Mirrors src/capture.js."""

import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from ._rules import ATLAS, OWASP, PRIORITY
from .redact import redact, redact_deep

SPEC = "firstwatch/0.1"
VERSION = "0.1.1"
LEVELS = ["stop", "note"]
OUTCOMES = ["blocked", "followed", "partial", "unknown"]
CAUGHT_BY = ["hook", "agent", "scanner", "owner"]
KINDS = ["web", "file", "command", "tool", "search", "message", "email", "other"]
MAX_EVIDENCE = 2_000_000
_TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d:\d\d)$")


def primary(findings):
    """Most serious first: what the attack does, then how it hides."""
    def rank(f):
        i = PRIORITY.index(f["rule"]) + 1 if f.get("rule") in PRIORITY else 50
        return (0 if f.get("level") == "stop" else 100) + i
    return sorted(findings, key=rank)[0] if findings else None


def capture_dir(cwd=None):
    return Path(os.environ.get("FIRSTWATCH_DIR") or Path(cwd or os.getcwd()) / "security-captures").resolve()


def iso_local(d=None):
    """ISO 8601 in local time with the UTC offset, e.g. 2026-10-29T14:05:00.123+05:30."""
    return (d or datetime.now()).astimezone().isoformat(timespec="milliseconds")


def _slug(s):
    s = re.sub(r"^www\.", "", str(s or "unknown").lower())
    return re.sub(r"[^a-z0-9]+", "-", s).strip("-")[:40] or "unknown"


def _host(url):
    try:
        return urlparse(url).hostname if url else None
    except ValueError:
        return None


def validate(rec):
    """Every problem at once, not the first. Returns a list of strings (empty = valid)."""
    if not isinstance(rec, dict):
        return ["record must be an object"]
    p = []

    def need(cond, msg):
        if not cond:
            p.append(msg)

    src, pay = rec.get("source") or {}, rec.get("payload") or {}
    need(rec.get("spec") == SPEC, f'spec must be "{SPEC}"')
    need(isinstance(rec.get("id"), str) and rec["id"], "id is required")
    need(isinstance(rec.get("time"), str) and _TIME.match(rec["time"]), "time must be ISO 8601 with a UTC offset")
    need(rec.get("level") in LEVELS, f"level must be one of {', '.join(LEVELS)}")
    need(isinstance(rec.get("summary"), str) and rec["summary"].strip(), "summary is required")
    need(src.get("kind") in KINDS, f"source.kind must be one of {', '.join(KINDS)}")
    need(isinstance(pay.get("text"), str) and pay["text"], "payload.text (the exact text) is required")
    need(isinstance(pay.get("hidden"), bool), "payload.hidden must be true or false")
    need(isinstance(rec.get("findings"), list), "findings must be a list")
    need(rec.get("outcome") in OUTCOMES, f"outcome must be one of {', '.join(OUTCOMES)}")
    need(rec.get("caught_by") in CAUGHT_BY, f"caught_by must be one of {', '.join(CAUGHT_BY)}")
    need(isinstance(rec.get("repro"), list), "repro must be a list of steps")
    return p


def build(data):
    """Turn partial input (from a hook, an agent or your code) into a full record. Redacts as it goes."""
    now = datetime.now(timezone.utc)
    findings = data.get("findings") or []
    top = primary(findings) or {}
    source = data.get("source") or {}
    payload_in = data.get("payload") or {}
    url = source.get("url")
    text, n1 = redact(payload_in.get("text") or top.get("excerpt") or "", keep_emails=True)
    trace, n2 = redact_deep(data.get("trace") or {})
    intent = data.get("intent") or top.get("what") or ""
    hidden = payload_in.get("hidden", bool(top.get("hidden")))
    where = f" on {_host(url)}" if url else (f" in {os.path.basename(source['file'])}" if source.get("file") else "")
    rec = {
        "spec": SPEC,
        "id": f"fw_{now.strftime('%Y%m%dT%H%M%S')}_{secrets.token_hex(3)}",
        "time": data.get("time") or iso_local(),
        "level": data.get("level") or ("stop" if any(f.get("level") == "stop" for f in findings) else "note"),
        "summary": data.get("summary") or f"{'Hidden text' if hidden else 'Text'}{where}: {intent or 'targets AI agents'}",
        "source": {
            "kind": source.get("kind") or ("web" if url else "other"),
            "url": url,
            "tool": source.get("tool"),
            "where": source.get("where") or top.get("where"),
            "file": source.get("file"),
        },
        "payload": {"text": text, "hidden": hidden, "hidden_how": payload_in.get("hidden_how", top.get("hidden_how", []))},
        "findings": findings,
        "intent": intent,
        "outcome": data.get("outcome") or "unknown",
        "caught_by": data.get("caught_by") or "agent",
        "trace": trace,
        "repro": data.get("repro") or [],
        "evidence": [],
        "redactions": n1 + n2,
    }
    if data.get("notes"):
        rec["notes"] = redact(data["notes"])[0]
    rec["attributes"] = _attributes(rec, data.get("context") or {})
    return rec


def _attributes(rec, ctx):
    """Flat attributes: OpenTelemetry names where a convention exists, firstwatch.* where none does."""
    def uniq(xs):
        return list(dict.fromkeys(xs))

    a = {
        "event.name": "firstwatch.capture",
        "firstwatch.spec": SPEC,
        "firstwatch.capture.id": rec["id"],
        "firstwatch.level": rec["level"],
        "firstwatch.outcome": rec["outcome"],
        "firstwatch.caught_by": rec["caught_by"],
        "firstwatch.hidden": rec["payload"]["hidden"],
        "firstwatch.rules": uniq(f["rule"] for f in rec["findings"]),
        "firstwatch.atlas.techniques": uniq(t for f in rec["findings"] for t in f.get("atlas", [])),
        "firstwatch.owasp.ids": uniq(t for f in rec["findings"] for t in f.get("owasp", [])),
    }
    if rec["source"]["url"]:
        a["url.full"] = rec["source"]["url"]
        if _host(rec["source"]["url"]):
            a["server.address"] = _host(rec["source"]["url"])
    if ctx.get("session_id"):
        a["gen_ai.conversation.id"] = ctx["session_id"]
    if rec["source"]["tool"]:
        a["gen_ai.operation.name"] = "execute_tool"
        a["gen_ai.tool.name"] = rec["source"]["tool"]
    if ctx.get("tool_use_id"):
        a["gen_ai.tool.call.id"] = ctx["tool_use_id"]
    if ctx.get("agent_name"):
        a["gen_ai.agent.name"] = ctx["agent_name"]
    return a


def _readme(rec):
    s, p = rec["source"], rec["payload"]
    via = f" (via {s['tool']})" if s.get("tool") else ""
    lines = [
        f"# {rec['level'].upper()}: {rec['summary']}",
        "",
        f"- **Time:** {rec['time']}",
        f"- **Source:** {s.get('url') or s.get('file') or s['kind']}{via}",
        f"- **Where:** {s.get('where') or 'not recorded'}",
        f"- **Hidden from people:** {('yes (' + (', '.join(p['hidden_how']) or 'how not recorded') + ')') if p['hidden'] else 'no'}",
        f"- **What it tried:** {rec['intent'] or 'not recorded'}",
        f"- **Outcome:** {rec['outcome']} · **caught by:** {rec['caught_by']}",
        "",
        "## Exact text",
        "",
        "```text",
        p["text"].replace("```", "'''"),
        "```",
        "",
    ]
    if rec["findings"]:
        lines += ["## Findings", "", "| Rule | Level | Where | ATLAS | OWASP |", "|---|---|---|---|---|"]
        for f in rec["findings"]:
            atlas = "; ".join(f"{t} {ATLAS.get(t, '')}".strip() for t in f.get("atlas", []))
            owasp = "; ".join(f"{t} {OWASP.get(t, '')}".strip() for t in f.get("owasp", []))
            lines.append(f"| {f['rule']} | {f['level']} | {f.get('where') or ''} | {atlas} | {owasp} |")
        lines.append("")
    if rec["repro"]:
        lines += ["## Reproduce", ""] + [f"{i + 1}. {x}" for i, x in enumerate(rec["repro"])] + [""]
    steps = (rec.get("trace") or {}).get("steps") or []
    if steps:
        lines += ["## Trace", ""]
        if rec["trace"].get("task"):
            lines += [f"Task: {rec['trace']['task']}", ""]
        lines += [f"{i + 1}. `{x.get('tool')}` {x.get('summary') or ''}".strip() for i, x in enumerate(steps)] + [""]
    if rec["evidence"]:
        lines += ["## Evidence", ""] + [f"- {e}" for e in rec["evidence"]] + [""]
    if rec.get("notes"):
        lines += ["## Notes", "", rec["notes"], ""]
    lines += ["---", "", f"Recorded by firstwatch {VERSION}. {rec['redactions']} value(s) masked before saving. Raw page source is stored as .txt so it never opens in a browser by mistake. Keep this folder private unless you choose to share it.", ""]
    return "\n".join(lines)


def _append(path, obj):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def write_capture(rec, dir=None, raw=None, raw_kind="html"):
    """Write a stop capture as a folder. Returns the folder path."""
    problems = validate(rec)
    if problems:
        raise ValueError("invalid capture:\n- " + "\n- ".join(problems))
    d = Path(dir) if dir else capture_dir()
    where = _slug(_host(rec["source"].get("url")) or (rec["source"].get("file") and os.path.basename(rec["source"]["file"])) or rec["source"].get("tool") or rec["source"]["kind"])
    name = _slug((primary(rec["findings"]) or {}).get("rule") or "capture")
    folder = d / f"{rec['time'][:10]}-{where}-{name}"
    n = 2
    while folder.exists():
        folder = d / f"{rec['time'][:10]}-{where}-{name}-{n}"
        n += 1
    folder.mkdir(parents=True)
    if raw:
        file = "raw.html.txt" if raw_kind == "html" else "raw.txt"
        masked, count = redact(raw[:MAX_EVIDENCE], keep_emails=True)
        (folder / file).write_text(masked, encoding="utf-8")
        rec["evidence"].append(file)
        rec["redactions"] += count
    (folder / "capture.json").write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (folder / "README.md").write_text(_readme(rec), encoding="utf-8")
    _append(d / "index.jsonl", {"time": rec["time"], "level": rec["level"], "id": rec["id"], "folder": str(folder), "summary": rec["summary"]})
    return str(folder)


def write_note(rec, dir=None):
    """A note is one line in notes.jsonl, not a folder."""
    d = Path(dir) if dir else capture_dir()
    d.mkdir(parents=True, exist_ok=True)
    _append(d / "notes.jsonl", {"time": rec["time"], "level": "note", "id": rec["id"], "source": rec["source"], "rules": [f["rule"] for f in rec["findings"]], "excerpt": rec["payload"]["text"][:300], "hidden_how": rec["payload"]["hidden_how"]})
    return str(d / "notes.jsonl")


def to_otlp(rec):
    """One OTLP/JSON log record, ready to POST to a collector's /v1/logs. No network here."""
    def value(v):
        if isinstance(v, list):
            return {"arrayValue": {"values": [value(x) for x in v]}}
        if isinstance(v, bool):
            return {"boolValue": v}
        if isinstance(v, (int, float)):
            return {"doubleValue": v}
        return {"stringValue": str(v)}

    t = datetime.fromisoformat(rec["time"].replace("Z", "+00:00"))
    stop = rec["level"] == "stop"
    return {"resourceLogs": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "firstwatch"}}]},
        "scopeLogs": [{
            "scope": {"name": "firstwatch", "version": VERSION},
            "logRecords": [{
                "timeUnixNano": str(int(t.timestamp() * 1000) * 1_000_000),
                "observedTimeUnixNano": str(time.time_ns()),
                "severityNumber": 13 if stop else 9,
                "severityText": "WARN" if stop else "INFO",
                "eventName": "firstwatch.capture",
                "body": {"stringValue": rec["summary"]},
                "attributes": [{"key": k, "value": value(v)} for k, v in (rec.get("attributes") or {}).items()],
            }],
        }],
    }]}
