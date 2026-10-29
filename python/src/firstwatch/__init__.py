"""firstwatch: first line of defence for AI agents.

    from firstwatch import scan, watch

    scan(page_html)                  # {"level": "clean"|"note"|"stop", "findings": [...]}
    watch(page_html, url=url)        # scans, saves a capture on a stop, returns the result + "saved"

Same rules and capture format as the Node package (https://github.com/dave8172/firstwatch).
"""

from ._rules import RULES_VERSION
from .capture import SPEC, VERSION, build, capture_dir, to_otlp, validate, write_capture, write_note
from .redact import redact
from .scan import scan

__version__ = VERSION
__all__ = ["scan", "watch", "build", "validate", "write_capture", "write_note", "to_otlp", "redact", "capture_dir", "SPEC", "RULES_VERSION", "__version__"]


def watch(text, *, url=None, file=None, tool=None, kind=None, task=None, steps=None, session_id=None, agent_name=None, dir=None, raw=None):
    """Scan one piece of outside content and record what it finds.

    A stop is saved as a capture folder, a note as one line in notes.jsonl.
    Returns the scan result plus "saved" (the folder or notes file, or None when clean).
    Your code decides what to do next; on a stop, don't pass the content on as instructions.
    """
    result = scan(text)
    result["saved"] = None
    if result["level"] == "clean":
        return result
    from .capture import primary

    top = primary(result["findings"])
    repro = [f"Fetch {url} as raw HTML (no JavaScript)." if url else f"Open {file}." if file else "Feed the same content to the agent."]
    repro.append(f'Find the text: "{top["excerpt"][:160]}"')
    rec = build({
        "level": result["level"],
        "findings": result["findings"],
        "source": {"kind": kind or ("web" if url else "file" if file else "tool" if tool else "other"), "url": url, "file": file, "tool": tool, "where": top["where"]},
        "payload": {"text": top["excerpt"], "hidden": top["hidden"], "hidden_how": top["hidden_how"]},
        "caught_by": "scanner",
        "outcome": "blocked" if result["level"] == "stop" else "unknown",
        "trace": {"task": task, "steps": steps or []},
        "repro": repro,
        "context": {"session_id": session_id, "agent_name": agent_name},
    })
    if result["level"] == "stop":
        result["saved"] = write_capture(rec, dir=dir, raw=raw if raw is not None else text, raw_kind="html" if "<" in (raw or text) else "text")
    else:
        result["saved"] = write_note(rec, dir=dir)
    return result
