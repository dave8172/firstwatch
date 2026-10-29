"""firstwatch command line (Python). Same commands as the Node CLI, minus the Claude Code hook."""

import json
import os
import re
import sys
from pathlib import Path

from . import VERSION, build, capture_dir, scan, to_otlp, validate, write_capture, write_note

HELP = f"""firstwatch {VERSION}: watch, record and stop attacks aimed at AI agents

  firstwatch scan [file]                 scan a file (or stdin) and print findings as JSON
  firstwatch capture                     read a capture as JSON on stdin, check it, save it
  firstwatch list                        list saved captures
  firstwatch validate <capture.json>     check a capture against the format
  firstwatch export otlp <capture.json>  print it as an OpenTelemetry (OTLP/JSON) log record
  firstwatch clear [--session <id>]      lift the approval gate for one session, or all

Captures go to ./security-captures, or FIRSTWATCH_DIR if set.
The Claude Code hook ships in the Node package: npx firstwatch hook claude-code"""


def _fail(msg):
    sys.stderr.write(f"firstwatch: {msg}\n")
    sys.exit(1)


def _print(v):
    sys.stdout.write((v if isinstance(v, str) else json.dumps(v, indent=2, ensure_ascii=False)) + "\n")


def _read(path):
    return Path(path).read_text(encoding="utf-8")


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args.pop(0) if args else None
    if cmd in (None, "-h", "--help", "help"):
        return _print(HELP)
    if cmd in ("-v", "--version"):
        return _print(VERSION)

    if cmd == "scan":
        text = _read(args[0]) if args and args[0] != "-" else sys.stdin.read()
        return _print(scan(text))

    if cmd == "capture":
        try:
            data = json.loads(sys.stdin.read())
        except ValueError as e:
            _fail(f"stdin must be JSON: {e}")
        text = (data.get("payload") or {}).get("text") or data.get("text")
        if not text:
            _fail("payload.text (the exact text of the attack) is required")
        data["payload"] = {"hidden": False, "hidden_how": [], **(data.get("payload") or {}), "text": text}
        found = scan(text)["findings"]
        data["findings"] = (data.get("findings") or []) + found
        data["level"] = data.get("level") or ("stop" if any(f["level"] == "stop" for f in found) else "note")
        rec = build(data)
        problems = validate(rec)
        if problems:
            _fail("capture is incomplete:\n- " + "\n- ".join(problems))
        raw_file = data.get("raw_file")
        raw = _read(raw_file) if raw_file and os.path.exists(raw_file) else None
        if rec["level"] == "stop":
            where = write_capture(rec, raw=raw, raw_kind="html" if re.search(r"\.html?$", raw_file or "", re.I) else "text")
        else:
            where = write_note(rec)
        return _print({"level": rec["level"], "saved": where, "findings": len(rec["findings"])})

    if cmd == "list":
        f = capture_dir() / "index.jsonl"
        if not f.exists():
            return _print("No captures yet.")
        for line in f.read_text(encoding="utf-8").strip().splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            _print(f"{r['time']}  {r['level'].upper()}  {r['summary']}\n    {r['folder']}")
        return None

    if cmd == "validate":
        if not args:
            _fail("usage: firstwatch validate <capture.json>")
        problems = validate(json.loads(_read(args[0])))
        if problems:
            _fail("not valid:\n- " + "\n- ".join(problems))
        return _print("valid")

    if cmd == "export":
        if len(args) < 2 or args[0] != "otlp":
            _fail("usage: firstwatch export otlp <capture.json>")
        return _print(to_otlp(json.loads(_read(args[1]))))

    if cmd == "clear":
        d = capture_dir() / ".sessions"
        if not d.exists():
            return _print("No gated sessions.")
        if "--session" in args:
            sid = args[args.index("--session") + 1]
            files = [d / (re.sub(r"[^a-z0-9]+", "-", sid.lower()) + ".json")]
        else:
            files = list(d.iterdir())
        for f in files:
            f.unlink(missing_ok=True)
        return _print("Lifted the gate for " + (f"session {sid}" if "--session" in args else "all sessions") + ".")

    _fail(f'unknown command "{cmd}"\n\n{HELP}')
    return None


if __name__ == "__main__":
    main()
