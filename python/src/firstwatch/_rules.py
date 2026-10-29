"""Loads the shared detection rules (rules.json, the same file the Node package uses)."""

import json
import re
from importlib import resources

_data = json.loads(resources.files("firstwatch").joinpath("rules.json").read_text(encoding="utf-8"))


def _rx(p):
    # re.ASCII keeps \w and \b the same as JavaScript regexes without the u flag.
    flags = re.ASCII
    if "i" in p["flags"]:
        flags |= re.IGNORECASE
    return re.compile(p["source"], flags)


RULES_VERSION = _data["version"]
ATLAS = _data["atlas"]
OWASP = _data["owasp"]
AGENT_RE = _rx(_data["agent"])
HIDDEN_STYLE = [(_rx(h), h["label"]) for h in _data["hidden_style"]]
DISCUSSION_RE = _rx(_data["discussion"])
DISCUSSION_MIN = _data["discussion"]["min"]
PRIORITY = _data["priority"]
BUILTIN = {b["id"]: b for b in _data["builtin"]}

RULES = []
for _r in _data["rules"]:
    _rule = dict(_r)
    if "pattern" in _r:
        _rule["re"] = _rx(_r["pattern"])
    else:
        _rule["agent_re"] = _rx(_r["agent"])
        _rule["imperative_re"] = _rx(_r["imperative"])
        _rule["danger_re"] = _rx(_r["danger"])
    RULES.append(_rule)
