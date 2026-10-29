"""Scan text or HTML for attacks aimed at AI agents. Pure: text in, findings out.

No network, no model. It splits the input into what people see and what they
don't, then runs the rules on each part. Mirrors src/scan.js in the Node package.
"""

import base64
import html
import re

from ._rules import AGENT_RE, BUILTIN, DISCUSSION_MIN, DISCUSSION_RE, HIDDEN_STYLE, RULES

ZERO_WIDTH = re.compile("[\u200B-\u200D\u2060-\u2064\uFEFF\u00AD]")
BIDI = re.compile("[\u202A-\u202E\u2066-\u2069]")
TAG_CHARS = re.compile("[\U000e0000-\U000e007f]+")
LEVELS = {"clean": 0, "note": 1, "stop": 2}
_SPACE = re.compile(r"\s+")


def decode_entities(s):
    def num(m, base):
        try:
            return chr(int(m.group(1), base))
        except (ValueError, OverflowError):
            return ""

    s = re.sub(r"&#x([0-9a-f]+);", lambda m: num(m, 16), s, flags=re.I)
    s = re.sub(r"&#(\d+);", lambda m: num(m, 10), s)
    for a, b in (("&nbsp;", " "), ("&quot;", '"'), ("&#39;", "'"), ("&apos;", "'"), ("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&")):
        s = s.replace(a, b)
    return s


def _strip_tags(s):
    return _SPACE.sub(" ", decode_entities(re.sub(r"<[^>]*>", " ", s))).strip()


def _inside(ranges, i):
    return any(a <= i < b for a, b in ranges)


def segments(text):
    """Split input into segments: dicts with text, hidden, how, where, offset, quoted."""
    out = []
    for m in TAG_CHARS.finditer(text):
        decoded = "".join(chr(ord(c) - 0xE0000) for c in m.group(0))
        out.append({"text": decoded, "hidden": True, "how": ["unicode-tag-characters"], "where": "invisible characters", "offset": m.start()})
    s = TAG_CHARS.sub("", text)
    if not re.search(r"</?[a-z][\w-]*[^>]*>|<!--", s, re.I):
        out.append({"text": s, "hidden": False, "how": [], "where": "text", "offset": 0})
        return _with_base64(out, s)

    lower = s.lower()
    removed = []
    for m in re.finditer(r"<!--([\s\S]*?)-->", s):
        out.append({"text": m.group(1).strip(), "hidden": True, "how": ["html-comment"], "where": "HTML comment", "offset": m.start()})
        removed.append((m.start(), m.end()))
    for m in re.finditer(r"<(script|style|template)\b[^>]*>[\s\S]*?</\1>", s, re.I):
        removed.append((m.start(), m.end()))

    for m in re.finditer(r"<([a-z][\w-]*)\b([^>]*)>", s, re.I | re.ASCII):
        tag, attrs = m.group(1).lower(), m.group(2)
        how = []
        style = re.search(r"\bstyle\s*=\s*(\"([^\"]*)\"|'([^']*)')", attrs, re.I)
        if style:
            value = style.group(2) if style.group(2) is not None else style.group(3)
            how += [label for rx, label in HIDDEN_STYLE if rx.search(value)]
        if re.search(r"(?:^|\s)hidden(?:\s|=|$)", attrs, re.I):
            how.append("attr:hidden")
        if re.search(r"aria-hidden\s*=\s*[\"']?true", attrs, re.I):
            how.append("attr:aria-hidden")
        if re.search(r"\bclass\s*=\s*[\"'][^\"']*\b(?:hidden|d-none|invisible)\b", attrs, re.I):
            how.append("class:hidden")
        for a in re.finditer(r"\b(alt|title|aria-label|content|data-[\w-]+)\s*=\s*(\"([^\"]*)\"|'([^']*)')", attrs, re.I | re.ASCII):
            val = decode_entities(a.group(3) if a.group(3) is not None else a.group(4)).strip()
            if len(val) > 15:
                name = a.group(1).lower()
                out.append({"text": val, "hidden": True, "how": [f"attribute:{name}"], "where": f"<{tag}> {name} attribute", "offset": m.start()})
        if not how or re.fullmatch(r"br|img|input|meta|link|hr", tag):
            continue
        start = m.end()
        close = lower.find(f"</{tag}", start)
        end = min(len(s), start + 4000) if close == -1 else close
        inner = _strip_tags(s[start:end])
        if inner:
            out.append({"text": inner, "hidden": True, "how": how, "where": f"hidden <{tag}>", "offset": m.start()})
        removed.append((m.start(), end))

    # Code blocks are quoted examples: a match there is a note, not a stop.
    for m in re.finditer(r"<(pre|code)\b[^>]*>([\s\S]*?)</\1>", s, re.I):
        if _inside(removed, m.start()):
            continue
        inner = _strip_tags(m.group(2))
        if inner:
            out.append({"text": inner, "hidden": False, "how": [], "where": f"<{m.group(1).lower()}> block", "offset": m.start(), "quoted": True})
        removed.append((m.start(), m.end()))

    visible, pos = [], 0
    for a, b in sorted(removed):
        if a > pos:
            visible.append(s[pos:a] + " ")
        pos = max(pos, b)
    visible.append(s[pos:])
    vis = _strip_tags("".join(visible))
    if vis:
        out.append({"text": vis, "hidden": False, "how": [], "where": "visible text", "offset": 0})
    return _with_base64(out, s)


def _with_base64(out, s):
    for m in re.finditer(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])", s):
        blob = m.group(0).rstrip("=")
        if len(blob) % 4 == 1:
            blob = blob[:-1]
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", errors="replace")
        except ValueError:
            continue
        printable = len(re.sub(r"[^\x20-\x7e\n\t]", "", decoded)) / max(len(decoded), 1)
        if printable > 0.95 and re.search(r"[a-z]{3,} [a-z]{3,}", decoded, re.I):
            out.append({"text": decoded, "hidden": True, "how": ["base64"], "where": "base64-encoded text", "offset": m.start()})
    return out


def _excerpt(text, index, length):
    a = max(0, index - 80)
    b = min(len(text), index + length + 80)
    return ("…" if a > 0 else "") + text[a:b] + ("…" if b < len(text) else "")


def _in_quotes(text, i):
    """Is position i inside a quotation? Counts open quotes in the 300 characters before it."""
    before = text[max(0, i - 300):i]
    return before.count('"') % 2 == 1 or (before.count("“") + before.count("«")) > (before.count("”") + before.count("»"))


def _level_for(rule, seg, text, index, near):
    level = rule["hidden"] if seg["hidden"] else rule["visible"]
    if level is None:
        level = "stop" if AGENT_RE.search(near) else None
    if not level:
        return None
    # A quoted example in visible text is someone talking about an attack, not making one.
    if level == "stop" and not seg["hidden"] and (seg.get("quoted") or _in_quotes(text, index)):
        level = "note"
    return level


def _finding(rule, level, seg, ex):
    atlas = list(rule["atlas"])
    if any(h in ("base64", "zero-width-characters") for h in seg["how"]) and "AML.T0068" not in atlas:
        atlas.append("AML.T0068")
    return {
        "rule": rule["id"],
        "what": rule["what"],
        "level": level,
        "hidden": bool(seg["hidden"]),
        "hidden_how": seg["how"],
        "where": seg["where"],
        "offset": seg["offset"],
        "excerpt": ex,
        "atlas": atlas,
        "owasp": list(rule["owasp"]),
    }


def scan(text):
    """Scan a string. Returns {"level": "clean"|"note"|"stop", "findings": [...]}."""
    if not isinstance(text, str) or not text:
        return {"level": "clean", "findings": []}
    findings, seen = [], set()
    segs = segments(text)
    if BIDI.search(text):
        findings.append(_finding(BUILTIN["bidi-control"], "note", {"hidden": True, "how": ["bidi-control-characters"], "where": "text", "offset": 0}, "(bidirectional control characters present)"))

    ai = next(r for r in RULES if r["id"] == "agent-imperative")
    for seg in segs:
        raw = seg["text"]
        t = ZERO_WIDTH.sub("", raw)
        how = list(seg["how"])
        if t != raw:
            how.append("zero-width-characters")
        sf = dict(seg, how=how)
        hit = False

        if "unicode-tag-characters" in seg["how"]:
            findings.append(_finding(BUILTIN["unicode-tag-smuggling"], "stop", sf, t[:240]))
            hit = True

        for rule in RULES:
            if rule["id"] == "agent-imperative":
                continue
            m = rule["re"].search(t)
            if not m:
                continue
            near = t[max(0, m.start() - 200):m.end() + 200]
            level = _level_for(rule, sf, t, m.start(), near)
            if not level:
                continue
            ex = _excerpt(t, m.start(), len(m.group(0)))
            if (rule["id"] + ex) in seen:
                continue
            seen.add(rule["id"] + ex)
            findings.append(_finding(rule, level, sf, ex))
            hit = True

        at = 0
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", t):
            index = t.find(sentence, at)
            at = index + len(sentence)
            if not ai["agent_re"].search(sentence) or not ai["imperative_re"].search(sentence):
                continue
            level = "stop" if sf["hidden"] or ai["danger_re"].search(sentence) else "note"
            if level == "stop" and not sf["hidden"] and (sf.get("quoted") or _in_quotes(t, index + 1)):
                level = "note"
            ex = sentence.strip()[:300]
            if (ai["id"] + ex) in seen:
                continue
            seen.add(ai["id"] + ex)
            findings.append(_finding(ai, level, sf, ex))
            hit = True

        # Hidden menus often name AI products; only a comment or invisible characters aimed at AI is worth a note.
        if not hit and seg["hidden"] and AGENT_RE.search(t) and (seg["how"][:1] in (["html-comment"], ["unicode-tag-characters"])):
            findings.append(_finding(BUILTIN["hidden-agent-text"], "note", sf, t[:240]))

    # A page that talks about these attacks at length quotes them in visible text.
    # Its visible examples become notes; anything hidden still stops.
    visible = " ".join(x["text"] for x in segs if not x["hidden"])
    if len(DISCUSSION_RE.findall(visible)) >= DISCUSSION_MIN:
        for f in findings:
            if f["level"] == "stop" and not f["hidden"]:
                f["level"] = "note"
                f["context"] = "page discusses attacks"

    level = "clean"
    for f in findings:
        if LEVELS[f["level"]] > LEVELS[level]:
            level = f["level"]
    return {"level": level, "findings": findings}
