"""Mask secrets before anything is written to disk. Emails are masked too unless the
caller keeps them (an attacker's address in the payload is evidence). Mirrors src/redact.js."""

import re

_A = re.ASCII
SECRETS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}", _A),
    re.compile(r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{30,}\b", _A),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b", _A),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b", _A),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}", _A),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b", _A),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", _A),
    re.compile(r"\b(?:hf|npm|glpat|pypi)[-_][A-Za-z0-9_-]{20,}", _A),
]
BEARER = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]{16,}=*", _A)
ASSIGNED = re.compile(r"\b([\w-]*(?:api[_-]?key|token|secret|passw(?:or)?d|pwd|auth)[\w-]*)([\"']?\s*[:=]\s*[\"']?)([^\s\"',;]{8,})", re.I | _A)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", _A)


def redact(text, keep_emails=False):
    """Return (masked_text, count)."""
    if not isinstance(text, str):
        return text, 0
    count = 0

    def sub(rx, repl, s):
        nonlocal count
        out, n = rx.subn(repl, s)
        count += n
        return out

    out = text
    for rx in SECRETS:
        out = sub(rx, "[REDACTED:secret]", out)
    out = sub(BEARER, lambda m: f"{m.group(1)} [REDACTED:secret]", out)

    def assigned(m):
        nonlocal count
        if m.group(3).startswith("[REDACTED"):
            return m.group(0)
        count += 1
        return f"{m.group(1)}{m.group(2)}[REDACTED:secret]"

    out = ASSIGNED.sub(assigned, out)
    if not keep_emails:
        out = sub(EMAIL, "[REDACTED:email]", out)
    return out, count


def redact_deep(value, keep_emails=False):
    """Redact every string inside a JSON-like value. Returns (value, count)."""
    total = 0

    def walk(v):
        nonlocal total
        if isinstance(v, str):
            out, n = redact(v, keep_emails)
            total += n
            return out
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        return v

    return walk(value), total
