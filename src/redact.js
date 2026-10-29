// Mask secrets before anything is written to disk. Emails are masked too unless
// the caller keeps them (an attacker's address in the payload is evidence).

const SECRETS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/g,
  /\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{30,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  /\b(?:hf|npm|glpat|pypi)[-_][A-Za-z0-9_-]{20,}/g,
];
const BEARER = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]{16,}=*/g;
const ASSIGNED = /\b([\w-]*(?:api[_-]?key|token|secret|passw(?:or)?d|pwd|auth)[\w-]*)(["']?\s*[:=]\s*["']?)([^\s"',;]{8,})/gi;
const EMAIL = /\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g;

export function redact(text, { keepEmails = false } = {}) {
  if (typeof text !== 'string') return { text, count: 0 };
  let count = 0;
  let out = text;
  for (const re of SECRETS) out = out.replace(re, () => (count++, '[REDACTED:secret]'));
  out = out.replace(BEARER, (_, kind) => (count++, `${kind} [REDACTED:secret]`));
  out = out.replace(ASSIGNED, (all, key, sep, val) => (val.startsWith('[REDACTED') ? all : (count++, `${key}${sep}[REDACTED:secret]`)));
  if (!keepEmails) out = out.replace(EMAIL, () => (count++, '[REDACTED:email]'));
  return { text: out, count };
}

// Redact every string inside a JSON value.
export function redactDeep(value, opts) {
  let count = 0;
  const walk = (v) => {
    if (typeof v === 'string') {
      const r = redact(v, opts);
      count += r.count;
      return r.text;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return { value: walk(value), count };
}
