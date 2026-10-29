// Scan text or HTML for attacks aimed at AI agents. Pure: text in, findings out.
// No network, no model. It splits the input into what people see and what they
// don't, then runs the rules on each part.

import { RULES, AGENT_RE, HIDDEN_STYLE, DISCUSSION, BUILTIN } from './rules.js';

const ZERO_WIDTH = /[\u200B-\u200D\u2060-\u2064\uFEFF\u00AD]/g;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/;
const TAG_CHARS = /[\u{E0000}-\u{E007F}]+/gu;
const LEVELS = { clean: 0, note: 1, stop: 2 };


export function decodeEntities(s) {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => safeChar(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => safeChar(parseInt(d, 10)))
    .replace(/&nbsp;/g, ' ').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

function safeChar(n) {
  try { return String.fromCodePoint(n); } catch { return ''; }
}

const stripTags = (s) => decodeEntities(s.replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();

// Split input into segments: { text, hidden, how[], where, offset, quoted }
export function segments(input) {
  const out = [];
  const tags = [...input.matchAll(TAG_CHARS)];
  for (const m of tags) {
    const decoded = [...m[0]].map((c) => String.fromCharCode(c.codePointAt(0) - 0xE0000)).join('');
    out.push({ text: decoded, hidden: true, how: ['unicode-tag-characters'], where: 'invisible characters', offset: m.index });
  }
  const s = input.replace(TAG_CHARS, '');
  const isHtml = /<\/?[a-z][\w-]*[^>]*>|<!--/i.test(s);
  if (!isHtml) {
    out.push({ text: s, hidden: false, how: [], where: 'text', offset: 0 });
    return withBase64(out, s);
  }

  const removed = []; // [start, end] ranges that are not visible text
  for (const m of s.matchAll(/<!--([\s\S]*?)-->/g)) {
    out.push({ text: m[1].trim(), hidden: true, how: ['html-comment'], where: 'HTML comment', offset: m.index });
    removed.push([m.index, m.index + m[0].length]);
  }
  for (const m of s.matchAll(/<(script|style|template)\b[^>]*>[\s\S]*?<\/\1>/gi)) removed.push([m.index, m.index + m[0].length]);

  for (const m of s.matchAll(/<([a-z][\w-]*)\b([^>]*)>/gi)) {
    const [tag, attrs] = [m[1].toLowerCase(), m[2]];
    const how = [];
    const style = /\bstyle\s*=\s*("([^"]*)"|'([^']*)')/i.exec(attrs);
    if (style) for (const [re, label] of HIDDEN_STYLE) if (re.test(style[2] ?? style[3])) how.push(label);
    if (/(?:^|\s)hidden(?:\s|=|$)/i.test(attrs)) how.push('attr:hidden');
    if (/aria-hidden\s*=\s*["']?true/i.test(attrs)) how.push('attr:aria-hidden');
    if (/\bclass\s*=\s*["'][^"']*\b(?:hidden|d-none|invisible)\b/i.test(attrs)) how.push('class:hidden');
    for (const a of attrs.matchAll(/\b(alt|title|aria-label|content|data-[\w-]+)\s*=\s*("([^"]*)"|'([^']*)')/gi)) {
      const val = decodeEntities(a[3] ?? a[4]).trim();
      if (val.length > 15) out.push({ text: val, hidden: true, how: [`attribute:${a[1].toLowerCase()}`], where: `<${tag}> ${a[1].toLowerCase()} attribute`, offset: m.index });
    }
    if (!how.length || /^(?:br|img|input|meta|link|hr)$/.test(tag)) continue;
    const start = m.index + m[0].length;
    const close = s.toLowerCase().indexOf(`</${tag}`, start);
    const end = close === -1 ? Math.min(s.length, start + 4000) : close;
    const text = stripTags(s.slice(start, end));
    if (text) out.push({ text, hidden: true, how, where: `hidden <${tag}>`, offset: m.index });
    removed.push([m.index, end]);
  }

  // Code blocks are quoted examples: a match there is a note, not a stop.
  for (const m of s.matchAll(/<(pre|code)\b[^>]*>([\s\S]*?)<\/\1>/gi)) {
    if (inside(removed, m.index)) continue;
    const text = stripTags(m[2]);
    if (text) out.push({ text, hidden: false, how: [], where: `<${m[1].toLowerCase()}> block`, offset: m.index, quoted: true });
    removed.push([m.index, m.index + m[0].length]);
  }

  let visible = '';
  let pos = 0;
  for (const [a, b] of removed.sort((x, y) => x[0] - y[0])) {
    if (a > pos) visible += s.slice(pos, a) + ' ';
    pos = Math.max(pos, b);
  }
  visible += s.slice(pos);
  const text = stripTags(visible);
  if (text) out.push({ text, hidden: false, how: [], where: 'visible text', offset: 0 });
  return withBase64(out, s);
}

const inside = (ranges, i) => ranges.some(([a, b]) => i >= a && i < b);

function withBase64(out, s) {
  for (const m of s.matchAll(/(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])/g)) {
    let decoded;
    try { decoded = Buffer.from(m[0], 'base64').toString('utf8'); } catch { continue; }
    const printable = decoded.replace(/[^\x20-\x7E\n\t]/g, '').length / Math.max(decoded.length, 1);
    if (printable > 0.95 && /[a-z]{3,} [a-z]{3,}/i.test(decoded)) {
      out.push({ text: decoded, hidden: true, how: ['base64'], where: 'base64-encoded text', offset: m.index });
    }
  }
  return out;
}

function excerpt(text, index, length) {
  const a = Math.max(0, index - 80);
  const b = Math.min(text.length, index + length + 80);
  return (a > 0 ? '…' : '') + text.slice(a, b) + (b < text.length ? '…' : '');
}

// Is position i inside a quotation? Counts open quotes in the 300 characters before it.
function inQuotes(text, i) {
  const before = text.slice(Math.max(0, i - 300), i);
  const straight = (before.match(/"/g) || []).length;
  const open = (before.match(/[“«]/g) || []).length;
  const close = (before.match(/[”»]/g) || []).length;
  return straight % 2 === 1 || open > close;
}

function levelFor(rule, seg, text, index, near) {
  let level = seg.hidden ? rule.hidden : rule.visible;
  if (level === null) level = AGENT_RE.test(near) ? 'stop' : null;
  if (!level) return null;
  // A quoted example in visible text is someone talking about an attack, not making one.
  if (level === 'stop' && !seg.hidden && (seg.quoted || inQuotes(text, index))) level = 'note';
  return level;
}

// Scan a string. Returns { level: 'clean'|'note'|'stop', findings: [...] }
export function scan(input) {
  if (typeof input !== 'string' || !input) return { level: 'clean', findings: [] };
  const findings = [];
  const seen = new Set();
  const segs = segments(input);
  if (BIDI.test(input)) {
    findings.push(finding(BUILTIN['bidi-control'], 'note', { hidden: true, how: ['bidi-control-characters'], where: 'text', offset: 0 }, '(bidirectional control characters present)'));
  }

  for (const seg of segs) {
    const raw = seg.text;
    const text = raw.replace(ZERO_WIDTH, '');
    const how = [...seg.how];
    if (text !== raw) how.push('zero-width-characters');
    const segFor = { ...seg, how };
    let segHit = false;

    if (seg.how.includes('unicode-tag-characters')) {
      findings.push(finding(BUILTIN['unicode-tag-smuggling'], 'stop', segFor, text.slice(0, 240)));
      segHit = true;
    }

    for (const rule of RULES) {
      if (rule.id === 'agent-imperative') continue;
      const m = rule.re.exec(text);
      if (!m) continue;
      const near = text.slice(Math.max(0, m.index - 200), m.index + m[0].length + 200);
      const level = levelFor(rule, segFor, text, m.index, near);
      if (!level) continue;
      const ex = excerpt(text, m.index, m[0].length);
      const key = rule.id + ex;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(finding(rule, level, segFor, ex));
      segHit = true;
    }

    const ai = RULES.find((r) => r.id === 'agent-imperative');
    let at = 0;
    for (const sentence of text.split(/(?<=[.!?])\s+|\n+/)) {
      const index = text.indexOf(sentence, at);
      at = index + sentence.length;
      if (!ai.agent.test(sentence) || !ai.imperative.test(sentence)) continue;
      let level = segFor.hidden || ai.danger.test(sentence) ? 'stop' : 'note';
      if (level === 'stop' && !segFor.hidden && (segFor.quoted || inQuotes(text, index + 1))) level = 'note';
      const ex = sentence.trim().slice(0, 300);
      if (seen.has(ai.id + ex)) continue;
      seen.add(ai.id + ex);
      findings.push(finding(ai, level, segFor, ex));
      segHit = true;
    }

    // Hidden menus often name AI products; only a comment or invisible characters aimed at AI is worth a note.
    if (!segHit && seg.hidden && AGENT_RE.test(text) && /^(?:html-comment|unicode-tag-characters)$/.test(seg.how[0] ?? '')) {
      findings.push(finding(BUILTIN['hidden-agent-text'], 'note', segFor, text.slice(0, 240)));
    }
  }

  // A page that talks about these attacks at length (an article, a course) quotes them in visible text.
  // Its visible examples become notes; anything hidden still stops.
  const visible = segs.filter((x) => !x.hidden).map((x) => x.text).join(' ');
  if ((visible.match(DISCUSSION.re) || []).length >= DISCUSSION.min) {
    for (const f of findings) {
      if (f.level === 'stop' && !f.hidden) {
        f.level = 'note';
        f.context = 'page discusses attacks';
      }
    }
  }

  const level = findings.reduce((l, f) => (LEVELS[f.level] > LEVELS[l] ? f.level : l), 'clean');
  return { level, findings };
}

function finding(rule, level, seg, ex) {
  const atlas = [...rule.atlas];
  if (seg.how.some((h) => h === 'base64' || h === 'zero-width-characters') && !atlas.includes('AML.T0068')) atlas.push('AML.T0068');
  return {
    rule: rule.id,
    what: rule.what,
    level,
    hidden: !!seg.hidden,
    hidden_how: seg.how,
    where: seg.where,
    offset: seg.offset,
    excerpt: ex,
    atlas,
    owasp: [...rule.owasp],
  };
}
