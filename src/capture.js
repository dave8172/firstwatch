// Build, check and write capture records (format: SPEC.md, firstwatch/0.1).

import { mkdirSync, writeFileSync, appendFileSync, existsSync, readFileSync } from 'node:fs';
import { join, resolve, basename } from 'node:path';
import { randomBytes } from 'node:crypto';
import { redact, redactDeep } from './redact.js';
import { ATLAS, OWASP, PRIORITY } from './rules.js';

export const SPEC = 'firstwatch/0.1';
export const VERSION = '0.3.0';
const LEVELS = ['stop', 'note'];
const OUTCOMES = ['blocked', 'followed', 'partial', 'unknown'];
const CAUGHT_BY = ['hook', 'agent', 'scanner', 'owner'];
const KINDS = ['web', 'file', 'command', 'tool', 'search', 'message', 'email', 'other'];
const MAX_EVIDENCE = 2_000_000;

// Most serious first: what the attack does, then how it hides.
const rank = (f) => (f.level === 'stop' ? 0 : 100) + (PRIORITY.indexOf(f.rule) + 1 || 50);
export const primary = (findings) => [...findings].sort((a, b) => rank(a) - rank(b))[0];

export function captureDir(cwd = process.cwd()) {
  return resolve(process.env.FIRSTWATCH_DIR || join(cwd, 'security-captures'));
}

// ISO 8601 in local time with the UTC offset, e.g. 2026-10-29T14:05:00.123+05:30
export function isoLocal(d = new Date()) {
  const off = -d.getTimezoneOffset();
  const pad = (n) => String(Math.floor(Math.abs(n))).padStart(2, '0');
  const local = new Date(d.getTime() + off * 60000).toISOString().slice(0, -1);
  return `${local}${off >= 0 ? '+' : '-'}${pad(off / 60)}:${pad(off % 60)}`;
}

const slug = (s) => String(s || 'unknown').toLowerCase().replace(/^www\./, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'unknown';

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

// Every problem at once, not the first.
export function validate(rec) {
  const p = [];
  const need = (cond, msg) => { if (!cond) p.push(msg); };
  need(rec && typeof rec === 'object', 'record must be an object');
  if (!rec || typeof rec !== 'object') return p;
  need(rec.spec === SPEC, `spec must be "${SPEC}"`);
  need(typeof rec.id === 'string' && rec.id, 'id is required');
  need(typeof rec.time === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d:\d\d)$/.test(rec.time), 'time must be ISO 8601 with a UTC offset');
  need(LEVELS.includes(rec.level), `level must be one of ${LEVELS.join(', ')}`);
  need(typeof rec.summary === 'string' && rec.summary.trim(), 'summary is required');
  need(rec.source && KINDS.includes(rec.source.kind), `source.kind must be one of ${KINDS.join(', ')}`);
  need(rec.payload && typeof rec.payload.text === 'string' && rec.payload.text, 'payload.text (the exact text) is required');
  need(rec.payload && typeof rec.payload.hidden === 'boolean', 'payload.hidden must be true or false');
  need(Array.isArray(rec.findings), 'findings must be a list');
  need(OUTCOMES.includes(rec.outcome), `outcome must be one of ${OUTCOMES.join(', ')}`);
  need(CAUGHT_BY.includes(rec.caught_by), `caught_by must be one of ${CAUGHT_BY.join(', ')}`);
  need(Array.isArray(rec.repro), 'repro must be a list of steps');
  return p;
}

// Turn partial input (from a hook or an agent) into a full record. Redacts as it goes.
export function build(input) {
  const now = new Date();
  const findings = input.findings || [];
  const top = primary(findings);
  const url = input.source?.url || null;
  const payloadText = input.payload?.text ?? top?.excerpt ?? '';
  const payload = redact(payloadText, { keepEmails: true });
  const trace = redactDeep(input.trace || {});
  const intent = input.intent || top?.what || '';
  const rec = {
    spec: SPEC,
    id: `fw_${now.toISOString().replace(/[-:]/g, '').slice(0, 15)}_${randomBytes(3).toString('hex')}`,
    time: input.time || isoLocal(now),
    level: input.level || (findings.some((f) => f.level === 'stop') ? 'stop' : 'note'),
    summary: input.summary || `${(input.payload?.hidden ?? top?.hidden) ? 'Hidden text' : 'Text'}${url ? ` on ${hostOf(url)}` : input.source?.file ? ` in ${basename(input.source.file)}` : ''}: ${intent || 'targets AI agents'}`,
    source: {
      kind: input.source?.kind || (url ? 'web' : 'other'),
      url,
      tool: input.source?.tool || null,
      where: input.source?.where || top?.where || null,
      file: input.source?.file || null,
    },
    payload: {
      text: payload.text,
      hidden: input.payload?.hidden ?? !!top?.hidden,
      hidden_how: input.payload?.hidden_how ?? top?.hidden_how ?? [],
    },
    findings,
    intent,
    outcome: input.outcome || 'unknown',
    caught_by: input.caught_by || 'agent',
    trace: trace.value,
    repro: input.repro || [],
    evidence: [],
    redactions: payload.count + trace.count,
    notes: input.notes ? redact(input.notes).text : undefined,
  };
  rec.attributes = attributes(rec, input.context || {});
  return rec;
}

// Flat attributes, OpenTelemetry names where a convention exists, firstwatch.* where none does.
function attributes(rec, ctx) {
  const atlas = [...new Set(rec.findings.flatMap((f) => f.atlas || []))];
  const owasp = [...new Set(rec.findings.flatMap((f) => f.owasp || []))];
  const a = {
    'event.name': 'firstwatch.capture',
    'firstwatch.spec': SPEC,
    'firstwatch.capture.id': rec.id,
    'firstwatch.level': rec.level,
    'firstwatch.outcome': rec.outcome,
    'firstwatch.caught_by': rec.caught_by,
    'firstwatch.hidden': rec.payload.hidden,
    'firstwatch.rules': [...new Set(rec.findings.map((f) => f.rule))],
    'firstwatch.atlas.techniques': atlas,
    'firstwatch.owasp.ids': owasp,
  };
  if (rec.source.url) {
    a['url.full'] = rec.source.url;
    const h = hostOf(rec.source.url);
    if (h) a['server.address'] = h;
  }
  if (ctx.session_id) a['gen_ai.conversation.id'] = ctx.session_id;
  if (rec.source.tool) {
    a['gen_ai.operation.name'] = 'execute_tool';
    a['gen_ai.tool.name'] = rec.source.tool;
  }
  if (ctx.tool_use_id) a['gen_ai.tool.call.id'] = ctx.tool_use_id;
  if (ctx.agent_name) a['gen_ai.agent.name'] = ctx.agent_name;
  return a;
}

function readme(rec) {
  const lines = [
    `# ${rec.level.toUpperCase()}: ${rec.summary}`,
    '',
    `- **Time:** ${rec.time}`,
    `- **Source:** ${rec.source.url || rec.source.file || rec.source.kind}${rec.source.tool ? ` (via ${rec.source.tool})` : ''}`,
    `- **Where:** ${rec.source.where || 'not recorded'}`,
    `- **Hidden from people:** ${rec.payload.hidden ? `yes (${rec.payload.hidden_how.join(', ') || 'how not recorded'})` : 'no'}`,
    `- **What it tried:** ${rec.intent || 'not recorded'}`,
    `- **Outcome:** ${rec.outcome} · **caught by:** ${rec.caught_by}`,
    '',
    '## Exact text',
    '',
    '```text',
    rec.payload.text.replace(/```/g, "'''"),
    '```',
    '',
  ];
  if (rec.findings.length) {
    lines.push('## Findings', '', '| Rule | Level | Where | ATLAS | OWASP |', '|---|---|---|---|---|');
    for (const f of rec.findings) lines.push(`| ${f.rule} | ${f.level} | ${f.where || ''} | ${(f.atlas || []).map((t) => `${t} ${ATLAS[t] || ''}`.trim()).join('; ')} | ${(f.owasp || []).map((t) => `${t} ${OWASP[t] || ''}`.trim()).join('; ')} |`);
    lines.push('');
  }
  if (rec.repro.length) lines.push('## Reproduce', '', ...rec.repro.map((s, i) => `${i + 1}. ${s}`), '');
  if (rec.trace?.steps?.length) {
    lines.push('## Trace', '');
    if (rec.trace.task) lines.push(`Task: ${rec.trace.task}`, '');
    rec.trace.steps.forEach((s, i) => lines.push(`${i + 1}. \`${s.tool}\` ${s.summary || ''}`.trim()));
    lines.push('');
  }
  if (rec.evidence.length) lines.push('## Evidence', '', ...rec.evidence.map((e) => `- ${e}`), '');
  if (rec.notes) lines.push('## Notes', '', rec.notes, '');
  lines.push('---', '', `Recorded by firstwatch ${VERSION}. ${rec.redactions} value(s) masked before saving. Raw page source is stored as .txt so it never opens in a browser by mistake. Keep this folder private unless you choose to share it.`, '');
  return lines.join('\n');
}

// Write a stop capture as a folder. Returns the folder path.
export function writeCapture(rec, { dir = captureDir(), raw = null, rawKind = 'html' } = {}) {
  const problems = validate(rec);
  if (problems.length) throw new Error(`invalid capture:\n- ${problems.join('\n- ')}`);
  const date = rec.time.slice(0, 10);
  const where = slug(hostOf(rec.source.url) || (rec.source.file && basename(rec.source.file)) || rec.source.tool || rec.source.kind);
  const name = slug(primary(rec.findings)?.rule || 'capture');
  let folder = join(dir, `${date}-${where}-${name}`);
  for (let n = 2; existsSync(folder); n++) folder = join(dir, `${date}-${where}-${name}-${n}`);
  mkdirSync(folder, { recursive: true });
  if (raw) {
    const file = rawKind === 'html' ? 'raw.html.txt' : 'raw.txt';
    const r = redact(raw.slice(0, MAX_EVIDENCE), { keepEmails: true });
    writeFileSync(join(folder, file), r.text);
    rec.evidence.push(file);
    rec.redactions += r.count;
  }
  writeFileSync(join(folder, 'capture.json'), JSON.stringify(rec, null, 2) + '\n');
  writeFileSync(join(folder, 'README.md'), readme(rec));
  appendFileSync(join(dir, 'index.jsonl'), JSON.stringify({ time: rec.time, level: rec.level, id: rec.id, folder, summary: rec.summary }) + '\n');
  return folder;
}

// A note is one line in notes.jsonl, not a folder.
export function writeNote(rec, { dir = captureDir() } = {}) {
  mkdirSync(dir, { recursive: true });
  const line = { time: rec.time, level: 'note', id: rec.id, source: rec.source, rules: rec.findings.map((f) => f.rule), excerpt: rec.payload.text.slice(0, 300), hidden_how: rec.payload.hidden_how };
  appendFileSync(join(dir, 'notes.jsonl'), JSON.stringify(line) + '\n');
  return join(dir, 'notes.jsonl');
}

// Session state: once a session has seen a stop (or, in careful mode, read outside content),
// outward actions need approval. `read` names that outside content when there is no capture.
export function markSession(dir, sessionId, folder, read = null) {
  if (!sessionId) return;
  const d = join(dir, '.sessions');
  mkdirSync(d, { recursive: true });
  writeFileSync(join(d, `${slug(sessionId)}.json`), JSON.stringify({ since: isoLocal(), capture: folder, ...(read ? { read } : {}) }) + '\n');
}

export function sessionState(dir, sessionId) {
  if (!sessionId) return null;
  const f = join(dir, '.sessions', `${slug(sessionId)}.json`);
  if (!existsSync(f)) return null;
  try { return JSON.parse(readFileSync(f, 'utf8')); } catch { return null; }
}

// One OTLP/JSON log record, ready to POST to a collector's /v1/logs. No network here.
export function toOtlp(rec) {
  const value = (v) => (Array.isArray(v) ? { arrayValue: { values: v.map(value) } }
    : typeof v === 'boolean' ? { boolValue: v }
      : typeof v === 'number' ? { doubleValue: v } : { stringValue: String(v) });
  const attrs = Object.entries(rec.attributes || {}).map(([key, v]) => ({ key, value: value(v) }));
  return {
    resourceLogs: [{
      resource: { attributes: [{ key: 'service.name', value: { stringValue: 'firstwatch' } }] },
      scopeLogs: [{
        scope: { name: 'firstwatch', version: VERSION },
        logRecords: [{
          timeUnixNano: String(BigInt(Date.parse(rec.time)) * 1000000n),
          observedTimeUnixNano: String(BigInt(Date.now()) * 1000000n),
          severityNumber: rec.level === 'stop' ? 13 : 9,
          severityText: rec.level === 'stop' ? 'WARN' : 'INFO',
          eventName: 'firstwatch.capture',
          body: { stringValue: rec.summary },
          attributes: attrs,
        }],
      }],
    }],
  };
}
