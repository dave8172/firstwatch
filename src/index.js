// firstwatch: first line of defence for AI agents.
//
//   import { scan, watch } from 'firstwatch';
//   scan(pageHtml)              // { level: 'clean'|'note'|'stop', findings: [...] }
//   watch(pageHtml, { url })    // scans, saves a capture on a stop, returns the result + saved

import { scan } from './scan.js';
import { build, validate, writeCapture, writeNote, toOtlp, captureDir, primary, SPEC, VERSION } from './capture.js';
import { redact } from './redact.js';
import { RULES_VERSION } from './rules.js';

export { scan, build, validate, writeCapture, writeNote, toOtlp, captureDir, redact, SPEC, VERSION, RULES_VERSION };

// Scan one piece of outside content and record what it finds. A stop is saved as a
// capture folder, a note as one line in notes.jsonl. Your code decides what to do
// next; on a stop, don't pass the content on as instructions.
export function watch(text, { url = null, file = null, tool = null, kind = null, task = null, steps = [], sessionId = null, agentName = null, dir, raw } = {}) {
  const result = { ...scan(text), saved: null };
  if (result.level === 'clean') return result;
  const top = primary(result.findings);
  const rec = build({
    level: result.level,
    findings: result.findings,
    source: { kind: kind || (url ? 'web' : file ? 'file' : tool ? 'tool' : 'other'), url, file, tool, where: top.where },
    payload: { text: top.excerpt, hidden: top.hidden, hidden_how: top.hidden_how },
    caught_by: 'scanner',
    outcome: result.level === 'stop' ? 'blocked' : 'unknown',
    trace: { task, steps },
    repro: [url ? `Fetch ${url} as raw HTML (no JavaScript).` : file ? `Open ${file}.` : 'Feed the same content to the agent.', `Find the text: "${top.excerpt.slice(0, 160)}"`],
    context: { session_id: sessionId, agent_name: agentName },
  });
  const content = raw ?? text;
  result.saved = result.level === 'stop'
    ? writeCapture(rec, { dir: dir ?? captureDir(), raw: content, rawKind: /</.test(content) ? 'html' : 'text' })
    : writeNote(rec, { dir: dir ?? captureDir() });
  return result;
}
