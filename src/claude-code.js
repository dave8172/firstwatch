// Claude Code adapter. Claude Code runs `firstwatch hook claude-code` and passes
// one JSON event on stdin. PostToolUse: scan the tool result. PreToolUse: gate
// risky actions. Output follows Claude Code's hook JSON.

import { readFileSync, existsSync } from 'node:fs';
import { scan } from './scan.js';
import { riskyMcp, warning } from './gate.js';

export { riskyMcp };
import { build, writeCapture, writeNote, markSession, sessionState, captureDir, primary } from './capture.js';

// Tools whose results never come from outside, so there is nothing to scan.
const SKIP_SCAN = /^(?:TodoWrite|ToolSearch|Skill|Edit|MultiEdit|Write|NotebookEdit|Glob|ExitPlanMode|EnterPlanMode|AskUserQuestion|KillShell|TaskStop)$/;
// Tools that only read; everything else is outward or changes something.
const READ_ONLY = /^(?:Read|Grep|Glob|LS|TodoWrite|ToolSearch|Skill|AskUserQuestion|ExitPlanMode|EnterPlanMode|BashOutput|TaskOutput)$/;
const FETCH_TIMEOUT = 8000;
const MAX_FETCH = 2_000_000;

export function resultText(toolName, response) {
  if (response == null) return '';
  if (typeof response === 'string') return response;
  if (toolName === 'Bash') return [response.stdout, response.stderr].filter(Boolean).join('\n');
  if (toolName === 'Read') return response.file?.content ?? response.content ?? JSON.stringify(response);
  if (toolName === 'WebFetch') return response.result ?? '';
  return JSON.stringify(response);
}

async function fetchRaw(url) {
  if (process.env.FIRSTWATCH_REFETCH === '0' || !/^https?:\/\//i.test(url || '')) return null;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT), redirect: 'follow', headers: { 'user-agent': 'Mozilla/5.0 (compatible; firstwatch; +https://github.com/dave8172/firstwatch)' } });
    const buf = Buffer.from(await res.arrayBuffer());
    return buf.subarray(0, MAX_FETCH).toString('utf8');
  } catch {
    return null;
  }
}

// The last steps before this tool call, from the session transcript.
export function traceFrom(transcriptPath, limit = 8) {
  const out = { task: null, steps: [] };
  if (!transcriptPath || !existsSync(transcriptPath)) return out;
  let lines;
  try { lines = readFileSync(transcriptPath, 'utf8').trim().split('\n').slice(-400); } catch { return out; }
  for (const line of lines) {
    let e;
    try { e = JSON.parse(line); } catch { continue; }
    const content = e.message?.content;
    if (e.type === 'user' && typeof content === 'string') out.task = content.slice(0, 300);
    if (e.type === 'user' && Array.isArray(content)) {
      const t = content.find((c) => c.type === 'text' && c.text && !c.text.startsWith('<'));
      if (t) out.task = t.text.slice(0, 300);
    }
    if (e.type === 'assistant' && Array.isArray(content)) {
      for (const c of content) {
        if (c.type !== 'tool_use') continue;
        const i = c.input || {};
        const summary = i.url || i.command || i.file_path || i.query || i.pattern || Object.keys(i).slice(0, 3).join(', ');
        out.steps.push({ tool: c.name, summary: String(summary).slice(0, 200) });
      }
    }
  }
  out.steps = out.steps.slice(-limit);
  return out;
}

export async function postToolUse(ev) {
  const tool = ev.tool_name || '';
  if (SKIP_SCAN.test(tool)) return null;
  const dir = captureDir(ev.cwd);
  const text = resultText(tool, ev.tool_response);
  const url = tool === 'WebFetch' ? ev.tool_input?.url : null;
  const raw = url ? await fetchRaw(url) : null;

  const results = [scan(text)];
  if (raw) results.push(scan(raw));
  const findings = results.flatMap((r) => r.findings);
  if (!findings.length) return null;
  const level = findings.some((f) => f.level === 'stop') ? 'stop' : 'note';

  const top = primary(findings);
  const kind = tool === 'WebFetch' ? 'web' : tool === 'WebSearch' ? 'search' : tool === 'Bash' ? 'command' : tool === 'Read' || tool === 'Grep' ? 'file' : 'tool';
  const repro = [];
  if (url) repro.push(`Fetch ${url} as raw HTML (no JavaScript).`, `Look in the ${top.where}${top.hidden_how.length ? ` (${top.hidden_how.join(', ')})` : ''}.`);
  else if (ev.tool_input?.file_path) repro.push(`Open ${ev.tool_input.file_path}.`);
  else if (ev.tool_input?.command) repro.push(`Run: ${ev.tool_input.command}`);
  else repro.push(`Call ${tool} with: ${JSON.stringify(ev.tool_input).slice(0, 300)}`);
  repro.push(`Find the text: "${top.excerpt.slice(0, 160)}"`);

  const rec = build({
    level,
    findings,
    source: { kind, url: url || ev.tool_input?.url || null, tool, where: top.where, file: ev.tool_input?.file_path || null },
    payload: { text: top.excerpt, hidden: top.hidden, hidden_how: top.hidden_how },
    outcome: 'unknown',
    caught_by: 'hook',
    trace: traceFrom(ev.transcript_path),
    repro,
    context: { session_id: ev.session_id, tool_use_id: ev.tool_use_id },
  });

  if (level === 'note') {
    writeNote(rec, { dir });
    return null;
  }
  const folder = writeCapture(rec, { dir, raw: raw || text, rawKind: raw || /<[a-z][\s\S]*>/i.test(text) ? 'html' : 'text' });
  markSession(dir, ev.session_id, folder);
  const rules = [...new Set(findings.filter((f) => f.level === 'stop').map((f) => f.rule))];
  return {
    systemMessage: `firstwatch stopped an attack in a ${tool} result → ${folder}`,
    hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: warning(tool, rules, folder) },
  };
}

export function preToolUse(ev) {
  const tool = ev.tool_name || '';
  const dir = captureDir(ev.cwd);
  const ask = (reason) => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: reason } });

  if (riskyMcp(tool)) return ask(`firstwatch: ${tool} acts on your behalf (send, pay, delete, share or grant). Approve it?`);
  const state = sessionState(dir, ev.session_id);
  if (state && !READ_ONLY.test(tool)) {
    return ask(`firstwatch: this session met an attack (${state.capture}). ${tool} could act on it. Check the action, then approve or deny.`);
  }
  return null;
}

export async function handle(ev) {
  if (ev.hook_event_name === 'PostToolUse') return postToolUse(ev);
  if (ev.hook_event_name === 'PreToolUse') return preToolUse(ev);
  return null;
}
