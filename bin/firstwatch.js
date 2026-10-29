#!/usr/bin/env node
// firstwatch: watch, record and stop attacks aimed at AI agents.

import { readFileSync, existsSync, rmSync, readdirSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { scan } from '../src/scan.js';
import { build, validate, writeCapture, writeNote, captureDir, toOtlp, VERSION } from '../src/capture.js';
import { handle } from '../src/claude-code.js';

const HELP = `firstwatch ${VERSION}: watch, record and stop attacks aimed at AI agents

  firstwatch scan [file]            scan a file (or stdin) and print findings as JSON
  firstwatch capture                read a capture as JSON on stdin, check it, save it
  firstwatch list                   list saved captures
  firstwatch validate <capture.json>  check a capture against the format
  firstwatch export otlp <capture.json>  print it as an OpenTelemetry (OTLP/JSON) log record
  firstwatch clear [--session <id>] lift the approval gate for one session, or all
  firstwatch hook claude-code       run as a Claude Code hook (reads the event on stdin)

Captures go to ./security-captures, or FIRSTWATCH_DIR if set.`;

const readStdin = () => new Promise((res) => {
  if (process.stdin.isTTY) return res('');
  let d = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => (d += c));
  process.stdin.on('end', () => res(d));
});

const fail = (msg, code = 1) => { process.stderr.write(`firstwatch: ${msg}\n`); process.exit(code); };
const print = (v) => process.stdout.write(typeof v === 'string' ? `${v}\n` : `${JSON.stringify(v, null, 2)}\n`);

async function main(argv) {
  const [cmd, ...args] = argv;
  if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') return print(HELP);
  if (cmd === '-v' || cmd === '--version') return print(VERSION);

  if (cmd === 'hook') {
    if (args[0] !== 'claude-code') fail('supported: firstwatch hook claude-code');
    let ev;
    try { ev = JSON.parse(await readStdin()); } catch { return; } // never break the agent on bad input
    try {
      const out = await handle(ev);
      if (process.env.FIRSTWATCH_DEBUG_LOG) appendFileSync(process.env.FIRSTWATCH_DEBUG_LOG, JSON.stringify({ event: ev.hook_event_name, tool: ev.tool_name, mode: ev.permission_mode, out }) + '\n');
      if (out) process.stdout.write(JSON.stringify(out));
    } catch (e) {
      process.stderr.write(`firstwatch: ${e.message}\n`); // exit 0: a hook error must not block the agent
    }
    return;
  }

  if (cmd === 'scan') {
    const text = args[0] && args[0] !== '-' ? readFileSync(args[0], 'utf8') : await readStdin();
    return print(scan(text));
  }

  if (cmd === 'capture') {
    let input;
    try { input = JSON.parse(await readStdin()); } catch (e) { fail(`stdin must be JSON: ${e.message}`); }
    const text = input.payload?.text || input.text;
    if (!text) fail('payload.text (the exact text of the attack) is required');
    input.payload = { hidden: false, hidden_how: [], ...input.payload, text };
    const found = scan(text).findings;
    input.findings = [...(input.findings || []), ...found];
    input.level = input.level || (found.some((f) => f.level === 'stop') ? 'stop' : 'note');
    const rec = build(input);
    const problems = validate(rec);
    if (problems.length) fail(`capture is incomplete:\n- ${problems.join('\n- ')}`);
    const raw = input.raw_file && existsSync(input.raw_file) ? readFileSync(input.raw_file, 'utf8') : null;
    const where = rec.level === 'stop'
      ? writeCapture(rec, { raw, rawKind: /\.html?$/i.test(input.raw_file || '') ? 'html' : 'text' })
      : writeNote(rec);
    return print({ level: rec.level, saved: where, findings: rec.findings.length });
  }

  if (cmd === 'list') {
    const f = join(captureDir(), 'index.jsonl');
    if (!existsSync(f)) return print('No captures yet.');
    for (const line of readFileSync(f, 'utf8').trim().split('\n')) {
      try {
        const r = JSON.parse(line);
        print(`${r.time}  ${r.level.toUpperCase()}  ${r.summary}\n    ${r.folder}`);
      } catch { /* skip a broken line */ }
    }
    return;
  }

  if (cmd === 'validate') {
    if (!args[0]) fail('usage: firstwatch validate <capture.json>');
    const problems = validate(JSON.parse(readFileSync(args[0], 'utf8')));
    if (problems.length) fail(`not valid:\n- ${problems.join('\n- ')}`);
    return print('valid');
  }

  if (cmd === 'export') {
    if (args[0] !== 'otlp' || !args[1]) fail('usage: firstwatch export otlp <capture.json>');
    return print(toOtlp(JSON.parse(readFileSync(args[1], 'utf8'))));
  }

  if (cmd === 'clear') {
    const d = join(captureDir(), '.sessions');
    if (!existsSync(d)) return print('No gated sessions.');
    const i = args.indexOf('--session');
    const files = i >= 0 ? [`${String(args[i + 1]).toLowerCase().replace(/[^a-z0-9]+/g, '-')}.json`] : readdirSync(d);
    for (const f of files) rmSync(join(d, f), { force: true });
    return print(`Lifted the gate for ${i >= 0 ? `session ${args[i + 1]}` : 'all sessions'}.`);
  }

  fail(`unknown command "${cmd}"\n\n${HELP}`);
}

main(process.argv.slice(2));
