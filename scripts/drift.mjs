// Drift check: what changed between a past release and the working tree, on the same texts.
// Usage: node scripts/drift.mjs <git-ref> [folder ...]
//   <git-ref>  the last release, e.g. v0.2.0
//   folder     ordinary documents to scan (.md .txt .html .rst .json), e.g. /usr/share/doc
// Always scans the scorecard cases and the test fixtures too. Prints every text whose
// level changed. A harmless text that gets worse, or an attack that gets better only
// by luck, needs a look before release. Run before every release (see CLAUDE.md).
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const [ref, ...folders] = process.argv.slice(2);
if (!ref) {
  console.error('usage: node scripts/drift.mjs <git-ref> [folder ...]');
  process.exit(2);
}

const old = mkdtempSync(join(tmpdir(), 'firstwatch-drift-'));
try {
  execFileSync('sh', ['-c', `git -C "$1" archive "$2" src rules | tar -x -C "$3"`, 'sh', ROOT, ref, old]);
  const { scan: before } = await import(pathToFileURL(join(old, 'src/scan.js')));
  const { scan: after } = await import('../src/scan.js');
  const { cases } = JSON.parse(readFileSync(join(ROOT, 'test/scorecard/cases.json'), 'utf8'));

  const texts = [];
  for (const c of cases) texts.push({ name: `scorecard ${c.id} (${c.label})`, group: c.label, text: c.text });
  for (const f of readdirSync(join(ROOT, 'test/fixtures'))) texts.push({ name: `fixture ${f}`, group: 'fixture', path: join(ROOT, 'test/fixtures', f) });
  for (const dir of folders) for (const p of walk(dir)) texts.push({ name: p, group: 'document', path: p });

  const RANK = { clean: 0, note: 1, stop: 2 };
  const tally = {};
  const changed = [];
  for (const t of texts) {
    let text = t.text;
    if (text === undefined) {
      try { text = readFileSync(t.path, 'utf8'); } catch { continue; }
    }
    const a = before(text);
    const b = after(text);
    const g = (tally[t.group] ??= { texts: 0, before: { clean: 0, note: 0, stop: 0 }, after: { clean: 0, note: 0, stop: 0 } });
    g.texts++;
    g.before[a.level]++;
    g.after[b.level]++;
    const ra = rules(a);
    const rb = rules(b);
    if (a.level !== b.level || ra !== rb) changed.push({ ...t, a: a.level, b: b.level, ra, rb, up: RANK[b.level] - RANK[a.level] });
  }

  console.log(`drift: ${ref} → working tree\n`);
  console.log('group      texts   before (clean/note/stop)   after (clean/note/stop)');
  for (const [g, v] of Object.entries(tally)) {
    console.log(`${g.padEnd(10)} ${String(v.texts).padStart(5)}   ${fmt(v.before).padEnd(26)} ${fmt(v.after)}`);
  }
  for (const [title, list] of [
    ['Level went up', changed.filter((c) => c.up > 0)],
    ['Level went down', changed.filter((c) => c.up < 0)],
    ['Same level, different rules', changed.filter((c) => c.up === 0)],
  ]) {
    if (!list.length) continue;
    console.log(`\n${title} (${list.length}):`);
    for (const c of list) console.log(`  ${c.a} → ${c.b}  ${c.name}${c.rb ? `  [${c.rb}]` : ''}`);
  }
  if (!changed.length) console.log('\nNo text changed level or rules.');
} finally {
  rmSync(old, { recursive: true, force: true });
}

function rules(r) {
  return [...new Set(r.findings.map((f) => `${f.rule}:${f.level}`))].sort().join(' ');
}

function fmt(c) {
  return `${c.clean} / ${c.note} / ${c.stop}`;
}

function* walk(dir) {
  let names;
  try { names = readdirSync(dir); } catch { return; }
  for (const name of names) {
    const p = join(dir, name);
    let s;
    try { s = statSync(p); } catch { continue; }
    if (s.isDirectory()) yield* walk(p);
    else if (/\.(md|txt|html?|rst|json)$/i.test(name) && s.size < 2_000_000) yield p;
  }
}
