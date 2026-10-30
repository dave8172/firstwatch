// Scorecard: score every labelled case in test/scorecard/cases.json and compare with
// the accepted levels in test/scorecard/baseline.json.
// Usage: node scripts/scorecard.mjs              show the score and every change from the baseline
//        node scripts/scorecard.mjs --update     accept the current levels (refuses if anything got worse)
//        node scripts/scorecard.mjs --update --allow-worse   accept them anyway; say why in the commit
// Worse = an attack's level went down, or a harmless text's level went up.
import { readFileSync, writeFileSync } from 'node:fs';
import { scan } from '../src/scan.js';

const DIR = new URL('../test/scorecard/', import.meta.url);
const RANK = { clean: 0, note: 1, stop: 2 };
const { cases } = JSON.parse(readFileSync(new URL('cases.json', DIR), 'utf8'));
let baseline = { levels: {} };
try { baseline = JSON.parse(readFileSync(new URL('baseline.json', DIR), 'utf8')); } catch {}

const levels = {};
for (const c of cases) levels[c.id] = scan(c.text).level;
const summary = summarise(cases, levels);

const changes = cases
  .filter((c) => baseline.levels[c.id] !== levels[c.id])
  .map((c) => {
    const was = baseline.levels[c.id];
    const now = levels[c.id];
    const delta = was === undefined ? 0 : RANK[now] - RANK[was];
    const verdict = was === undefined ? 'new' : (c.label === 'attack' ? delta > 0 : delta < 0) ? 'better' : 'worse';
    return { ...c, was: was ?? '-', now, verdict };
  });
const worse = changes.filter((c) => c.verdict === 'worse');

console.log('                 stop  note  clean');
for (const label of ['attack', 'harmless']) {
  const s = summary[label];
  console.log(`${(label + ` (${s.total})`).padEnd(16)} ${String(s.stop).padStart(4)}  ${String(s.note).padStart(4)}  ${String(s.clean).padStart(5)}`);
}
if (changes.length) {
  console.log(`\nChanged from the baseline (${changes.length}):`);
  for (const c of changes) console.log(`  ${c.verdict.padEnd(6)} ${c.id} (${c.label}) ${c.was} → ${c.now}`);
} else {
  console.log('\nSame as the baseline.');
}

if (process.argv.includes('--update')) {
  if (worse.length && !process.argv.includes('--allow-worse')) {
    console.error(`\nNot updated: ${worse.length} case(s) got worse. Fix them, or pass --allow-worse and say why in the commit.`);
    process.exit(1);
  }
  writeFileSync(new URL('baseline.json', DIR), JSON.stringify({ summary, levels }, null, 1) + '\n');
  console.log('\nbaseline.json updated.');
}

function summarise(list, lv) {
  const out = {};
  for (const label of ['attack', 'harmless']) {
    const mine = list.filter((c) => c.label === label);
    out[label] = { total: mine.length, stop: 0, note: 0, clean: 0 };
    for (const c of mine) out[label][lv[c.id]]++;
  }
  return out;
}
