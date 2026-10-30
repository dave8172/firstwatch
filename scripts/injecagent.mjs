// Outside benchmark: InjecAgent (MIT, github.com/uiuc-kang-lab/InjecAgent), attacks planted in
// real-shaped tool responses, written by people other than firstwatch's authors.
// Usage: node scripts/injecagent.mjs [git-ref]   compares the working tree with a past release (default: the last tag)
// Downloads the pinned test cases once into the system temp folder. Run before every release.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const COMMIT = 'f19c9f2c79a41046eb13c03c51a24c567a8ffa07';
const FILES = ['test_cases_dh_base.json', 'test_cases_ds_base.json', 'test_cases_dh_enhanced.json', 'test_cases_ds_enhanced.json', 'user_cases.jsonl'];
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ref = process.argv[2] || execFileSync('git', ['-C', ROOT, 'describe', '--tags', '--abbrev=0'], { encoding: 'utf8' }).trim();

const data = join(tmpdir(), `firstwatch-injecagent-${COMMIT.slice(0, 7)}`);
mkdirSync(data, { recursive: true });
for (const f of FILES) {
  if (existsSync(join(data, f))) continue;
  const res = await fetch(`https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/${COMMIT}/data/${f}`);
  if (!res.ok) throw new Error(`${f}: HTTP ${res.status}`);
  writeFileSync(join(data, f), await res.text());
}

const old = mkdtempSync(join(tmpdir(), 'firstwatch-injecagent-old-'));
try {
  execFileSync('sh', ['-c', `git -C "$1" archive "$2" src rules | tar -x -C "$3"`, 'sh', ROOT, ref, old]);
  const versions = [[ref, (await import(pathToFileURL(join(old, 'src/scan.js')))).scan], ['working tree', (await import('../src/scan.js')).scan]];
  const read = (f) => JSON.parse(readFileSync(join(data, f), 'utf8'));
  const sets = [
    ['direct harm', read('test_cases_dh_base.json')],
    ['data stealing', read('test_cases_ds_base.json')],
    ['direct harm, enhanced', read('test_cases_dh_enhanced.json')],
    ['data stealing, enhanced', read('test_cases_ds_enhanced.json')],
  ];
  const clean = readFileSync(join(data, 'user_cases.jsonl'), 'utf8').trim().split('\n')
    .map((l) => String(JSON.parse(l)['Tool Response Template']).replace('<Attacker Instruction>', ''));

  console.log(`InjecAgent ${COMMIT.slice(0, 7)}: stop / note / clean per version\n`);
  console.log('set                       cases  ' + versions.map(([v]) => v.padEnd(22)).join(''));
  for (const [name, cases] of sets) {
    const cols = versions.map(([, scan]) => count(cases.map((c) => scan(String(c['Tool Response'])).level)));
    console.log(`${name.padEnd(25)} ${String(cases.length).padStart(5)}  ${cols.map((c) => c.padEnd(22)).join('')}`);
  }
  const cols = versions.map(([, scan]) => count(clean.map((t) => scan(t).level)));
  console.log(`${'clean (no attack)'.padEnd(25)} ${String(clean.length).padStart(5)}  ${cols.map((c) => c.padEnd(22)).join('')}`);
} finally {
  rmSync(old, { recursive: true, force: true });
}

function count(levels) {
  const c = { stop: 0, note: 0, clean: 0 };
  for (const l of levels) c[l]++;
  return `${c.stop} / ${c.note} / ${c.clean}`;
}
