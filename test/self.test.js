// firstwatch checks its own source for the tricks it detects.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const INVISIBLE = /[\u200B-\u200F\u2060-\u2064\uFEFF\u00AD\u202A-\u202E\u2066-\u2069]|[\u{E0000}-\u{E007F}]/u;
const SKIP = new Set(['node_modules', '.git', 'fixtures', 'dist', '__pycache__', 'security-captures']);

function* files(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* files(p);
    else if (/\.(js|mjs|py|json|md|toml|yml|yaml)$/.test(name)) yield p;
  }
}

test('no invisible or reordering characters in source, docs or config (fixtures excepted)', () => {
  const bad = [...files(ROOT)].filter((p) => INVISIBLE.test(readFileSync(p, 'utf8')));
  assert.deepEqual(bad, []);
});

test('the Python package carries the same rules file', () => {
  assert.equal(readFileSync(join(ROOT, 'python/src/firstwatch/rules.json'), 'utf8'), readFileSync(join(ROOT, 'rules/rules.json'), 'utf8'));
});

test('src/rules-data.js carries the same rules (run: npm run sync-rules)', async () => {
  const { default: data } = await import('../src/rules-data.js');
  assert.deepEqual(data, JSON.parse(readFileSync(join(ROOT, 'rules/rules.json'), 'utf8')));
});

test('scan.js and its imports use no Node-only modules, so it runs in a browser', () => {
  for (const f of ['src/scan.js', 'src/rules.js', 'src/rules-data.js']) assert.doesNotMatch(readFileSync(join(ROOT, f), 'utf8'), /from ['"]node:|require\(/, f);
});

test('docs/rules.md is generated from the current rules (run: npm run sync-rules)', () => {
  const doc = readFileSync(join(ROOT, 'docs/rules.md'), 'utf8');
  const rules = JSON.parse(readFileSync(join(ROOT, 'rules/rules.json'), 'utf8'));
  for (const r of [...rules.rules, ...rules.builtin]) assert.ok(doc.includes(`\`${r.id}\``), r.id);
  assert.ok(doc.includes(`version ${rules.version}`));
});
