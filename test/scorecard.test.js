// The scorecard: every labelled case must score exactly its accepted level.
// A rule change that moves any case fails here until the baseline is updated on
// purpose (npm run scorecard -- --update), which refuses changes for the worse.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { scan } from '../src/scan.js';

const read = (f) => JSON.parse(readFileSync(new URL(`./scorecard/${f}`, import.meta.url), 'utf8'));
const { cases } = read('cases.json');
const { levels } = read('baseline.json');

test('every scorecard case has a baseline level', () => {
  assert.deepEqual(cases.map((c) => c.id).filter((id) => !(id in levels)), []);
});

for (const c of cases) {
  test(`scorecard ${c.id} (${c.label}) → ${levels[c.id]}`, () => {
    assert.equal(scan(c.text).level, levels[c.id], 'level moved: run npm run scorecard to see it');
  });
}
