// False-alarm check: fetch ordinary pages as raw HTML and scan them.
// Usage: node scripts/check-pages.mjs [urls.txt]   (one URL per line; default: scripts/pages.txt)
// Ordinary pages should come back clean or note. A stop needs a look: either a real attack or a rule to fix.
import { readFileSync } from 'node:fs';
import { scan } from '../src/scan.js';

const list = process.argv[2] || new URL('./pages.txt', import.meta.url);
const urls = readFileSync(list, 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
let stops = 0;
for (const url of urls) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000), headers: { 'user-agent': 'Mozilla/5.0 (compatible; firstwatch-check)' } });
    const r = scan(await res.text());
    if (r.level === 'stop') stops++;
    const rules = [...new Set(r.findings.map((f) => `${f.rule}:${f.level}`))].join(' ');
    console.log(`${r.level.padEnd(5)}  ${url}${rules ? `  (${rules})` : ''}`);
  } catch (e) {
    console.log(`error  ${url}  (${e.message})`);
  }
}
console.log(`\n${urls.length} pages, ${stops} stop(s)`);
