// After editing rules/rules.json: copy it into the Python package and regenerate docs/rules.md.
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs';

const at = (p) => new URL(`../${p}`, import.meta.url);
copyFileSync(at('rules/rules.json'), at('python/src/firstwatch/rules.json'));

const d = JSON.parse(readFileSync(at('rules/rules.json'), 'utf8'));
const ids = (xs, names) => xs.map((x) => `${x} ${names[x] ?? ''}`.trim()).join('<br>');
const lvl = (l) => l ?? 'only if hidden or aimed at AI';

const lines = [
  '# What firstwatch detects',
  '',
  `<!-- Generated from rules/rules.json (version ${d.version}) by scripts/sync-rules.mjs. Edit the JSON, not this file. -->`,
  '',
  'Each rule has two levels: one for text people can see, one for text hidden from them. **stop** means the agent must not follow it and its owner hears about it. **note** means it gets logged quietly.',
  '',
  'Three adjustments apply to every rule:',
  '- **Hidden text raises** a match to stop.',
  '- **Quoted or code-block text lowers** a visible stop to a note: it\'s someone writing about an attack.',
  `- **A page that discusses attacks** (visible text matching \`${d.discussion.source}\` ${d.discussion.min}+ times) has its visible stops lowered to notes. Its hidden text still stops.`,
  '',
  '## Rules',
  '',
  '| Rule | Catches | Visible | Hidden | MITRE ATLAS | OWASP LLM Top 10 (2025) |',
  '|---|---|---|---|---|---|',
  ...d.rules.map((r) => `| \`${r.id}\` | ${r.what} | ${lvl(r.visible)} | ${r.hidden} | ${ids(r.atlas, d.atlas)} | ${ids(r.owasp, d.owasp)} |`),
  ...d.builtin.map((b) => `| \`${b.id}\` | ${b.what} | ${b.level} | ${b.level} | ${ids(b.atlas, d.atlas)} | ${ids(b.owasp, d.owasp)} |`),
  '',
  '`agent-imperative` matches a sentence that names an AI (AI, LLM, GPT, Claude, Gemini, ChatGPT, Copilot, assistant, chatbot, language model) *and* gives an order (you must, do not, never, always, before you answer…). Visible, it\'s a note, unless the order is to send, pay, transfer, delete, reveal, grant, approve, sign up or subscribe. Words like "agents" alone don\'t count: "our agents will never ask for your password" is about people.',
  '',
  '## Where text hides',
  '',
  '| How | Found in |',
  '|---|---|',
  '| `html-comment` | `<!-- … -->` |',
  ...d.hidden_style.map((h) => `| \`${h.label}\` | an inline \`style\` matching \`${h.source.replace(/\|/g, '\\|')}\` |`),
  '| `attr:hidden`, `attr:aria-hidden`, `class:hidden` | the `hidden` attribute, `aria-hidden="true"`, classes `hidden` / `d-none` / `invisible` |',
  '| `attribute:alt`, `attribute:title`, `attribute:aria-label`, `attribute:content`, `attribute:data-*` | attribute values longer than 15 characters (image alt text, meta descriptions…) |',
  '| `unicode-tag-characters` | invisible Unicode tag characters (U+E0000–U+E007F), decoded and scanned |',
  '| `zero-width-characters` | zero-width and soft-hyphen characters inside words, removed before matching |',
  '| `base64` | base64 runs of 40+ characters that decode to readable text, decoded and scanned |',
  '| `bidi-control-characters` | characters that reorder text on screen |',
  '',
  'Text inside `<script>`, `<style>` and `<template>` is skipped.',
  '',
  'To add or change a rule: [CONTRIBUTING.md](../CONTRIBUTING.md#adding-or-changing-a-rule).',
  '',
];
writeFileSync(at('docs/rules.md'), lines.join('\n'));
console.log('python/src/firstwatch/rules.json and docs/rules.md updated');
