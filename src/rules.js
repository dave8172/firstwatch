// Loads the shared detection rules (rules/rules.json, also used by the Python package).

import { readFileSync } from 'node:fs';

const data = JSON.parse(readFileSync(new URL('../rules/rules.json', import.meta.url), 'utf8'));
const rx = (p) => new RegExp(p.source, p.flags.replace('g', ''));

export const RULES_VERSION = data.version;
export const ATLAS = data.atlas;
export const OWASP = data.owasp;
export const AGENT_RE = rx(data.agent);
export const HIDDEN_STYLE = data.hidden_style.map((h) => [rx(h), h.label]);
export const DISCUSSION = { re: new RegExp(data.discussion.source, 'gi'), min: data.discussion.min };
export const PRIORITY = data.priority;
export const BUILTIN = Object.fromEntries(data.builtin.map((b) => [b.id, b]));

export const RULES = data.rules.map((r) => (r.pattern
  ? { ...r, re: rx(r.pattern) }
  : { ...r, agent: rx(r.agent), imperative: rx(r.imperative), danger: rx(r.danger) }));
