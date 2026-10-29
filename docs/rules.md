# What firstwatch detects

<!-- Generated from rules/rules.json (version 0.2.0) by scripts/sync-rules.mjs. Edit the JSON, not this file. -->

Each rule has two levels: one for text people can see, one for text hidden from them. **stop** means the agent must not follow it and its owner hears about it. **note** means it gets logged quietly.

Three adjustments apply to every rule:
- **Hidden text raises** a match to stop.
- **Quoted or code-block text lowers** a visible stop to a note: it's someone writing about an attack.
- **A page that discusses attacks** (visible text matching `prompt[ -]?injections?|jailbreak` 3+ times) has its visible stops lowered to notes. Its hidden text still stops.

## Rules

| Rule | Catches | Visible | Hidden | MITRE ATLAS | OWASP LLM Top 10 (2025) |
|---|---|---|---|---|---|
| `override-instructions` | tells the agent to ignore or replace its instructions | stop | stop | AML.T0051.001 LLM Prompt Injection: Indirect | LLM01:2025 Prompt Injection |
| `role-hijack` | tries to switch the agent into an unrestricted role | stop | stop | AML.T0054 LLM Jailbreak | LLM01:2025 Prompt Injection |
| `new-instructions` | announces new instructions for the reader | note | stop | AML.T0051.001 LLM Prompt Injection: Indirect | LLM01:2025 Prompt Injection |
| `conceal-from-user` | tells the agent to hide something from its user | stop | stop | AML.T0051.001 LLM Prompt Injection: Indirect | LLM01:2025 Prompt Injection |
| `exfiltrate-secrets` | asks for secrets to be sent to an outside address | stop | stop | AML.T0086 Exfiltration via AI Agent Tool Invocation<br>AML.T0057 LLM Data Leakage | LLM02:2025 Sensitive Information Disclosure<br>LLM06:2025 Excessive Agency |
| `request-secrets` | asks for passwords, keys, codes or other secrets to be sent back | stop | stop | AML.T0057 LLM Data Leakage | LLM02:2025 Sensitive Information Disclosure<br>LLM06:2025 Excessive Agency |
| `request-all-files` | asks for the contents of every file, email or document to be sent | stop | stop | AML.T0057 LLM Data Leakage<br>AML.T0086 Exfiltration via AI Agent Tool Invocation | LLM02:2025 Sensitive Information Disclosure<br>LLM06:2025 Excessive Agency |
| `bulk-delete` | asks for everything to be deleted | stop | stop | AML.T0051.001 LLM Prompt Injection: Indirect | LLM06:2025 Excessive Agency |
| `reveal-instructions` | asks the agent to reveal its instructions | stop | stop | AML.T0057 LLM Data Leakage | LLM07:2025 System Prompt Leakage |
| `remote-code` | pipes a download straight into a shell | only if hidden or aimed at AI | stop | AML.T0051.001 LLM Prompt Injection: Indirect | LLM06:2025 Excessive Agency |
| `image-exfiltration` | markdown image whose URL carries a data placeholder | stop | stop | AML.T0086 Exfiltration via AI Agent Tool Invocation | LLM02:2025 Sensitive Information Disclosure |
| `modify-agent-config` | asks for changes to the agent's own setup | note | stop | AML.T0081 Modify AI Agent Configuration | LLM06:2025 Excessive Agency |
| `agent-imperative` | gives orders to AI agents | note | stop | AML.T0051.001 LLM Prompt Injection: Indirect | LLM01:2025 Prompt Injection |
| `unicode-tag-smuggling` | hides text in invisible Unicode tag characters | stop | stop | AML.T0068 LLM Prompt Obfuscation<br>AML.T0051.001 LLM Prompt Injection: Indirect | LLM01:2025 Prompt Injection |
| `bidi-control` | contains characters that reorder text on screen | note | note | AML.T0068 LLM Prompt Obfuscation | LLM01:2025 Prompt Injection |
| `hidden-agent-text` | hidden text that mentions AI agents | note | note | AML.T0051.001 LLM Prompt Injection: Indirect | LLM01:2025 Prompt Injection |

`agent-imperative` matches a sentence that names an AI (AI, LLM, GPT, Claude, Gemini, ChatGPT, Copilot, assistant, chatbot, language model) *and* gives an order (you must, do not, never, always, before you answer…). Visible, it's a note, unless the order is to send, pay, transfer, delete, reveal, grant, approve, sign up or subscribe. Words like "agents" alone don't count: "our agents will never ask for your password" is about people.

## Where text hides

| How | Found in |
|---|---|
| `html-comment` | `<!-- … -->` |
| `css:display-none` | an inline `style` matching `display\s*:\s*none` |
| `css:visibility-hidden` | an inline `style` matching `visibility\s*:\s*hidden` |
| `css:tiny-text` | an inline `style` matching `font-size\s*:\s*(?:0\|0?\.\d+\|1)(?:px\|pt\|em\|rem)?\s*(?:;\|$\|!)` |
| `css:opacity-0` | an inline `style` matching `opacity\s*:\s*0(?:\.0+)?\s*(?:;\|$\|!)` |
| `css:off-screen` | an inline `style` matching `(?:left\|top\|right\|text-indent\|margin-left)\s*:\s*-\d{3,}` |
| `css:white-or-transparent-text` | an inline `style` matching `(?:^\|[;\s])color\s*:\s*(?:#fff\b\|#ffffff\b\|white\b\|transparent\b\|rgba\([^)]*,\s*0\s*\))` |
| `css:zero-size` | an inline `style` matching `(?:height\|width)\s*:\s*0(?:px)?\s*;[^\"']*overflow\s*:\s*hidden` |
| `attr:hidden`, `attr:aria-hidden`, `class:hidden` | the `hidden` attribute, `aria-hidden="true"`, classes `hidden` / `d-none` / `invisible` |
| `attribute:alt`, `attribute:title`, `attribute:aria-label`, `attribute:content`, `attribute:data-*` | attribute values longer than 15 characters (image alt text, meta descriptions…) |
| `unicode-tag-characters` | invisible Unicode tag characters (U+E0000–U+E007F), decoded and scanned |
| `zero-width-characters` | zero-width and soft-hyphen characters inside words, removed before matching |
| `base64` | base64 runs of 40+ characters that decode to readable text, decoded and scanned |
| `bidi-control-characters` | characters that reorder text on screen |

Text inside `<script>`, `<style>` and `<template>` is skipped.

To add or change a rule: [CONTRIBUTING.md](../CONTRIBUTING.md#adding-or-changing-a-rule).
