// Detection rules. Each rule is a pattern with a level for visible text and one
// for text hidden from people. Hidden text, or text addressed to an agent, raises
// a rule to "stop". Rules map to MITRE ATLAS and OWASP LLM Top 10 (2025) IDs.

const SECRET = String.raw`(?:\.env\b|api[ _-]?keys?|access[ _-]?tokens?|auth(?:entication)?[ _-]?tokens?|secrets?|passwords?|credentials?|private[ _-]?keys?|ssh[ _-]?keys?|id_rsa|aws_[a-z_]+|session[ _-]?(?:tokens?|cookies?)|cookies|seed[ _-]?phrase|wallet)`;
const EXFIL_VERB = String.raw`(?:send|e-?mail|post|upload|share|forward|transmit|exfiltrate|leak|paste|include|append|attach|submit)`;
const DESTINATION = String.raw`(?:[\w.+-]+@[\w-]+\.[\w.]+|https?:\/\/\S+|\bto (?:this|the following|our|my) (?:address|url|endpoint|webhook|server|email)|\bin (?:your|the) (?:reply|response|answer|output))`;
// AI-specific words only: "our agents will never ask" on a bank page is about people.
const AGENT = String.raw`(?:\b(?:ai|llms?|gpt|claude|gemini|chatgpt|copilot)\b|\blanguage models?\b|\b(?:assistants?|chatbots?)\b)`;
const IMPERATIVE = String.raw`(?:\byou (?:must|should|need to|are required to|will|have to)\b|\bdo not\b|\bdon'?t\b|\bnever\b|\balways\b|\bimmediately\b|\bbefore (?:you )?(?:answer|respond|reply|continue|proceed)\b|\bmake sure\b)`;
// Actions that move money, data or access. Visible orders to agents only stop when they ask for one of these.
const DANGER = String.raw`(?:send|e-?mail|forward|upload|transfer|wire|pay|buy|purchase|delete|wipe|reveal|disclose|grant|authori[sz]e|approve|sign ?up|subscribe|share (?:your|the|all))`;

export const ATLAS = {
  'AML.T0051.001': 'LLM Prompt Injection: Indirect',
  'AML.T0054': 'LLM Jailbreak',
  'AML.T0057': 'LLM Data Leakage',
  'AML.T0068': 'LLM Prompt Obfuscation',
  'AML.T0081': 'Modify AI Agent Configuration',
  'AML.T0086': 'Exfiltration via AI Agent Tool Invocation',
  'AML.T0100': 'AI Agent Clickbait',
};

export const OWASP = {
  'LLM01:2025': 'Prompt Injection',
  'LLM02:2025': 'Sensitive Information Disclosure',
  'LLM06:2025': 'Excessive Agency',
  'LLM07:2025': 'System Prompt Leakage',
};

// visible: level when people can see the text (null = ignore unless hidden or addressed to an agent)
// hidden: level when the text is hidden from people
export const RULES = [
  {
    id: 'override-instructions',
    what: 'tells the agent to ignore or replace its instructions',
    re: /\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|all|any|your|system|original|preceding)\b[^.\n]{0,20}?\b(?:instructions?|prompts?|rules|directions|guidelines|directives|context|constraints)\b/i,
    visible: 'stop', hidden: 'stop', atlas: ['AML.T0051.001'], owasp: ['LLM01:2025'],
  },
  {
    id: 'role-hijack',
    what: 'tries to switch the agent into an unrestricted role',
    re: /\byou are now (?:in )?(?:dan\b|an? (?:unrestricted|unfiltered|jailbroken)|unrestricted|jailbroken|in developer mode)|\b(?:enter|enable|activate) (?:dan|god|jailbreak) mode\b|\bact as dan\b/i,
    visible: 'stop', hidden: 'stop', atlas: ['AML.T0054'], owasp: ['LLM01:2025'],
  },
  {
    id: 'new-instructions',
    what: 'announces new instructions for the reader',
    re: /\b(?:new|updated|real|actual|true|secret|hidden|additional) (?:system )?(?:instructions?|directives?|orders|task)\s*[:\-]/i,
    visible: 'note', hidden: 'stop', atlas: ['AML.T0051.001'], owasp: ['LLM01:2025'],
  },
  {
    id: 'conceal-from-user',
    what: 'tells the agent to hide something from its user',
    re: /\b(?:do not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|alert|notify|let)\b[^.\n]{0,30}?\b(?:the )?(?:user|human|owner|operator|anyone)\b|\bwithout (?:telling|informing|alerting|notifying|asking)\b[^.\n]{0,20}?\b(?:the )?(?:user|human|owner|operator)\b/i,
    visible: 'stop', hidden: 'stop', atlas: ['AML.T0051.001'], owasp: ['LLM01:2025'],
  },
  {
    id: 'exfiltrate-secrets',
    what: 'asks for secrets to be sent to an outside address',
    re: new RegExp(`\\b${EXFIL_VERB}\\b[^\\n]{0,80}?${SECRET}[^\\n]{0,80}?${DESTINATION}|${SECRET}[^\\n]{0,40}?\\b${EXFIL_VERB}\\b[^\\n]{0,60}?${DESTINATION}`, 'i'),
    visible: 'stop', hidden: 'stop', atlas: ['AML.T0086', 'AML.T0057'], owasp: ['LLM02:2025', 'LLM06:2025'],
  },
  {
    id: 'reveal-instructions',
    what: "asks the agent to reveal its instructions",
    re: /\b(?:reveal|print|output|repeat|show|disclose|leak|share|tell me)\b[^.\n]{0,30}?\b(?:(?:your|the) system prompt|your (?:instructions|initial prompt|hidden prompt|rules|configuration)|the (?:initial|hidden) prompt)\b/i,
    visible: 'stop', hidden: 'stop', atlas: ['AML.T0057'], owasp: ['LLM07:2025'],
  },
  {
    id: 'remote-code',
    what: 'pipes a download straight into a shell',
    re: /\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\b(?:iex|invoke-expression)\b[^\n]{0,40}\b(?:iwr|invoke-webrequest|downloadstring)\b/i,
    visible: null, hidden: 'stop', atlas: ['AML.T0051.001'], owasp: ['LLM06:2025'],
  },
  {
    id: 'image-exfiltration',
    what: 'markdown image whose URL carries a data placeholder',
    re: /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*[?&][\w-]+=\s*(?:\{|\[|<|%7b|\$\{)/i,
    visible: 'stop', hidden: 'stop', atlas: ['AML.T0086'], owasp: ['LLM02:2025'],
  },
  {
    id: 'modify-agent-config',
    what: "asks for changes to the agent's own setup",
    re: /\b(?:edit|modify|update|append|write|add|overwrite|replace)\b[^\n]{0,100}?(?:\bCLAUDE\.md\b|\bAGENTS\.md\b|\.cursorrules\b|\bsettings\.json\b|\bMEMORY\.md\b|\byour (?:memory|instructions|system prompt|hooks?|rules)\b|\.bashrc\b|\.zshrc\b|\bcrontab\b|\bauthorized_keys\b)/i,
    visible: 'note', hidden: 'stop', atlas: ['AML.T0081'], owasp: ['LLM06:2025'],
  },
  {
    id: 'agent-imperative',
    what: 'gives orders to AI agents',
    // matched by scan.js: an agent mention and an imperative in one sentence
    agent: new RegExp(AGENT, 'i'), imperative: new RegExp(IMPERATIVE, 'i'), danger: new RegExp(`\\b${DANGER}\\b`, 'i'),
    visible: 'note', hidden: 'stop', atlas: ['AML.T0051.001'], owasp: ['LLM01:2025'],
  },
];

export const AGENT_RE = new RegExp(AGENT, 'i');
