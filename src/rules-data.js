// Generated from rules/rules.json by scripts/sync-rules.mjs. Edit the JSON, not this file.
export default {
  "version": "0.3.0",
  "_about": "firstwatch detection rules. Shared by the Node and Python packages; edit here only. Patterns use the common subset of JavaScript and Python regex syntax. Levels: visible = when people can see the text (null = only when hidden or addressed to an AI), hidden = when the text is hidden from people.",
  "atlas": {
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0068": "LLM Prompt Obfuscation",
    "AML.T0081": "Modify AI Agent Configuration",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0100": "AI Agent Clickbait"
  },
  "owasp": {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage"
  },
  "agent": {
    "source": "(?:\\b(?:ai|llms?|gpt|claude|gemini|chatgpt|copilot)\\b|\\blanguage models?\\b|\\b(?:assistants?|chatbots?)\\b)|\\bautomated (?:agents?|assistants?|systems?|handling|clients?|tools?|readers?|processing)\\b|\\bagents?\\s+(?:that\\s+|who\\s+)?(?:read|open|process|consum|handl|summari[sz]|pars|sort)\\w*|\\b(?:coding|autonomous|software|browsing) agents?\\b",
    "flags": "i"
  },
  "rules": [
    {
      "id": "override-instructions",
      "what": "tells the agent to ignore or replace its instructions",
      "visible": "stop",
      "hidden": "stop",
      "atlas": [
        "AML.T0051.001"
      ],
      "owasp": [
        "LLM01:2025"
      ],
      "pattern": {
        "source": "\\b(?:ignore|disregard|forget|override|bypass)\\b[^.\\n]{0,40}?\\b(?:previous|prior|above|earlier|all|any|your|system|original|preceding)\\b[^.\\n]{0,20}?\\b(?:instructions?|prompts?|rules|directions|guidelines|directives|context|constraints)\\b",
        "flags": "i"
      }
    },
    {
      "id": "role-hijack",
      "what": "tries to switch the agent into an unrestricted role",
      "visible": "stop",
      "hidden": "stop",
      "atlas": [
        "AML.T0054"
      ],
      "owasp": [
        "LLM01:2025"
      ],
      "pattern": {
        "source": "\\byou are now (?:in )?(?:dan\\b|an? (?:unrestricted|unfiltered|jailbroken)|unrestricted|jailbroken|in developer mode)|\\b(?:enter|enable|activate) (?:dan|god|jailbreak) mode\\b|\\bact as dan\\b",
        "flags": "i"
      }
    },
    {
      "id": "new-instructions",
      "what": "announces new instructions for the reader",
      "visible": "note",
      "hidden": "stop",
      "atlas": [
        "AML.T0051.001"
      ],
      "owasp": [
        "LLM01:2025"
      ],
      "pattern": {
        "source": "\\b(?:new|updated|real|actual|true|secret|hidden|additional) (?:system )?(?:instructions?|directives?|orders|task)\\s*[:\\-]",
        "flags": "i"
      }
    },
    {
      "id": "abandon-task",
      "what": "tells an AI reader to drop the task it was given",
      "visible": null,
      "hidden": "stop",
      "atlas": [
        "AML.T0051.001"
      ],
      "owasp": [
        "LLM01:2025"
      ],
      "pattern": {
        "source": "\\b(?<!n't )(?<!not )(?<!never )(?<!will )(?<!would )(?<!might )(?<!could )(?:ignore|disregard|forget(?: about)?|abandon|stop working on|stop doing|drop|set aside|put aside|quit|scrap|discontinue|leave unfinished|don't bother with|do not bother with|no longer (?:work(?:ing)? on|pursue|continue))\\s+(?:(?:the|this|that|your|their|its|any|whatever)\\s+(?:[\\w'-]+\\s+){0,3}?(?:tasks?|requests?|query|queries|questions?|jobs?|assignments?|objectives?|goals?|work|changes?|instructions?|summar(?:y|ies|ization)|missions?|prompts?)\\b|(?:the|this|that|your)\\s+(?:[\\w'-]+\\s+){0,3}?you(?:'ve| have)?\\s+(?:were|been)\\s+(?:asked|given|told|assigned)\\b|what(?:ever)?\\s+(?:you(?:'re| are| were)?|they|the user)\\s+(?:[\\w'-]+\\s+){0,3}?(?:doing|asked|told|working on|requested|sent)\\b)|\\b(?:tasks?|requests?|query|queries|questions?|jobs?|assignments?|objectives?|goals?|work|changes?|instructions?|summar(?:y|ies|ization)|missions?|prompts?)\\s+(?:\\w+\\s+){0,6}?(?:is|has been|was|are|have been)\\s+(?:now\\s+)?(?:cancell?ed|void|withdrawn|superseded|obsolete|out of scope|no longer (?:needed|relevant|valid|required|in scope))\\b|\\byour (?:new|real|actual|true) (?:task|job|goal|objective|mission|assignment) is (?:now )?to\\b|\\bno longer matters\\b|\\bset it aside\\b|\\bleave it unfinished\\b",
        "flags": "i"
      }
    },
    {
      "id": "required-step",
      "what": "tells an AI reader to do something first before it may answer",
      "visible": null,
      "hidden": "stop",
      "atlas": [
        "AML.T0051.001"
      ],
      "owasp": [
        "LLM01:2025",
        "LLM06:2025"
      ],
      "pattern": {
        "source": "(?:^|[.!?\\n])\\s*(?=(?:[^.!?\\n*]|\\.(?=\\S)){0,300}?(?:\\b(?:before|prior to|until)\\s+(?:you\\s+|it\\s+|they\\s+)?(?:have\\s+)?(?:answer|respond|repl|report|summari[sz]|present|relay|show|finish|complet|continu|proceed)\\w*|\\b(?:before|prior to)\\s+(?:giving|you give|it gives)\\s+(?:[\\w-]+\\s+)?(?:answer|reply|response)|\\b(?:only|may only|can only)\\s+(?:then\\s+)?(?:answer|respond|reply|report)\\w*|\\b(?:answer|respond|reply)\\w*\\s+(?:only\\s+)?(?:until|after)\\b|\\b(?:must|need to|needs to|are required to|is required to|have to|has to)\\s+first\\b|\\b(?:please|you)\\s+first\\b|\\bfirst need to\\b|\\bpre-?answer\\b|\\b(?:is|are)\\s+(?:mandatory|required)\\b|\\b(?:mandatory|required)\\s*:|\\b(?:mandatory|required)\\s+(?:[\\w-]+\\s+)?(?:step|check|action|procedure|verification)\\b))(?=(?:[^.!?\\n*]|\\.(?=\\S)){0,300}?\\b(?:read|open|fetch|retrieve|load|access|visit|call|invoke|run|execute|query|look(?:s|ed|ing)? up|search|download|attach|paste|include|send|upload|use the \\w+ tool)(?:s|es|ed|d|ing)?\\b)(?:[^.!?\\n*]|\\.(?=\\S)){1,300}",
        "flags": "i"
      }
    },
    {
      "id": "conceal-from-user",
      "what": "tells the agent to hide something from its user",
      "visible": "stop",
      "hidden": "stop",
      "atlas": [
        "AML.T0051.001"
      ],
      "owasp": [
        "LLM01:2025"
      ],
      "pattern": {
        "source": "\\b(?:do not|don'?t|never)\\s+(?:tell|inform|mention|reveal|show|alert|notify|let)\\b[^.\\n]{0,30}?\\b(?:the )?(?:user|human|owner|operator|anyone)\\b|\\bwithout (?:telling|informing|alerting|notifying|asking)\\b[^.\\n]{0,20}?\\b(?:the )?(?:user|human|owner|operator)\\b",
        "flags": "i"
      }
    },
    {
      "id": "exfiltrate-secrets",
      "what": "asks for secrets to be sent to an outside address",
      "visible": "stop",
      "hidden": "stop",
      "atlas": [
        "AML.T0086",
        "AML.T0057"
      ],
      "owasp": [
        "LLM02:2025",
        "LLM06:2025"
      ],
      "pattern": {
        "source": "\\b(?:send|e-?mail|post|upload|share|forward|transmit|exfiltrate|leak|paste|include|append|attach|submit)\\b[^\\n]{0,80}?(?:\\.env\\b|api[ _-]?keys?|access[ _-]?tokens?|auth(?:entication)?[ _-]?tokens?|secrets?|passwords?|credentials?|private[ _-]?keys?|ssh[ _-]?keys?|id_rsa|aws_[a-z_]+|session[ _-]?(?:tokens?|cookies?)|cookies|seed[ _-]?phrase|wallet)[^\\n]{0,80}?(?:[\\w.+-]+@[\\w-]+\\.[\\w.]+|https?:\\/\\/\\S+|\\bto (?:this|the following|our|my) (?:address|url|endpoint|webhook|server|email)|\\bin (?:your|the) (?:reply|response|answer|output))|(?:\\.env\\b|api[ _-]?keys?|access[ _-]?tokens?|auth(?:entication)?[ _-]?tokens?|secrets?|passwords?|credentials?|private[ _-]?keys?|ssh[ _-]?keys?|id_rsa|aws_[a-z_]+|session[ _-]?(?:tokens?|cookies?)|cookies|seed[ _-]?phrase|wallet)[^\\n]{0,40}?\\b(?:send|e-?mail|post|upload|share|forward|transmit|exfiltrate|leak|paste|include|append|attach|submit)\\b[^\\n]{0,60}?(?:[\\w.+-]+@[\\w-]+\\.[\\w.]+|https?:\\/\\/\\S+|\\bto (?:this|the following|our|my) (?:address|url|endpoint|webhook|server|email)|\\bin (?:your|the) (?:reply|response|answer|output))",
        "flags": "i"
      }
    },
    {
      "id": "request-secrets",
      "what": "asks for passwords, keys, codes or other secrets to be sent back",
      "visible": "stop",
      "hidden": "stop",
      "atlas": [
        "AML.T0057"
      ],
      "owasp": [
        "LLM02:2025",
        "LLM06:2025"
      ],
      "pattern": {
        "source": "(?:^|[.!?\\n])\\s*(?![^.!?\\n]*?(?:\\b(?:never|not|no one|nobody)\\b|n't\\b))[^.!?\\n]*?(?:\\b(?:reply|respond|write back|answer)\\b[^.!?\\n]{0,60}?\\bwith\\b|\\b(?:send|give|share|tell|provide|forward|e-?mail|text|dm|show)\\s+(?:it\\s+|them\\s+)?(?:to\\s+)?(?:me|us)\\b|\\b(?:send|share|forward|provide|give|upload|paste|post|e-?mail)\\b(?=[^.!?\\n]{0,120}?(?:\\b(?:to|with) (?:me|us|this (?:address|email))\\b|[\\w.+-]+@[\\w-]+\\.[\\w.]+)))[^.!?\\n]{0,60}?\\b(?:passwords?|passcodes?|pass ?phrases?|log ?in (?:details|credentials)|credentials?|api[ _-]?keys?|access[ _-]?tokens?|auth(?:entication)?[ _-]?tokens?|secret keys?|private[ _-]?keys?|ssh[ _-]?keys?|recovery codes?|backup codes?|(?:2fa|mfa|verification|one[ -]time|security) codes?|otps?|pin (?:codes?|numbers?)|seed[ _-]?phrases?|card numbers?|cvv)\\b",
        "flags": "i"
      }
    },
    {
      "id": "request-all-files",
      "what": "asks for the contents of every file, email or document to be sent",
      "visible": "stop",
      "hidden": "stop",
      "atlas": [
        "AML.T0057",
        "AML.T0086"
      ],
      "owasp": [
        "LLM02:2025",
        "LLM06:2025"
      ],
      "pattern": {
        "source": "(?:^|[.!?\\n])\\s*(?![^.!?\\n]*?(?:\\b(?:never|not|no one|nobody)\\b|n't\\b))[^.!?\\n]*?(?:\\b(?:reply|respond|write back|answer)\\b[^.!?\\n]{0,60}?\\bwith\\b|\\b(?:send|give|share|tell|provide|forward|e-?mail|text|dm|show)\\s+(?:it\\s+|them\\s+)?(?:to\\s+)?(?:me|us)\\b|\\b(?:send|share|forward|provide|give|upload|paste|post|e-?mail)\\b(?=[^.!?\\n]{0,120}?(?:\\b(?:to|with) (?:me|us|this (?:address|email))\\b|[\\w.+-]+@[\\w-]+\\.[\\w.]+)))[^.!?\\n]{0,60}?(?:\\b(?:full )?(?:contents?|text|copies|a copy)\\s+(?:of|in)\\s+(?:every|all|each)\\b[^.!?\\n]{0,20}?\\b(?:files?|documents?|docs|emails?|messages?|notes|folders?)\\b|\\beverything in (?:my|your|the user's|their|the) (?:files|documents|docs|folders?|inbox|home folder|drive)\\b)",
        "flags": "i"
      }
    },
    {
      "id": "bulk-delete",
      "what": "asks for everything to be deleted",
      "visible": "stop",
      "hidden": "stop",
      "atlas": [
        "AML.T0051.001"
      ],
      "owasp": [
        "LLM06:2025"
      ],
      "pattern": {
        "source": "(?:^|[.!?\\n])\\s*(?![^.!?\\n]*?(?:\\b(?:never|not|no one|nobody)\\b|n't\\b))[^.!?\\n]*?\\b(?:please|kindly|now|immediately|go ahead and|you (?:must|should|need to|have to))\\s+(?:delete|erase|wipe|purge|remove|empty|destroy)\\b[^.!?\\n]{0,40}?\\b(?:every|all|each|entire|the whole)\\b[^.!?\\n]{0,30}?\\b(?:emails?|messages?|mail|files?|folders?|data|inbox|documents?|records?|repos?|repositories|backups?|branches|databases?|tables?)\\b",
        "flags": "i"
      }
    },
    {
      "id": "reveal-instructions",
      "what": "asks the agent to reveal its instructions",
      "visible": "stop",
      "hidden": "stop",
      "atlas": [
        "AML.T0057"
      ],
      "owasp": [
        "LLM07:2025"
      ],
      "pattern": {
        "source": "\\b(?:reveal|print|output|repeat|show|disclose|leak|share|tell me)\\b[^.\\n]{0,30}?\\b(?:(?:your|the) system prompt|your (?:instructions|initial prompt|hidden prompt|rules|configuration)|the (?:initial|hidden) prompt)\\b",
        "flags": "i"
      }
    },
    {
      "id": "remote-code",
      "what": "pipes a download straight into a shell",
      "visible": null,
      "hidden": "stop",
      "atlas": [
        "AML.T0051.001"
      ],
      "owasp": [
        "LLM06:2025"
      ],
      "pattern": {
        "source": "\\b(?:curl|wget)\\b[^\\n|]{0,200}\\|\\s*(?:sudo\\s+)?(?:ba|z)?sh\\b|\\b(?:iex|invoke-expression)\\b[^\\n]{0,40}\\b(?:iwr|invoke-webrequest|downloadstring)\\b",
        "flags": "i"
      }
    },
    {
      "id": "image-exfiltration",
      "what": "markdown image whose URL carries a data placeholder",
      "visible": "stop",
      "hidden": "stop",
      "atlas": [
        "AML.T0086"
      ],
      "owasp": [
        "LLM02:2025"
      ],
      "pattern": {
        "source": "!\\[[^\\]]*\\]\\(\\s*https?:\\/\\/[^)\\s]*[?&][\\w-]+=\\s*(?:\\{|\\[|<|%7b|\\$\\{)",
        "flags": "i"
      }
    },
    {
      "id": "modify-agent-config",
      "what": "asks for changes to the agent's own setup",
      "visible": "note",
      "hidden": "stop",
      "atlas": [
        "AML.T0081"
      ],
      "owasp": [
        "LLM06:2025"
      ],
      "pattern": {
        "source": "\\b(?:edit|modify|update|append|write|add|overwrite|replace)\\b[^\\n]{0,100}?(?:\\bCLAUDE\\.md\\b|\\bAGENTS\\.md\\b|\\.cursorrules\\b|\\bsettings\\.json\\b|\\bMEMORY\\.md\\b|\\byour (?:memory|instructions|system prompt|hooks?|rules)\\b|\\.bashrc\\b|\\.zshrc\\b|\\bcrontab\\b|\\bauthorized_keys\\b)",
        "flags": "i"
      }
    },
    {
      "id": "agent-imperative",
      "what": "gives orders to AI agents",
      "visible": "note",
      "hidden": "stop",
      "atlas": [
        "AML.T0051.001"
      ],
      "owasp": [
        "LLM01:2025"
      ],
      "agent": {
        "source": "(?:\\b(?:ai|llms?|gpt|claude|gemini|chatgpt|copilot)\\b|\\blanguage models?\\b|\\b(?:assistants?|chatbots?)\\b)",
        "flags": "i"
      },
      "imperative": {
        "source": "(?:\\byou (?:must|should|need to|are required to|will|have to)\\b|\\bdo not\\b|\\bdon'?t\\b|\\bnever\\b|\\balways\\b|\\bimmediately\\b|\\bbefore (?:you )?(?:answer|respond|reply|continue|proceed)\\b|\\bmake sure\\b)",
        "flags": "i"
      },
      "danger": {
        "source": "\\b(?:send|e-?mail|forward|upload|transfer|wire|pay|buy|purchase|delete|wipe|reveal|disclose|grant|authori[sz]e|approve|sign ?up|subscribe|share (?:your|the|all))\\b",
        "flags": "i"
      }
    }
  ],
  "hidden_style": [
    {
      "label": "css:display-none",
      "source": "display\\s*:\\s*none",
      "flags": "i"
    },
    {
      "label": "css:visibility-hidden",
      "source": "visibility\\s*:\\s*hidden",
      "flags": "i"
    },
    {
      "label": "css:tiny-text",
      "source": "font-size\\s*:\\s*(?:0|0?\\.\\d+|1)(?:px|pt|em|rem)?\\s*(?:;|$|!)",
      "flags": "i"
    },
    {
      "label": "css:opacity-0",
      "source": "opacity\\s*:\\s*0(?:\\.0+)?\\s*(?:;|$|!)",
      "flags": "i"
    },
    {
      "label": "css:off-screen",
      "source": "(?:left|top|right|text-indent|margin-left)\\s*:\\s*-\\d{3,}",
      "flags": "i"
    },
    {
      "label": "css:white-or-transparent-text",
      "source": "(?:^|[;\\s])color\\s*:\\s*(?:#fff\\b|#ffffff\\b|white\\b|transparent\\b|rgba\\([^)]*,\\s*0\\s*\\))",
      "flags": "i"
    },
    {
      "label": "css:zero-size",
      "source": "(?:height|width)\\s*:\\s*0(?:px)?\\s*;[^\\\"']*overflow\\s*:\\s*hidden",
      "flags": "i"
    }
  ],
  "discussion": {
    "_about": "A page that mentions these words this many times in visible text discusses attacks: its visible stops become notes. Hidden text still stops.",
    "source": "prompt[ -]?injections?|jailbreak",
    "flags": "gi",
    "min": 3
  },
  "priority": [
    "exfiltrate-secrets",
    "request-secrets",
    "request-all-files",
    "bulk-delete",
    "image-exfiltration",
    "remote-code",
    "modify-agent-config",
    "override-instructions",
    "role-hijack",
    "abandon-task",
    "required-step",
    "reveal-instructions",
    "unicode-tag-smuggling",
    "conceal-from-user",
    "agent-imperative",
    "new-instructions",
    "hidden-agent-text",
    "bidi-control"
  ],
  "builtin": [
    {
      "id": "unicode-tag-smuggling",
      "what": "hides text in invisible Unicode tag characters",
      "level": "stop",
      "atlas": [
        "AML.T0068",
        "AML.T0051.001"
      ],
      "owasp": [
        "LLM01:2025"
      ]
    },
    {
      "id": "bidi-control",
      "what": "contains characters that reorder text on screen",
      "level": "note",
      "atlas": [
        "AML.T0068"
      ],
      "owasp": [
        "LLM01:2025"
      ]
    },
    {
      "id": "hidden-agent-text",
      "what": "hidden text that mentions AI agents",
      "level": "note",
      "atlas": [
        "AML.T0051.001"
      ],
      "owasp": [
        "LLM01:2025"
      ]
    }
  ]
};
