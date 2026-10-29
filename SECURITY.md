# Security policy

firstwatch is a security tool, so two kinds of report matter.

## A way past firstwatch, or a bug in it

Examples: a page that stops the hook from scanning, a way to lift the approval gate from content, a crash that turns the hook off, a capture that saves a secret unmasked, code in firstwatch that runs something it shouldn't.

**Report privately:** use GitHub's [private vulnerability reporting](https://github.com/dave8172/firstwatch/security/advisories/new) on this repo. Please don't open a public issue for these.

You'll get a reply within 7 days. Once there's a fix and a release, the advisory is published with credit to you, unless you'd rather stay anonymous.

## An attack that firstwatch didn't flag

A new wording, a new hiding trick, or a payload in another language that gets past the rules. These make the rules better, and they're usually fine to share in public: open a [missed attack](https://github.com/dave8172/firstwatch/issues/new?template=missed-attack.yml) issue.

Before you paste anything:
- Remove real secrets, tokens and personal data. Run the text through `firstwatch capture` or `firstwatch scan` first; capture masks secrets.
- If the attack is live against a real product and its owner doesn't know yet, report it to them first, or use the private route above.

## Supported versions

The latest minor release gets fixes. Until 1.0, that's the only one.
