# Security

Mobius Guard is a security tool, so flaws in it can leave people exposed.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub: go to
**Security → Report a vulnerability** on this repository. Include what you found, how to
reproduce it, and what an attacker could do with it.

We aim to acknowledge reports within **3 working days**, keep you posted while we work on a
fix, and credit you in the release notes if you'd like.

## What counts as a vulnerability

- A way to make the proxy forward a request it decided to block, or skip a layer it is
  configured to run.
- A secret or PII pattern that the redactor is documented to catch, but that leaks through
  in a streamed reply (for example, because of how the reply is split into chunks).
- Anything that exposes the audit log, configuration, upstream API keys or other users'
  traffic.
- Crashes or resource exhaustion that a request can trigger.

## What doesn't

- **A new prompt that the classifier misses.** No classifier catches everything, and we say
  so in the documentation. Please report these with the *Missed attack or false positive*
  issue template so they can join the evaluation sets. If it is a broad technique that
  defeats the classifier and you'd rather not publish it, report it privately as above.
- Issues in the LLMs or upstream APIs behind the proxy.

## Supported versions

Mobius Guard is pre-release. Fixes go into the latest version only.
