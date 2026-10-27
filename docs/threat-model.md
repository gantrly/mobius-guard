# Threat model

A first version, written before the code. It is updated as each part is built.

## What we protect

1. **The model's instructions and tools** against prompts that try to override them
   (direct prompt injection and jailbreaks).
2. **Data in replies**: secrets (API keys, tokens, private keys) and personal data that the
   model might output, for example from its context, retrieved documents or tool results.
3. **The firewall itself**: its configuration, rules, upstream API keys and audit log.

## Who we defend against

- **A user of the app** sending crafted prompts, including ones hidden with encodings,
  invisible characters, look-alike letters, other languages or role-play framing.
- **An adaptive attacker** who can query the firewall many times and change the attack based
  on what gets blocked. We assume they will eventually find prompts the classifier misses.
- **Content the model reads** (documents, web pages, tool output) that carries injected
  instructions. *(Screening that content is planned for v0.3; v0.1 covers the user's prompt
  and the reply.)*

## What Mobius Guard does not do

- **It does not make an LLM app safe on its own.** Classifiers can be bypassed: published
  adaptive attacks beat most of them. Use it as one layer, together with least-privilege
  tools, human approval for risky actions, and keeping secrets out of the model's context.
- It does not judge whether answers are true, harmful or on-topic (content moderation).
- It does not protect against a compromised host or a malicious upstream API.

## Trust boundaries

| Boundary | Risk | Mitigation |
|---|---|---|
| Client → proxy | Crafted prompts; oversized or malformed requests | Normalise before detection; size limits; strict request parsing; fail closed |
| Proxy → upstream | Forwarding a blocked request; leaking upstream keys | Single decision point before forwarding; keys only from config/env, never logged |
| Upstream → client (stream) | Secrets split across chunks; very long tokens that defeat the holdback | Holdback sized to the longest pattern; chunk-invariance tests; bounded buffer with a documented limit |
| Proxy → audit log | Logs become a second copy of sensitive data | Hashes and IDs by default; text logging is opt-in |
| Rules and model files | Tampered rule updates or model weights | Hashes checked on load; v0.2 patches require review before applying |

## Known limits (to be measured, not hidden)

- Recall and false-positive rates per attack family and language are published from the
  evaluation harness, including the families we do worst on.
- Redaction catches only the documented pattern set. Free-form personal data (names,
  addresses) needs an NER model and is out of scope for v0.1.
