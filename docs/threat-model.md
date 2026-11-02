# Threat model

Written before the code and updated as each part was built; this version matches v0.1
(2026-11-02).

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
  instructions. v0.1 checks tool results sent back to the model (indirect injection through
  tools) as well as user messages; screening documents and web pages before they reach the
  app is planned for v0.3.

## What Mobius Guard does not do

- **It does not make an LLM app safe on its own.** Classifiers can be bypassed: published
  adaptive attacks beat most of them. Use it as one layer, together with least-privilege
  tools, human approval for risky actions, and keeping secrets out of the model's context.
- It does not judge whether answers are true, harmful or on-topic (content moderation).
- It does not protect against a compromised host or a malicious upstream API.

## Trust boundaries

| Boundary | Risk | Mitigation |
|---|---|---|
| Client → proxy | Crafted prompts; oversized or malformed requests; strangers using a proxy that holds the provider key | Normalise before detection; a body size limit (413); JSON parsing with a 400 on anything else; fail closed; client tokens when the proxy holds the key, with a start-up warning if they are missing |
| Proxy → upstream | Forwarding a blocked request; leaking upstream keys | Single decision point before forwarding; only allowlisted headers forwarded; keys only from the caller or an environment variable, never logged |
| Upstream → client (stream) | Secrets split across chunks; secrets the model garbles; very long matches that defeat the holdback | Hold back from the earliest possible match start; property tests that the output is the same at every split; patterns that tolerate garbled echoes; at most 8,192 characters held, then the held text is redacted rather than sent |
| Proxy → audit log | Logs become a second copy of sensitive data | Decisions, rule IDs, counts and a prompt hash by default; text logging is opt-in |
| Rules and model files | Tampered rules or model weights | Rules ship inside the package and change only through reviewed pull requests; classifier weights are pinned to a model commit and loaded without running downloaded code; releases come from a tag with a person approving the upload; v0.2 rule patches require review before applying |

## Known limits (to be measured, not hidden)

- Recall and false-positive rates per attack family and language are published from the
  evaluation harness, including the families we do worst on.
- Redaction catches only the documented pattern set. Free-form personal data (names,
  addresses) needs an NER model and is out of scope for v0.1.
- The rules are precise but narrow (no false blocks on 23,221 benign texts, 0–36% of
  attacks blocked depending on the set). Indirect and adaptive attacks (LLMail-Inject,
  BIPIA) remain hard for every detector measured, ours included
  ([results](results/2026-10-29-proxy.md)).
- A secret the model rewrites beyond recognition (spelled out, translated, split by spaces)
  is not redacted.
