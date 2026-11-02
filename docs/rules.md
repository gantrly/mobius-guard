# The request rules

Every user message and tool result is checked against eight named rules before the request
is forwarded. Each rule has a severity: under the default policy (`rules = "block"`) a
**high** rule blocks the request, and a **medium** rule is only recorded in the audit log.

## What the rules see

Attackers hide instructions from detectors by spacing out letters, swapping in look-alike
characters or encoding the text. Each text is therefore checked in up to three *views*:

| View | What it is |
|---|---|
| `original` | The text as sent |
| `normalized` | Invisible characters removed (zero-width, bidi controls, tag characters), compatibility forms and Cyrillic/Greek look-alikes folded to Latin, spaced-out letters joined (`i g n o r e` → `ignore`), leetspeak undone (`1gn0r3` → `ignore`) |
| `base64` | The decoded contents of any base64 run that decodes to text |

The views are for detection only: the request sent to the model is never changed. The audit
log records which view matched.

## The rules

| ID | Severity | Catches |
|---|---|---|
| `override_instructions` | high | Telling the model to ignore, forget, override or bypass its previous, system or original instructions, rules or prompt |
| `chat_template_injection` | high | Chat-template control tokens that fake a new turn or a system message: `<\|im_start\|>`, `<\|system\|>`, `<\|eot_id\|>`, `[INST]`, `<<SYS>>` and similar |
| `markdown_exfiltration` | high | A markdown image whose URL carries data in its query (`![x](https://evil.example/?q=…)`), which a chat UI fetches on render |
| `fake_system_turn` | medium | A line claiming to be a system or developer message (`System: …`, `### developer prompt: …`) |
| `reveal_instructions` | medium | Asking the model to reveal, print or repeat its system prompt, hidden instructions or secret password |
| `jailbreak_persona` | medium | Classic jailbreak personas and modes: DAN, "do anything now", "developer mode enabled", AIM |
| `send_data_out` | medium | Asking to send, forward or upload data to an email address or URL |
| `decode_and_follow` | medium | Asking to decode hidden content and then follow or execute it |

Negated requests are not matched: "do not ignore the previous instructions" or "never
reveal the system prompt" pass.

## How well they work

Measured with the evaluation harness on sets the rules were not written from
([results](results/2026-10-29-proxy.md)):

- **Blocked by the default policy:** none of 23,221 benign texts (ordinary chat, hard
  benign prompts that mention "ignore" or "system prompt", benign emails); 36% of Gandalf
  attacks, 12% of SPML, 9% of LLMail-Inject, 6% of jailbreak prompts, 11–23% of each
  obfuscated attack family.
- **Cost:** under a millisecond for a 512-token prompt on one CPU core, normalisation
  included.

The rules are a cheap, precise first layer, not the detector. Broad recall, especially on
indirect and adaptive attacks, needs a classifier: add one with
[`policy.classifier`](configuration.md#adding-a-classifier).

## Watching before blocking

`rules = "log"` records every hit without blocking anything, which is a safe way to see
what the rules would do on your traffic first. `mobiusguard check "<text>"` shows the
decision for a single text. In v0.1 the rule set is fixed; to switch the rules off, use
`rules = "off"`.
