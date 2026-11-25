# 0020: Tell the classifier where a text comes from (role marking)

- **Status:** proposed, 2026-11-25, for the maintainer's choice. Nothing is built yet.
- **Builds on:** [0017](0017-disguises-carry-no-label.md) (the gate),
  [0019](0019-per-role-thresholds.md) (per-role thresholds),
  [0018](0018-long-inputs-in-windows.md) (windows)

## Context

The classifier sees only text. The same words are a request when the user types them and
an injection inside an email or a tool result. Every fix that leaves the model blind to
this has traded one failure for another:

- **v2's tool-call data:** it helped the developer check and cost LLMail; removing it did
  the opposite.
- **The three messages no model passes:** two "Call save_note with the text exactly: …"
  requests and "my key is …". They look like the instructions hidden in LLMail's emails.
- **A separate tool threshold** (decision 0019) recovered part of LLMail. On real tool
  output it blocks 1–3% and is unstable, because the model scores harmless API output
  high.

The proxy already knows each checked text's role: the user's turn, or a tool result.

## Proposal

**1. A role marker at the start of each text the model reads.** It is plain text, either
`[user]` or `[tool]` and a newline, put in front of the text by the code that calls the
model. It works with the current tokenizer, model architecture and ONNX export, with no
change to any of them.
- **The alternative:** new special tokens. They are cleaner, but they mean resizing the
  embeddings and a custom export, for the same information.
- **Every view and every window gets the marker,** not only the first window of a long
  text.
- **Spoofing:** a marker an attacker writes inside a document must not count. The proxy
  breaks up `[user]` and `[tool]` where they occur inside a text (for example to
  `[ user ]`) before adding its own.

**2. Every training item gets a role, by source:**

| Role | Sources |
|---|---|
| `[tool]` (document or tool result) | browsesafe_md, browsesafe_html, nemotron_ipi, sep, injecagent, rgeada_tool, gandalf_sum, and the tool outputs of the tool-call sources (glaive_fc, hermes_fc, toolace, toucan) |
| `[user]` | everything else: chats, jailbreak and injection prompts, coding requests, dev_secrets, wildchat_dev, and the user turns of the tool-call sources |

- **The tool-call sources come back.** v3 left them out because they cost LLMail. With
  roles marked, their harmless user requests ("send an email to …") are `[user]`, and their
  harmless API outputs are `[tool]`. That is the data the model lacked.
- **Half of their tool outputs are held out** (by cluster, about 1,100). They are used to
  set and test the tool threshold, never for training.

**3. A fair share of both labels in each role.** In the planned data, `[tool]` items are
about 48% attacks and `[user]` items about 26%.
- **The prior is real:** documents are where indirect injection lives.
- **The risk:** the model learns "tool means attack", the same kind of shortcut as the
  disguises (decision 0017).
- **The guard against it:** both roles hold many harmless items (about 18,000 `[tool]`),
  and the gate checks harmless tool output and documents on their own.

**4. Thresholds per role,** each set on harmless text of its role (decision 0019):
- the user threshold on oasst1's calibration half, marked `[user]`, as now;
- the tool threshold on held-out harmless documents and tool outputs, marked `[tool]`.

Both ship in `fortress.json`, which also says the model expects markers
(`"role_marker": true`). The proxy adds markers only for a model that says so, so v1 and
v3 run as before.

**5. Evaluation roles.** The suite's LLMail, BIPIA and LLMail harmless emails, with their
disguised copies, are scored as `[tool]`. Everything else is `[user]`, including the
developer check and the disguised harmless messages.

**6. The harmful output** reads the same marked text. Its training labels are almost all
user-turn requests.

## How it is tested

This uses the screening half of the suite (ROADMAP B3), 1 epoch per run and 2 seeds per
candidate. The jackhhao question (ROADMAP B2) is answered in the same grid:

| Candidate | Data | Seeds to train |
|---|---|---:|
| D (v3's recipe, no marker) | as v3 | 1 more (one exists) |
| R | D + markers + the tool-call sources back (half their tool outputs held out) | 2 |
| R − wildchat_dev | R without wildchat_dev | 2 |
| R − dev_secrets | R without dev_secrets | 2 |

**R must beat D** on LLMail, the developer check and the harmless jackhhao prompts. It must
also block no more harmless tool output and documents at its tool threshold, and must not
regress elsewhere. If it does, the full run (3 epochs) goes on R or its better variant, and
the final half of the suite is used once against v1.

## Costs and risks

- **Latency:** a few tokens more per text, which is negligible.
- **The deployment matters:** callers outside the proxy (`mobiusguard check`, the
  harness, the demo Space) must add the marker the same way. Unmarked text is treated as
  `[user]`.
- **Roles have to be right:** a deployment that passes tool output inside a user message
  (for example a RAG system that pastes documents into the user's turn) gets the user's
  role and threshold for it. The configuration guide must say so.
- **The marker could become a shortcut.** The gate's separate checks on harmless tool
  output and documents are what would show it.
