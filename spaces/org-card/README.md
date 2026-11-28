---
title: README
emoji: 🏰
colorFrom: yellow
colorTo: gray
sdk: static
pinned: false
---

<p align="center">
  <img src="https://huggingface.co/spaces/gantrly/README/resolve/main/assets/gantrly-lockup.png" alt="Gantrly" width="300" class="dark:hidden">
  <img src="https://huggingface.co/spaces/gantrly/README/resolve/main/assets/gantrly-lockup-dark.png" alt="Gantrly" width="300" class="hidden dark:block mx-auto">
</p>

<p align="center"><b>Self-hostable project tracking for teams that build — on sites, not just in code.</b></p>

<p align="center">
  On Hugging Face we publish the models behind
  <a href="https://github.com/gantrly/mobius-guard"><b>Mobius Guard</b></a>, our open-source
  firewall for LLM apps.
</p>

### 🏰 Fortress-XS: prompt-injection and harmful-request detection on a CPU

| Fortress-XS v1 | |
|---|---|
| **Model** | [gantrly/fortress-xs](https://huggingface.co/gantrly/fortress-xs): 81 MB INT8 ONNX, two outputs (attack, harmful), Apache-2.0 |
| **Try it** | [Demo](https://huggingface.co/spaces/gantrly/fortress-xs): the model runs in your browser, so your text never leaves the page |
| **Speed** | 36 ms at 128 tokens, 183 ms at 512 on 4 CPU threads; no GPU, no torch |
| **Held-out results** | 66% of attacks caught on average over 9 test families no compared detector trained on, at 1% false positives, against 44% for PIGuard and 29% for ProtectAI v2 |
| **Use it** | `pip install "mobiusguard[onnx]"`, then `classifier = "fortress-xs"` |

<p align="center">
  <img src="https://huggingface.co/gantrly/fortress-xs/resolve/main/assets/fortress-speed.svg" alt="Fortress-XS: 66% average recall on 9 held-out attack families at 1% false positives, 183 ms on a CPU; PIGuard 44% and ProtectAI v2 29% at 1,151 ms" width="680">
</p>

### 🏯 Fortress-Base: for documents, email and developer traffic

| Fortress-Base v1 | |
|---|---|
| **Model** | [gantrly/fortress-base](https://huggingface.co/gantrly/fortress-base): DeBERTa-v3-base, 308 MB INT8 ONNX, two outputs (attack, harmful), Apache-2.0 |
| **Held-out results** | Against Fortress-XS on the same held-out sets: 68.5% of LLMail-Inject's injections in emails caught (47.4%), 70.5% of BIPIA's injections inside documents (12.9%), 6.0% of real developer messages blocked (10.6%) |
| **Speed** | 104 ms at 128 tokens, 525 ms at 512 on 4 CPU threads: 2.9× Fortress-XS |
| **Roles** | Reads each text with its role, user or tool result; each role has its own threshold |
| **Use it** | Mobius Guard 0.3 or later: `classifier = "fortress-base"` |

### How we publish

- **Held-out numbers only.**
  - Every result is on test sets the model never saw, at a fixed false-positive rate on
    ordinary messages, next to other detectors scored the same way.
  - Weak spots are published with the model.
- **Licensed data only.** Every training source is listed with its licence and attribution.
- **Pinned and reproducible.** Mobius Guard loads each model at a fixed commit, so an update
  never changes what an installed version does. The training and evaluation code is open.
- **Red-teamed.** Mobius Guard is attacked with a million mutated garak prompts, and every
  fix is checked on a sealed holdout and on harmless text
  ([guide](https://github.com/gantrly/mobius-guard/blob/main/docs/red-team.md)).

### Links

[Mobius Guard on GitHub](https://github.com/gantrly/mobius-guard) ·
[PyPI](https://pypi.org/project/mobiusguard/) ·
[Docs](https://github.com/gantrly/mobius-guard/tree/main/docs) ·
[Results](https://github.com/gantrly/mobius-guard/tree/main/docs/results) ·
[Discussions](https://github.com/gantrly/mobius-guard/discussions) ·
[Report a bypass privately](https://github.com/gantrly/mobius-guard/blob/main/SECURITY.md) ·
[Gantrly on GitHub](https://github.com/gantrly)
