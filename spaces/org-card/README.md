---
title: README
emoji: 🏰
colorFrom: yellow
colorTo: gray
sdk: static
pinned: false
---

<p align="center">
  <img src="https://huggingface.co/gantrly/fortress-xs/resolve/main/assets/fortress-speed.svg" alt="Fortress-XS: 66% average recall on 9 held-out attack families at 1% false positives, 183 ms on a CPU; PIGuard 44% and ProtectAI v2 29% at 1,151 ms" width="680">
</p>

# Gantrly

Open-source tools for teams that build. On Hugging Face, we publish the models behind
**[Mobius Guard](https://github.com/gantrly/mobius-guard)**, an open-source firewall for LLM
apps.

### 🏰 Fortress-XS: prompt-injection and harmful-request detection on a CPU

| Fortress-XS v1 | |
|---|---|
| **Model** | [gantrly/fortress-xs](https://huggingface.co/gantrly/fortress-xs): 81 MB INT8 ONNX, two outputs (attack, harmful), Apache-2.0 |
| **Try it** | [Demo](https://huggingface.co/spaces/gantrly/fortress-xs): the model runs in your browser, so your text never leaves the page |
| **Speed** | 36 ms at 128 tokens, 183 ms at 512 on 4 CPU threads; no GPU, no torch |
| **Held-out results** | 66% of attacks caught on average over 9 test families no compared detector trained on, at 1% false positives, against 44% for PIGuard and 29% for ProtectAI v2 |
| **Use it** | `pip install "mobiusguard[onnx]"`, then `classifier = "fortress-xs"` |

### How we publish

- **Held-out numbers only.**
  - Every result is on test sets the model never saw, at a fixed false-positive rate on
    ordinary messages, next to other detectors scored the same way.
  - Weak spots are published with the model.
- **Licensed data only.** Every training source is listed with its licence and attribution.
- **Pinned and reproducible.** Mobius Guard loads each model at a fixed commit, so an update
  never changes what an installed version does. The training and evaluation code is open.

### Links

[Mobius Guard on GitHub](https://github.com/gantrly/mobius-guard) ·
[PyPI](https://pypi.org/project/mobiusguard/) ·
[Docs](https://github.com/gantrly/mobius-guard/tree/main/docs) ·
[Results](https://github.com/gantrly/mobius-guard/tree/main/docs/results) ·
[Discussions](https://github.com/gantrly/mobius-guard/discussions) ·
[Report a bypass privately](https://github.com/gantrly/mobius-guard/blob/main/SECURITY.md) ·
[Gantrly on GitHub](https://github.com/gantrly)
