---
title: Fortress-XS
emoji: 🏰
colorFrom: blue
colorTo: gray
sdk: gradio
sdk_version: 6.30.0
app_file: app.py
pinned: false
license: apache-2.0
models:
  - gantrly/fortress-xs
short_description: Prompt-injection and harmful-request classifier on a CPU
---

# Fortress-XS demo

Type a prompt, or paste a document, email or tool output, and see both of
[Fortress-XS](https://huggingface.co/gantrly/fortress-xs)'s scores:
- **attack:** prompt injection or a jailbreak;
- **harmful:** a request for harmful content.

It runs the 81 MB INT8 ONNX model on this Space's CPU, the same file
[Mobius Guard](https://github.com/gantrly/mobius-guard) uses. Thresholds are the model's own,
set so that 1% of ordinary user messages are flagged.

What you type is not stored. Inputs longer than 512 tokens are cut, as in the model.
