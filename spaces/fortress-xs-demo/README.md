---
title: Fortress-XS
emoji: 🏰
colorFrom: yellow
colorTo: gray
thumbnail: https://huggingface.co/spaces/gantrly/fortress-xs/resolve/main/thumbnail.png
sdk: static
app_file: index.html
pinned: false
license: apache-2.0
models:
  - gantrly/fortress-xs
tags:
  - prompt-injection
  - llm-security
  - guardrails
  - onnxruntime-web
  - in-browser
short_description: Prompt-injection classifier that runs in your browser
---

# Fortress-XS demo

Type a prompt, or paste a document, email or tool output, and see both of
[Fortress-XS](https://huggingface.co/gantrly/fortress-xs)'s scores:
- **attack:** prompt injection or a jailbreak;
- **harmful:** a request for harmful content.

It runs the 81 MB INT8 ONNX model **in your browser**, with onnxruntime-web: your text never
leaves the page. It is the same file [Mobius Guard](https://github.com/gantrly/mobius-guard)
uses, pinned to v1. The model downloads once and is cached.

Thresholds are the model's own, each set so that 1% of ordinary user messages go over it.
Inputs longer than 512 tokens are cut, as in the model.
