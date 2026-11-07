# 0013: Releasing the classifier as Fortress-XS, in Mobius Guard 0.2.0

- **Status:** accepted, 2026-11-07
- **Builds on:** [0011](0011-releasing-v0.1.md) (how releases work),
  [0012](0012-classifier-v0.2.md) (the classifier)

## Decision

**The name.** The model is **Fortress-XS**: "Fortress" for what it does, "XS" for its size,
which leaves room for a larger one. Before the maintainer chose it, the shortlist was
checked against Hugging Face models, GitHub projects in LLM security and well-known security
products. Names already used in this space were rejected: Bastion, Sentry, Warden, Aegis,
Vigil, Shield, Guardian, Defender, Gatekeeper.

**Versions.**
- The model has its own version, starting at **v1**, and lives at
  [`gantrly/fortress-xs`](https://huggingface.co/gantrly/fortress-xs).
- The proxy pins it by Hugging Face commit, so a retrained model never changes what an
  installed proxy does.
- The packages go to **0.2.0** together (decision 0011), because the proxy gains the
  classifier and new settings.

**What ships with the model.**
- `model.int8.onnx` is what the proxy runs.
- `model.safetensors` and `config.json` are the full-precision weights, for transformers
  users.
- The tokenizer.
- `fortress.json`: the outputs, the maximum length, the thresholds at 0.1%, 1% and 5% false
  positives on ordinary user messages, and the training data's hash.
- The proxy scores each text on its own. Dynamic INT8 quantizes a batch as a whole, so in
  a batch a text's score moved by up to 0.55 log-odds with its neighbours.
- The model card's numbers are the held-out suite's, scored once (decision 0012). They come
  from the PyTorch model; the INT8 file agrees with it at a correlation of 0.9996 / 0.9991
  (export gate). The suite was not re-scored with the INT8 file.

**Defaults in the proxy.**
- The classifier stays opt-in: `pip install "mobiusguard[onnx]"` and
  `classifier = "fortress-xs"`. A plain install keeps no model dependencies.
- With Fortress, the **attack output blocks** at the model's own threshold
  (`classifier_action = "block"`).
- The **harmful output only logs** (`harmful = "log"`). It flags 48% of OR-Bench's harmless
  prompts that only sound harmful, too many to block by default.
- A threshold in the config wins over the model's own.
- Scores over a threshold that only logs are recorded as `flagged`.
- PIGuard and ProtectAI v2 keep their behaviour: they have no thresholds of their own, so
  they log until one is set.

**Runtime.** onnxruntime and tokenizers, with no torch (the `onnx` extra). The model loads
from Hugging Face at the pinned commit, or from `classifier_dir` for offline installs.
Texts are cut at 512 tokens, as in training.

**Publishing.**
- The model, its card and the charts go to the `gantrly` organisation on Hugging Face.
- A demo Space, `gantrly/fortress-xs`, runs the same INT8 file **in the visitor's
  browser** (onnxruntime-web), so text never leaves their device.
  - It is a static Space because Hugging Face hosts server-side (Gradio) Spaces under an
    organisation only on a paid plan.
  - The browser runtime's scores differ from the server's by at most 0.7 log-odds; the
    verdicts were the same on the examples.
- The packages are released as in decision 0011.
- The card, the charts' script and the Space's code live in this repository
  (`model-cards/`, `scripts/release_charts.py`, `spaces/`), so they are reviewed like code.

**Not in this release.**
- **Scoring long inputs in windows:** it changes the false-positive rate, so it ships only
  after it is measured.
- **Re-scoring the suite with the INT8 file:** the maintainer judged the export gate enough.
- **Comparisons with Prompt Guard 2 and Llama Guard 4:** not run, so the card claims no
  rank against them.

## Considered

- **Classifier on by default:** a plain install would then need onnxruntime and a model
  download, and every existing deployment would change behaviour on upgrade. Rejected for
  0.2.0; the quickstart shows the classifier instead.
- **Block on the harmful output by default:** rejected for the over-blocking above.
- **One version for the model and the packages:** a retrained model would need a package
  release, and the reverse. Separate versions, with the proxy pinning the model's commit,
  keep both honest.
