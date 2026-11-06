# Results: the v0.2 classifier baseline (2026-11-06)

The first full training of our own classifier ([decision 0012](../decisions/0012-classifier-v0.2.md)):
- one model with two outputs, **attack** and **harmful**;
- trained on the cleaned public data only, with no indirect-injection or synthetic data;
- this is the **baseline**: the indirect-injection data is added next, whatever these
  numbers say (decision 0012, *Order of training*).

**Setup:**
- **Training data:** 141,497 train / 15,616 val items (`ids_sha256 25a6cdaf…`), from 15
  sources, none from the suite ([training-data.md](../training-data.md)).
- **Bases:** `microsoft/deberta-v3-xsmall` @ 4b419818 and `jhu-clsp/mmBERT-small` @ abc32620.
  512 tokens, 3 epochs, bf16.
- **Learning-rate sweep** {2e-5, 5e-5} with seed 0, then seeds 1 and 2 at each base's best
  rate.
- **Hardware and versions:** NVIDIA L4 (AWS g6.xlarge); torch 2.15.0, transformers 5.22.1,
  onnxruntime 1.31.1; code commit 562fd07.
- **The run:** 8 trainings, scoring and export in 6 h 24 min, with no failures or restarts.
- **Suite:** v0.2 (`ids_sha256 26c1e8f9…`, 62,919 items) = the v0.1 suite (`6db51432…`)
  plus XSTest's unsafe prompts and OR-Bench's toxic set as harmful-request families.
- **How it was scored:**
  - each base's exported model scored the suite **once**;
  - thresholds are set on 16,286 ordinary user messages (the calibration half of oasst1);
  - every set below is out of sample;
  - **†** = the detector trained on that set.

## Training, selection and export

| | DeBERTa-v3-xsmall | mmBERT-small |
|---|---:|---:|
| Learning rate chosen (validation, seed 0: 5e-5 / 2e-5) | 5e-5 (0.9855 / 0.9816) | 2e-5 (0.9801 / 0.9802) |
| Validation selection, 3 seeds (mean ± sd) | **0.985 ± 0.001** | 0.981 ± 0.001 |
| Training speed, peak GPU memory | 145 items/s, 11.2 GB | 179 items/s, 8.3 GB |
| INT8 agreement with PyTorch, attack / harmful (gate ≥ 0.98) | 0.9997 / 0.999 | 0.994 / 0.988 |
| INT8 AUC change (gate ≤ 0.01) | ≤ 0.0002 | ≤ 0.0004 |
| INT8 ONNX size | **81 MB** | 138 MB |
| CPU latency, batch 1, P50 at 128 / 512 tokens | **37 / 194 ms** | 48 / 238 ms |

Notes on the table:
- The selection score is the mean of the two outputs' recall at 1% false positives, on
  validation.
- Latency is for the INT8 ONNX model on an AMD EPYC 7R13 with 4 threads.

**Selected: DeBERTa-v3-xsmall.** Under decision 0012's rule, the bases' validation scores
are within noise of each other (0.4 points), so the tie goes to lower CPU latency. DeBERTa
is also 40% smaller. The suite was not used to choose.

## Attack output: recall at 1% false positives on ordinary messages (%)

| Attack family | n | DeBERTa (ours) | mmBERT (ours) | PIGuard | ProtectAI v2 | keyword |
|---|---:|---:|---:|---:|---:|---:|
| Gandalf (ignore instructions) | 999 | **98.7** | 99.3 | 91.7 | 90.9 | 72.7 |
| jackhhao (jailbreaks) | 644 | **81.1** | 84.0 | 94.1 † | 22.2 † | 65.8 |
| deepset | 261 | 22.6 | 28.7 | 73.9 † | 11.1 | 23.4 |
| SPML (system-prompt chatbots) | 12,541 | 29.2 | 32.4 | 21.3 | **91.9** | 28.2 |
| BIPIA (indirect) | 125 | 19.2 | 17.6 | **53.6** | 0.8 | 0.0 |
| LLMail-Inject (indirect, adaptive) | 2,981 | 12.1 | 7.7 | 28.3 | 2.1 | **59.4** |
| obfuscated: base64 | 1,000 | 100.0 | 99.7 | 100.0 | 45.5 | 0.0 |
| obfuscated: spaced letters | 1,000 | 99.5 | 96.7 | 0.8 | 0.0 | 0.0 |
| obfuscated: invisible characters | 1,000 | 38.4 | 84.4 | 0.2 | 11.2 | 5.9 |
| obfuscated: look-alike letters | 1,000 | 26.0 | 55.3 | 4.1 | 16.6 | 8.6 |
| obfuscated: leetspeak | 1,000 | 3.0 | 35.7 | 97.1 | 0.3 | 0.2 |

**False positives at the same threshold (%):**

| Benign set | n | DeBERTa | mmBERT | PIGuard | ProtectAI v2 |
|---|---:|---:|---:|---:|---:|
| oasst1 test half (ordinary messages) | 16,061 | 0.9 | 1.0 | 1.0 | 0.9 |
| NotInject (attack trigger words, benign) | 339 | 8.0 | 11.2 | 8.3 | 4.7 |
| OR-Bench hard (sounds harmful, isn't) | 1,319 | 0.0 | 0.1 | 11.1 | 0.8 |
| XSTest safe prompts | 250 | 0.0 | 0.0 | 0.0 † | 0.0 † |
| LLMail-Inject benign emails | 160 | 0.0 | 0.0 | 0.0 | 0.0 |
| English ordinary messages | 7,668 | 1.6 | 1.7 | 0.6 | 0.1 |

The 0.1% and 5% tables, AUC per family and false positives by language are in the run's
`report.md` (`mobiusguard-eval report` on suite v0.1 with the v0.1 baseline scores).

## Harmful output (%)

Thresholds are set on the same ordinary messages. The harmful families are the suite's
XSTest unsafe and OR-Bench toxic prompts. Their harmless counterparts measure over-blocking.

| At 1% false positives on ordinary messages | DeBERTa | mmBERT |
|---|---:|---:|
| Recall: OR-Bench toxic (n = 655) | 89.2 | 84.9 |
| Recall: XSTest unsafe (n = 200) | 82.5 | 81.0 |
| Over-blocking: XSTest safe (n = 250) | 9.2 | 6.8 |
| Over-blocking: OR-Bench hard (n = 1,319) | **54.9** | **54.6** |
| AUC, OR-Bench toxic vs the two harmless sets | 0.818 | 0.761 |
| The **attack** output on the harmful families (recall) | 0.0 | 0.0 |

## What it shows

1. **The two outputs separate the two jobs.** The attack output never fires on a plain
   harmful request, and the harmful output catches 82–89% of them.
2. **Strong on direct injection, jailbreaks and most obfuscations:**
   - It beats both published classifiers on every family neither of them trained on,
     except SPML and the indirect ones.
   - On a CPU it takes 194 ms at 512 tokens, where they take 1,151 ms
     ([v0.1 baselines](2026-10-27-baselines.md)).
   - Gandalf and jackhhao share a style with some training sources (Mosscap is another
     Lakera game, and the in-the-wild jailbreaks come from the same communities). The
     overlap filters removed near copies, but those two numbers may still be flattered.
3. **Weak on indirect injection:** BIPIA 19%, LLMail-Inject 12%. The training data has
   122 indirect examples. This is the next step:
   [research note](../research/2026-11-05-indirect-injection-datasets.md).
4. **The harmful output judges by topic.** It flags 55% of OR-Bench's harmless prompts
   that only sound harmful, because the training data has few such examples. It needs
   hard-benign training data from sources outside the suite.
5. **Two smaller gaps:**
   - SPML, where ProtectAI v2 reaches 92% without having trained on it;
   - leetspeak for DeBERTa (3%), which the proxy's input normalisation should cover. These
     numbers are the classifier alone.
6. **DeBERTa runs at 1.6% false positives on English ordinary messages** at the threshold
   that gives 1% overall, so an English-only deployment would set its own threshold.
