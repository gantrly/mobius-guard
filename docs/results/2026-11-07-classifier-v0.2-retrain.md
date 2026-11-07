# Results: the v0.2 classifier retrained on all the data (2026-11-07)

The second full training of the v0.2 classifier ([decision 0012](../decisions/0012-classifier-v0.2.md)):
- the same recipe as the [baseline](2026-11-06-classifier-v0.2-baseline.md);
- trained from the pretrained bases, not from the baseline model;
- trained on the baseline's data plus the 9 indirect-injection and hard-benign sources added on
  2026-11-06 ([training-data.md](../training-data.md), *Added 2026-11-06*).

**Setup:**
- **Training data:** 185,852 train / 20,586 val items (`ids_sha256 3b60d865…`). This is the
  cleaned v0.3 build, 206,438 items, none of them from the suite.
- **Bases:** `microsoft/deberta-v3-xsmall` @ 4b419818 and `jhu-clsp/mmBERT-small` @ abc32620.
  512 tokens, 3 epochs, bf16.
- **Learning rates:** the baseline's sweep picked them, 5e-5 for DeBERTa and 2e-5 for mmBERT.
  This run did not sweep again; it trained 3 seeds per base.
- **Hardware and versions:** NVIDIA L4 (AWS g6.xlarge); torch 2.15.0, transformers 5.22.1,
  onnxruntime 1.31.1; code commit c0b0a81.
- **The run:** 6 trainings plus scoring and export, 7 h 19 min.
  - No restarts.
  - One failure: mmBERT's INT8 export did not pass its accuracy check (below).
- **How it was scored:** as for the baseline. Suite v0.2 was scored **once** per base.
  Thresholds are set on the calibration half of oasst1, and **†** = the detector trained on
  that set.

## Training, selection and export

| | DeBERTa-v3-xsmall | mmBERT-small |
|---|---:|---:|
| Validation selection, 3 seeds (mean ± sd) | **0.958 ± 0.002** | 0.957 ± 0.001 |
| Best seed, attack / harmful recall at 1% FPR (validation) | 99.5 / 92.5 | 99.7 / 91.8 |
| Training speed, peak GPU memory | 121 items/s, 11.2 GB | 157 items/s, 8.3 GB |
| INT8 agreement with PyTorch, attack / harmful (gate ≥ 0.98) | 0.9996 / 0.9991 | 0.988 / **0.961 ✗** |
| INT8 AUC change (gate ≤ 0.01) | ≤ 0.0005 | ≤ 0.003 |
| INT8 ONNX size | **81 MB** | 137 MB |
| CPU latency, batch 1, P50 at 128 / 512 tokens | **36 / 183 ms** | 48 / 240 ms |

Notes on the table:
- The validation set is not the baseline's: it now holds the new sources' held-out items, so
  its scores (0.958) cannot be compared with the baseline's (0.985).
- mmBERT's INT8 model fails the agreement gate on the harmful output. Its AUC barely moves,
  but the gate is set on agreement, so mmBERT has no INT8 release model.
  - Its suite scores below come from the PyTorch model, scored before export.
  - Two standard fixes were not tried: keeping the sensitive layers in fp32, and static
    INT8.

**Selected: DeBERTa-v3-xsmall again.**
- On validation the bases are 0.1 points apart, within noise, so the tie goes to lower CPU
  latency.
- DeBERTa also passes the INT8 gate, and it is 40% smaller.
- The suite was not used to choose. It favours mmBERT on several families; see point 5
  below.

## Attack output: recall at 1% false positives on ordinary messages (%)

| Attack family | n | DeBERTa baseline | **DeBERTa retrain** | mmBERT baseline | mmBERT retrain | PIGuard | ProtectAI v2 | keyword |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Gandalf (ignore instructions) | 999 | 98.7 | **99.3** | 99.3 | 98.8 | 91.7 | 90.9 | 72.7 |
| jackhhao (jailbreaks) | 644 | 81.1 | **86.8** | 84.0 | 89.4 | 94.1 † | 22.2 † | 65.8 |
| deepset | 261 | 22.6 | **37.5** | 28.7 | 44.4 | 73.9 † | 11.1 | 23.4 |
| SPML (system-prompt chatbots) | 12,541 | 29.2 | **34.1** | 32.4 | 38.3 | 21.3 | 91.9 | 28.2 |
| BIPIA (indirect) | 125 | 19.2 | **15.2** | 17.6 | 14.4 | 53.6 | 0.8 | 0.0 |
| LLMail-Inject (indirect, adaptive) | 2,981 | 12.1 | **43.9** | 7.7 | 46.5 | 28.3 | 2.1 | 59.4 |
| obfuscated: base64 | 1,000 | 100.0 | **100.0** | 99.7 | 100.0 | 100.0 | 45.5 | 0.0 |
| obfuscated: spaced letters | 1,000 | 99.5 | **99.5** | 96.7 | 97.7 | 0.8 | 0.0 | 0.0 |
| obfuscated: invisible characters | 1,000 | 38.4 | **59.0** | 84.4 | 95.9 | 0.2 | 11.2 | 5.9 |
| obfuscated: look-alike letters | 1,000 | 26.0 | **52.2** | 55.3 | 82.5 | 4.1 | 16.6 | 8.6 |
| obfuscated: leetspeak | 1,000 | 3.0 | **90.4** | 35.7 | 99.4 | 97.1 | 0.3 | 0.2 |

AUC on the indirect families, baseline → retrain:
- **DeBERTa:** LLMail 0.918 → 0.974; BIPIA 0.696 → 0.725.
- **mmBERT:** LLMail 0.796 → 0.977; BIPIA 0.764 → 0.746.

**False positives at the same threshold (%):**

| Benign set | n | DeBERTa baseline | **DeBERTa retrain** | mmBERT baseline | mmBERT retrain | PIGuard | ProtectAI v2 |
|---|---:|---:|---:|---:|---:|---:|---:|
| oasst1 test half (ordinary messages) | 16,061 | 0.9 | **0.9** | 1.0 | 1.0 | 1.0 | 0.9 |
| NotInject (attack trigger words, benign) | 339 | 8.0 | **6.8** | 11.2 | 8.6 | 8.3 | 4.7 |
| OR-Bench hard (sounds harmful, isn't) | 1,319 | 0.0 | **0.0** | 0.1 | 0.0 | 11.1 | 0.8 |
| XSTest safe prompts | 250 | 0.0 | **0.0** | 0.0 | 0.0 | 0.0 † | 0.0 † |
| LLMail-Inject benign emails | 160 | 0.0 | **0.0** | 0.0 | 0.0 | 0.0 | 0.0 |
| jackhhao benign | 1,323 | 0.8 | **1.3** | 0.4 | 0.5 | 0.7 † | 0.1 † |
| English ordinary messages | 7,668 | 1.6 | **1.3** | 1.7 | 1.3 | 0.6 | 0.1 |

The 0.1% and 5% tables, AUC per family and false positives by language are in the run's
`report.md` (`mobiusguard-eval report` on suite v0.1, with the v0.1 baselines' scores).

## Harmful output (%)

| At 1% false positives on ordinary messages | DeBERTa baseline | **DeBERTa retrain** | mmBERT baseline | mmBERT retrain |
|---|---:|---:|---:|---:|
| Recall: OR-Bench toxic (n = 655) | 89.2 | **90.4** | 84.9 | 87.6 |
| Recall: XSTest unsafe (n = 200) | 82.5 | **84.0** | 81.0 | 81.5 |
| Over-blocking: XSTest safe (n = 250) | 9.2 | **8.0** | 6.8 | 7.6 |
| Over-blocking: OR-Bench hard (n = 1,319) | 54.9 | **48.2** | 54.6 | 50.9 |
| AUC, OR-Bench toxic vs the two harmless sets | 0.818 | **0.861** | 0.761 | 0.785 |
| The **attack** output on the harmful families (recall) | 0.0 | **0.0** | 0.0 | 0.0 |

## What it shows

1. **LLMail-Inject went from 12% to 44%.**
   - It is the indirect family closest to the new data: injections hidden in emails and tool
     output.
   - Its AUC is now 0.97.
   - Of the inputs over 512 tokens, 32% are caught (232 of 733), against 48% (1,077 of 2,248)
     of the shorter ones. The tail of a long input is cut off, so windowed scoring in the
     proxy is the next lever.
2. **BIPIA did not improve (19% → 15%, within its interval of about ±7 points).** All 125
   items fit in 512 tokens, so the cut-off is not the cause.
   - The model catches BIPIA's encoded injections (base64, reversed text, ciphers).
   - It misses the plain-language ones: an out-of-place task inserted into an email, table or
     code snippet, such as an ad, a translation or a summary.
   - The new sources teach injections that try to make the assistant act (send, forward,
     cancel). They teach little about "a harmless-sounding instruction that does not belong
     in this document". That needs training data of that kind, not more of the same.
3. **Obfuscation is much better.** Leetspeak rose from 3% to 90%; look-alike letters and
   invisible characters gained 20–26 points for DeBERTa.
4. **False positives held or fell.** NotInject fell from 8.0% to 6.8%, and English ordinary
   messages from 1.6% to 1.3%. The attack output still never fires on plain harmful requests.
5. **mmBERT now leads on obfuscation and on several families.** It beats DeBERTa on deepset,
   SPML, LLMail and every obfuscation except spaced letters. It was not chosen because:
   - the rule is validation plus latency, and the suite is not used to choose;
   - its INT8 model fails the gate.

   If those suite gaps matter for the release, the honest route is a new pre-registered rule
   and fixing mmBERT's INT8 export, not picking it from these tables.
6. **Over-blocking of harmless prompts that sound harmful fell only from 55% to 48%.** The
   hard-benign sources (PHTest, CoCoNot contrast, the CyberSecEval FRR set, Aegis 2.0 safe
   items) moved it 7 points. It is still the classifier's largest weakness.
7. **SPML barely moved (29% → 34%).** ProtectAI v2 still leads at 92%.
