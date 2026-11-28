# Results: Fortress-Base v1, the release check (2026-11-27 to 28)

[Decision 0024](../decisions/0024-fortress-base.md): teacher T3 (DeBERTa-v3-base, recipe R2,
3 epochs, best epoch 2) released as an opt-in model next to Fortress-XS.

**Setup:**
- **The release gate,** run once on the final halves, against Fortress-XS v1 as shipped
  (decisions 0021 and 0022). Suite v0.3's final half was already scored, since its runs
  cover the whole suite; the Phase 1 final half was scored for this. The screening halves
  chose T3, so their numbers are not used here.
- **Thresholds:** user text on oasst1's calibration half (16,286 messages), tool output on
  the document calibration set (1,682 documents), at 1% false positives. Fortress-XS runs
  as shipped: every view, one threshold. Fortress-Base runs as Mobius Guard runs it: every
  view, role marks, a threshold per role.
- **Intervals:** 95%, by unit ([decision 0023](../decisions/0023-intervals-by-unit.md)).
- **Hardware:** NVIDIA L4 for scoring, commit `e4f23a8`; the CPU numbers are on the same
  box's AMD EPYC 7R13 (4 threads, no VNNI), onnxruntime 1.31.1.

## The release gate: PASS, 45 of 45

| | Fortress-XS v1 | Fortress-Base | Bar |
|---|---:|---:|---|
| LLMail full (Phase 1) caught | 47.4% (42.4–52.4) | **68.5%** (64.8–71.8) | ≥ 42.4% |
| BIPIA inside documents caught | 12.9% (8.0–18.0) | **70.5%** (62.1–78.1) | ≥ 8.0% |
| Real developer messages blocked | 10.6% | **6.0%** | ≤ 10.6% |
| LLMail (v0.3) caught | 41.6% | **67.6%** | ≥ 35.1% |
| BIPIA (v0.3) caught | 16.9% | **42.4%** | ≥ 9.5% |
| deepset caught | 40.0% | **51.1%** | ≥ 31.6% |
| SPML caught | 34.1% | **39.5%** | ≥ 33.0% |
| Harmless spaced / leetspeak blocked | 93.3 / 74.6% | **3.4 / 3.0%** | ≤ 5% |
| Disguised attacks caught, against plain text's 66.6% | 67–100% | 75–78% | ≥ 85% of plain |
| Ordinary chat (oasst1) blocked | 1.0% | 0.9% | ≤ 1.3% |
| Ordinary Russian messages blocked | 2 of 737 | 3 of 737 | ≤ 1.0% |
| Held-out tool outputs blocked | 2.0% | 3.0% | ≤ 4.3% |
| Harmful: OR-Bench hard blocked | 47.0% | 50.6% | ≤ 50.9% |
| Harmful: OR-Bench toxic / XSTest unsafe caught | 90.5 / 82.6% | **93.2 / 88.4%** | ≥ 86.9 / 74.9% |

**What it shows:**
- **The screening halves' gains hold on the final halves:** LLMail and BIPIA inside
  documents, with intervals that do not overlap v1's.
- **Russian passes here** (3 of 737). On the screening half it was 11 of 795, one over, so
  the card's Russian exception is dropped. The one-seed exception stays.
- **Close to a bound:** the harmful output on OR-Bench hard, 50.6% against 50.9%.
- **The harmful output flags disguised harmless text:** 37.3% of spaced-out and 29.0% of
  leetspeak harmless messages (v1: 0.0% and 0.4%). It is logged, not blocked, by default.

## The export

The release export's dynamic INT8 did not agree with PyTorch (correlation 0.92 / 0.89).
Each layer's second feed-forward MatMul takes the GELU output, whose outlier activations
do not survive per-tensor 8-bit rounding. A sweep of 8 variants on the float32 ONNX, 500
validation texts each, 4 CPU threads:

| Variant | Correlation (attack / harmful) | Size | 128 / 512 tokens |
|---|---|---:|---:|
| **INT8, second feed-forward and activation MatMuls float32 (chosen)** | **0.9992 / 0.9984** | **308 MB** | **105 / 524 ms** |
| INT8 on attention and embeddings only | 0.9998 / 0.9997 | 392 MB | 121 / 585 ms |
| float32 | 1.0 / 1.0 | 740 MB | 135 / 632 ms |
| 8-bit weight-only (MatMulNBits), float32 / int8 compute | 1.0 / 1.0 | 530 MB | 204 / 729, 199 / 908 ms |
| INT8 on every weight MatMul, with or without the embedding | 0.93 / 0.90 | 223–518 MB | 86 / 452 ms |
| The release settings, on the pre-processed graph | 0.93 / 0.90 | 223 MB | 86 / 451 ms |

The maintainer chose the smallest and fastest that agrees: `export --quantize
int8-ffn2-float` (commit `2bb8b44`). Its largest difference from PyTorch is about 3 logits
on a few texts, with AUC unchanged; the runtime check below counts the decisions that flip.

## The release files

Exported with the chosen mode at commit `2bb8b44` (`mg-v4base`, 2026-11-28, on the box): the
file is byte-identical to the sweep's (sha256 `52587a12525de5b1…`).

| | |
|---|---|
| `model.int8.onnx` | 308 MB; 60 MatMuls kept float32 |
| Export parity (500 validation texts) | float32 largest difference 1.6e-5; INT8 correlation 0.9992 / 0.9984, AUC 1.000 / 0.995 (PyTorch 1.000 / 0.996) |
| Latency, 4 threads, batch 1, 128 / 512 tokens | **104 / 525 ms**; Fortress-XS on the same CPU: 35 / 183 ms (2.9×) |
| Runtime check: the proxy's loader, role marks, 300 user messages | 298 of 300 flagged as PyTorch (3 flagged by each; one flips each way); median difference 0.20 logits, largest 5.2 |
| Runtime check: 300 documents (tool role) | 300 of 300 flagged as PyTorch; median 0.19, largest 1.9 |
| `fortress.json` at 1% | attack −0.826, attack_tool −2.546, harmful −1.494; every view: attack −0.440, attack_tool −2.277. Not reliable: attack_tool at 0.1% (1,682 documents) |
| Release folder | `model.int8.onnx`, `model.safetensors`, `config.json`, `tokenizer.json`, `tokenizer_config.json`, `fortress.json` (1.0 GB) |

The runtime check's correlation (0.97 / 0.98) is lower than the export's because its texts
are all harmless, so their scores spread less (standard deviation 2.2 logits); the
difference per text is the same size. The card's numbers are the PyTorch model's, as for
Fortress-XS.

**Published 2026-11-28** with the maintainer's OK: [`gantrly/fortress-base`](https://huggingface.co/gantrly/fortress-base),
model files at commit `e33cc8f7d6ed70a4473f2b5eb3b98ee1c6d32826`, which the proxy pins.
