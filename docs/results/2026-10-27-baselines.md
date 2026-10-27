# Results: baselines and the redactor (2026-10-27)

First full run of `mobiusguard-eval` (decision 0009). These are **baselines**: existing
open classifiers and two simple yardsticks. Mobius Guard's own detection (input
normalisation in the proxy, then our classifier in v0.2) will be measured with the same
suite and rules, so this page is the line to beat.

**Setup.** Suite `ids_sha256 6db51432…` (62,064 items from 11 pinned sources, see
[datasets.md](../datasets.md)). Thresholds are set on 16,286 ordinary user messages (the
calibration half of oasst1); every set below is out of sample. Scoring: ProtectAI v2
(`90c9989b`) and PIGuard (`dd78b24e`) on an NVIDIA L4, as log-odds; keyword and TF-IDF
(leave-one-source-out) on CPU. **†** = the detector trained on that set, so its number
there is not a fair comparison. Reproduce with `mobiusguard-eval pipeline --device cuda`.

## Recall on attacks at 1% false positives on ordinary messages (%)

| Attack family | n | keyword | TF-IDF | ProtectAI v2 | PIGuard |
|---|---:|---:|---:|---:|---:|
| BIPIA (planted instructions, without their document) | 125 | 0.0 | 0.0 | 0.8 | 53.6 |
| deepset | 261 | 23.4 | 9.6 | 11.1 | 73.9 † |
| Gandalf | 999 | 72.7 | 82.0 | 90.9 | 91.7 |
| jackhhao (jailbreaks) | 644 | 65.8 | 53.9 | 22.2 † | 94.1 † |
| LLMail-Inject (adaptive, 2025) | 2,981 | 59.4 | 17.0 | 2.1 | 28.3 |
| SPML | 12,541 | 28.2 | 26.8 | 91.9 | 21.3 |
| obfuscated: base64 | 1,000 | 0.0 | 0.0 | 45.5 | 100.0 |
| obfuscated: leetspeak | 1,000 | 0.2 | 0.0 | 0.3 | 97.1 |
| obfuscated: look-alike letters | 1,000 | 8.6 | 10.3 | 16.6 | 4.1 |
| obfuscated: spaced letters | 1,000 | 0.0 | 0.0 | 0.0 | 0.8 |
| obfuscated: invisible characters | 1,000 | 5.9 | 14.5 | 11.2 | 0.2 |

## False positives on hard benign text, same threshold (%)

| Benign set | n | keyword | TF-IDF | ProtectAI v2 | PIGuard |
|---|---:|---:|---:|---:|---:|
| oasst1 test half (ordinary messages) | 16,061 | 0.3 | 1.0 | 0.9 | 1.0 |
| NotInject (attack trigger words, benign) | 339 | 2.1 | 3.8 | 4.7 | 8.3 |
| OR-Bench hard (sounds harmful, isn't) | 1,319 | 0.0 | 2.6 | 0.8 | 11.1 |
| XSTest safe prompts | 250 | 0.0 | 0.0 | 0.0 † | 0.0 † |
| LLMail-Inject benign emails | 160 | 0.0 | 77.5 | 0.0 | 0.0 |

The 0.1% and 5% tables, AUC per family and false positives by language are in the run's
`report.md` and `metrics.json`.

## CPU latency, batch 1 (ms, P50)

AMD EPYC 7R13, 4 threads (AWS g6.xlarge), torch 2.14.1, transformers 5.21.0.

| Detector | 64 tokens | 256 tokens | 512 tokens |
|---|---:|---:|---:|
| keyword | 0.03 | 0.10 | 0.21 |
| TF-IDF + LR | 0.74 | 1.25 | 1.86 |
| ProtectAI v2 (DeBERTa-v3-base) | 212 | 480 | 1,151 |
| PIGuard (DeBERTa-v3-base) | 213 | 480 | 1,151 |

## The redactor

- **Synthetic secrets** of all 24 curated types, placed in real messages and streamed in
  random chunks: 4,800 of 4,800 redacted with the expected label; streamed output equal to
  one-shot output in every case. Near misses (bad check digit, too short): 1 of 1,000
  redacted (a short phone number joined to digits in the message around it).
- **Firing on 57,064 public texts:** secret rules fired on 11 texts: 9 placeholder
  passwords (`password = "your_password"`, gitleaks' Terraform rule), `Bearer
  YOUR_API_KEY`, and an image hash read as a Sourcegraph token. Among personal data,
  `email` fired on 2,378 texts and `us_ssn` on 39, mostly inside LLMail attack emails that
  contain made-up personal data; a hex dump passed the Aadhaar check once.
- The run found three redactor bugs, fixed before these numbers (commit e92394d).

## What it shows

1. **Simple obfuscation beats every baseline:** spaced letters, look-alike letters and
   invisible characters. Normalising input before detection is the first thing the proxy
   must do.
2. **Adaptive attacks (LLMail-Inject) beat both pretrained classifiers**; even the keyword
   rules do better there.
3. **Trained-on sets look much better than the rest**, which is why contamination is
   marked and why the comparison has to be out of sample.
4. **TF-IDF learned a format shortcut:** it flags most ordinary business emails because,
   among its training sources, emails in that format were attacks.
5. **Transformer baselines cost about a second per 512 tokens on a CPU**; the v0.2
   classifier targets milliseconds.

## Limits

Inputs over 512 tokens are truncated for the transformer baselines. The obfuscated
base64 family includes a plain instruction to decode it, which a detector can flag without
reading the payload. LLMail items are attack attempts, not only successful attacks. oasst1
contains a few pasted jailbreaks, counted as false positives in calibration. See decision
0009's known limits.
