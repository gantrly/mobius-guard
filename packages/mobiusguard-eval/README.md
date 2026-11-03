# mobiusguard-eval

The Mobius Guard evaluation harness. Part of [Mobius Guard](https://github.com/gantrly/mobius-guard).
Alpha: the API may still change before 1.0.

It scores prompt-injection detectors as recall at a fixed false-positive rate, with
thresholds set on ordinary traffic and every reported set out of sample, attack families
broken out (including obfuscated copies), datasets pinned and recorded with their licence
and who trained on them, and CPU latency with the hardware stated. It also evaluates the
`mobiusguard-redact` streaming redactor. The design is in
[decision 0009](https://github.com/gantrly/mobius-guard/blob/main/docs/decisions/0009-evaluation-harness-v0.1.md).

```bash
pip install "mobiusguard-eval[sklearn,hf]"

mobiusguard-eval sources                                   # the provenance ledger
mobiusguard-eval build --out runs/suite                    # fetch pinned data, build the suite
mobiusguard-eval score --suite runs/suite --detector piguard --device cuda --out runs/piguard
mobiusguard-eval score --suite runs/suite --detector tfidf --out runs/tfidf
mobiusguard-eval report --suite runs/suite --runs runs/piguard runs/tfidf --out runs/report
mobiusguard-eval latency --detector piguard --threads 4 --out runs/latency-piguard.json
mobiusguard-eval redaction --suite runs/suite --out runs/redaction
```

Or all of it in order: `mobiusguard-eval pipeline --out runs --device cuda`.

Every step saves its work as it goes and skips what is already done for the same inputs, so
running a command again resumes it after a crash or a fix; `--force` redoes a step.

Detectors: `keyword`, `tfidf` (needs `[sklearn]`), `protectai-v2` and `piguard` (need `[hf]`).
