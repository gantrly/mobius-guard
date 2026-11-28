# Changelog

All notable changes, per release. The three packages (`mobiusguard-redact`, `mobiusguard`,
`mobiusguard-eval`) are released together with one version number. Versions follow
[Semantic Versioning](https://semver.org); before 1.0, a minor version may change the API.

## Unreleased

- **Fortress-Base** ([decision 0024](docs/decisions/0024-fortress-base.md)), not yet
  published: a larger, opt-in classifier (DeBERTa-v3-base) next to Fortress-XS, for
  documents, email and developer traffic. The proxy knows `classifier = "fortress-base"`;
  until it is published it loads only from a local directory. Fortress-XS stays the default.
- **Evaluation: distillation** ([decision 0022](docs/decisions/0022-distillation.md)):
  `teacher-scores` writes a teacher's logits for every training item and extra text, and
  `train --teacher-scores --alpha --temperature --extra-train` trains a student on labels
  and the teacher's soft targets.
- **Evaluation: `export --quantize int8-ffn2-float`** keeps each layer's second feed-forward
  MatMul and the activation-by-activation MatMuls in float32. Plain INT8 broke
  DeBERTa-v3-base (correlation 0.92 with PyTorch); this agrees at 0.999. The default,
  `int8`, is unchanged.
- **Evaluation: `model-meta`** writes a released model's `fortress.json` from its score
  runs: thresholds per role and per view at 0.1%, 1% and 5% false positives, with the
  unreliable ones listed.
- **Evaluation: 95% intervals by unit** ([decision 0023](docs/decisions/0023-intervals-by-unit.md)):
  `metrics.json` adds `ci95_units`, a bootstrap over attacks or near-duplicate clusters, and
  the gate uses it. Rows that share an attack no longer count as independent. Sets of
  independent rows are unchanged.
- **Evaluation: larger held-out sets** ([decision 0021](docs/decisions/0021-capacity-and-measurement.md)):
  `llmail_full` (all of LLMail phase 2), `bipia_embedded` (BIPIA's test attacks inside its
  documents) and `wildchat_dev_test` (real developer messages), and `train --base
  deberta-v3-base --micro-batch N` for a larger teacher on a 24 GB GPU.
- **Red-teaming** (`mobiusguard-eval redteam`, [guide](docs/red-team.md),
  [decision 0014](docs/decisions/0014-red-team-runner.md)): attack a configuration with
  garak's prompt-injection probes in 26 mutated forms, each as a user message and as a
  tool result; resumable runs with one row per attempt and no attack text; findings
  grouped by near-duplicate cluster and mutation; a sealed holdout; and a gate that
  refuses a patch which blocks more harmless text. `run`, `summary`, `findings`, `seal`,
  `verify-holdout`, `gate`.
- **Adaptive attacks** (`mobiusguard-eval redteam adapt`, [decision 0016](docs/decisions/0016-adaptive-attacks.md)):
  PyRIT's PAIR rewrites each prompt up to 10 times, guided by the guard's verdict and
  score, against one or more configs; a second model judges whether a rewrite that got
  through still asks for the same thing. Prompts from the sealed holdout are refused; runs
  resume; reports carry counts only (`adapt-summary`).
- **Fortress-XS scores every view of a text** ([decision 0015](docs/decisions/0015-classifier-sees-every-view.md)):
  the normalised text and decoded base64 as well as the original, as the rules already did,
  so look-alike letters, invisible characters and spaced-out letters hide less from it. Its
  attack threshold for this is 3.1107, set on the same ordinary messages as its own 2.7634,
  so it blocks no more of them. A text with a second view costs one more classifier call.
  On the red team's sealed holdout, 20.6% of attempts got through instead of 25.4%, but
  leetspeak alone and injections inside documents got through more often
  ([results](docs/results/2026-11-10-classifier-views.md#on-the-holdout)).
  `policy.classifier_views = "original"` keeps the old behaviour.
- **Input normalisation catches three more disguises** (found by the first red-team run):
  invisible characters hidden between spaced-out letters, base64 whose text hides
  invisible characters, and base64 runs spaced out, given look-alike letters or invisible
  characters after encoding. Rules now see the hidden text; harmless text is unchanged.
- `mobiusguard-eval[pyrit]`: PyRIT's prompt converters as extra mutations, limited to
  ones that turn text into text and call no model or service.
- `examples/ollama-fortress.toml`: the local-model example with Fortress-XS on.
- `scripts/live_check.py` can send held-out emails (`LIVE_ITEMS`) and time the proxy
  (`LIVE_OVERHEAD`). [Results with Fortress-XS](docs/results/2026-11-07-live-check-fortress.md):
  the proxy adds about 9 ms, and Fortress-XS blocks some harmless developer-style messages
  (keys, databases, tokens, tool calls), now listed in its model card's limits.
- **Fortress-XS v1 blocks most harmless text written in a disguise.** Measured 2026-11-24
  on 1,000 harmless messages: 94% are blocked once spaced out letter by letter, 79% in
  leetspeak and 17% with invisible characters. It caught spaced-out attacks by blocking
  everything spaced, not by reading them
  ([results](docs/results/2026-11-24-fortress-v2-diagnosis.md)). A retrained model that
  fixes this is being tested ([decision 0017](docs/decisions/0017-disguises-carry-no-label.md)).
- Harness, for training and gating Fortress models
  ([decision 0017](docs/decisions/0017-disguises-carry-no-label.md)):
  - `augment`: disguised training copies of attack and harmless items at the same rate,
    and group weights;
  - `extend-suite`: harmless disguised test sets and the developer messages added to a copy
    of the suite;
  - `gate`: pass or fail of a candidate model against a baseline;
  - `local-views:DIR`: scores a trained model on every view of a text, as the proxy does.
  - Training reads a per-item loss weight.
- `policy.classifier_long = "windows"` (off by default,
  [decision 0018](docs/decisions/0018-long-inputs-in-windows.md)): a text over 512 tokens
  is scored in overlapping windows, and the highest score counts, so an injection near the
  end of a long document is seen. Each extra window costs one more classifier call. It stays
  off until its effect on false positives is measured.
- `policy.classifier_threshold_tool`: an attack threshold for tool results. The same words
  are a request when the user writes them and an injection inside a document, so a
  document can be judged against a threshold set on harmless documents. Unset, tool results
  use the same threshold as before.
- `scripts/dev_check.py`: scores the eight developer messages of the 2026-11-07 live check
  with any Fortress model or export.

## 0.2.0 (2026-11-07)

- **Fortress-XS, Mobius Guard's own classifier.** An 81 MB INT8 ONNX model
  ([gantrly/fortress-xs](https://huggingface.co/gantrly/fortress-xs), Apache-2.0) with two
  outputs: attack (prompt injection and jailbreaks, also inside documents and tool results)
  and harmful (requests for harmful content). At 1% false positives on ordinary messages it
  catches 66% of attacks on average over 9 held-out families, against PIGuard's 44% and
  ProtectAI v2's 29%. It takes 183 ms at 512 tokens on 4 CPU threads, where they take
  1,151 ms. Weak spots, published with it: plain-language indirect injection (BIPIA 15%)
  and harmless prompts that only sound harmful (the harmful output flags 48% of them).
  [Results](docs/results/2026-11-07-classifier-v0.2-retrain.md).
- **A demo that runs in your browser:**
  [huggingface.co/spaces/gantrly/fortress-xs](https://huggingface.co/spaces/gantrly/fortress-xs).
  It uses the same INT8 file with onnxruntime-web, so text never leaves the page.
- `pip install "mobiusguard[onnx]"` and `classifier = "fortress-xs"`: onnxruntime and
  tokenizers, no torch. The model downloads at a pinned commit, or loads from
  `classifier_dir` for offline installs.
- New policy settings:
  - `classifier_action` (block or log): the attack output blocks at the model's own
    threshold by default;
  - `harmful` (block, log or off): log by default;
  - `harmful_threshold`.
  - A threshold in the config still wins.
  - PIGuard and ProtectAI v2 behave as before: scores are logged until
    `classifier_threshold` is set.
- Each checked text is scored on its own, so a text always gets the same score. The INT8
  model quantizes a batch as a whole, so a text's score could move by up to 0.55 with the
  other texts of the same request.
- The audit log, spans and `mobiusguard check` add the harmful score (`harmful`) and
  `flagged`: the scores over a threshold, including those that only log.
- `mobiusguard-eval` trains and exports the classifier:
  - `train-data` builds the training set from 24 licensed sources, with suite-overlap
    filters, contrast pairs and twins kept in one split;
  - `judge` cleans labels with two LLM judges and per-source rules;
  - `train` fine-tunes with resume points;
  - `export` writes ONNX and INT8 with a parity gate.
  - The suite adds XSTest unsafe and OR-Bench toxic as harmful-request families.
  - `score --limit` takes a random subset, not the first items.
- The README and the proxy's PyPI page linked to a private repository; they now link to
  the Gantrly organisation.

## 0.1.2 (2026-11-05)

- Fix: of two IBANs written in groups of four with only a space between them, the second
  was not redacted; nor was the second of two such American Express numbers (#20). The
  first number's match ran on into the second and was cut back to pass its check, but the
  search then went on from inside the second number. It now goes on from the end of the
  accepted number, in one-shot and streaming redaction alike.
- `mobiusguard` and `mobiusguard-eval` now require `mobiusguard-redact>=0.1.2`, so upgrading
  the proxy brings this fix.
- README: the PyPI badge reads the version from PyPI's JSON and is cached for 10 minutes;
  the standard PyPI badge is cached for 6 hours, so it showed the old version after a release.
- PyPI pages: fuller descriptions for all three packages (what each does, measured numbers,
  links to the docs, changelog, security policy and releases), with sharper summaries,
  keywords and classifiers.

## 0.1.1 (2026-11-04)

- SECURITY.md: response times, coordinated disclosure, safe harbour, scope and supported
  versions. OpenSSF Best Practices badge in the README.
- `serve` names the upstream, not the variable, when a held key's variable is not set.
- The redactor no longer rescans all the held text on every chunk while a possible secret
  is open, such as a private key whose END line hasn't arrived yet. Each pattern resumes
  where its last scan left off. With 6,000–8,000 characters held, a chunk takes 3.5 ms
  instead of 66 ms with all patterns (#17). The output is unchanged.
- The benchmark measures this case: `benchmarks/redact_stream.py --held`.
- `mobiusguard` and `mobiusguard-eval` now require `mobiusguard-redact>=0.1.1`, so upgrading
  the proxy brings this fix.
- Dependencies in the lockfile updated to their latest releases; no known
  vulnerabilities.
- Releases: each GitHub release also carries its build provenance as files, a Sigstore
  bundle and an in-toto envelope, so a download can be checked offline
  (`gh attestation verify <file> --bundle …`). The provenance now covers only the wheels
  and sdists (0.1.0's also listed a stray `.gitignore`). Uploads use
  `pypa/gh-action-pypi-publish`, which adds PEP 740 attestations on PyPI.
- A fuzz target for the redactor (`fuzz/redactor.py`, Atheris), run on pull requests that
  touch the redactor and weekly.

## 0.1.0 (2026-11-03)

The first release.

### mobiusguard-redact

- Streaming redaction: secrets and personal data are rewritten in text that arrives in
  chunks, with the same output however the text is split (property-tested at every split
  point), about one word of delay, and at most 8,192 characters held back.
- 24 curated patterns (API keys and tokens, private keys, connection-string passwords,
  bearer tokens, emails, payment cards with Luhn, IBAN with mod-97, US SSN, Aadhaar with
  Verhoeff, PAN, international phone numbers) and all 221 gitleaks v8.30.1 rules with their
  entropy, allowlist and keyword checks.
- Private keys: the block ends at its END line, so the text after a key flows on at once;
  a key cut off before its END line (a model reaching its token limit) is still redacted.
- gitleaks' curl rules follow a command onto the next line only after a continuation
  character, so the lines after the word "curl" are no longer held back.
- Tolerates the ways models garble what they echo: tokens a few characters longer or
  shorter (Stripe keys too), values wrapped in quotes or markdown, passwords in URLs without a host.
- Keyword prefilter: 177 gitleaks rules run only where one of their keywords is present or
  arriving (same output, checked on every public text in the evaluation).

### mobiusguard

- Proxy for OpenAI Chat Completions, OpenAI Responses and Anthropic Messages, streamed or
  not, in front of any compatible upstream.
- Request check on user messages and tool results: normalisation (invisible characters,
  look-alike letters, spaced-out letters, leetspeak, base64), eight named rules with
  severities, an optional PIGuard or ProtectAI v2 classifier, and a policy that blocks with
  HTTP 403 in each API's own error format. Fails closed.
- Streaming redaction of replies and tool-call arguments, per choice, output item and
  content block.
- Audit log (one JSON line per request, no prompt text by default) and OpenTelemetry spans.
- Forwarded or held API keys, with client tokens; start-up warnings for risky key settings.
- `mobiusguard serve`, `mobiusguard check`, and a container image.

### mobiusguard-eval

- Provenance ledger of 11 pinned public datasets with licences and known training use.
- Suite builder with near-duplicate clusters and five obfuscation families; recall at a
  fixed false-positive rate from thresholds set on ordinary traffic, AUC, Wilson intervals
  and CPU latency.
- Baselines: keyword rules, TF-IDF trained leave-one-source-out, ProtectAI v2, PIGuard.
- Redactor evaluation: firing rates on public text, synthetic and garbled secrets in real
  messages, near misses.
- Every step checkpointed; `mobiusguard-eval pipeline` resumes where it stopped.
