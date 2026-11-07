# Configuration

Settings are a TOML file passed with `mobiusguard serve --config mobiusguard.toml`. Every
key is optional; the defaults are shown. A few environment variables override the file
for what differs per deployment.

```toml
[upstream.openai]                # serves /v1/chat/completions, /v1/responses, /v1/models
base_url = "https://api.openai.com/v1"
api_key_env = ""                 # name of an env var holding the key; "" = forward the caller's

[upstream.anthropic]             # serves /v1/messages
base_url = "https://api.anthropic.com/v1"
api_key_env = ""

[policy]
rules = "block"                  # block | log | off
classifier = ""                  # "" | "fortress-xs" (needs mobiusguard[onnx])
                                 #    | "piguard" | "protectai-v2" (need mobiusguard[classifier])
classifier_dir = ""              # a local copy of Fortress's files; "" = download the pinned one
classifier_action = "block"      # block | log: what an attack score over the threshold does
classifier_threshold = ""        # attack log-odds; "" = the model's own (Fortress), or for
                                 # PIGuard / ProtectAI v2: log scores, never block on them
harmful = "log"                  # block | log | off: Fortress's harmful-request output
harmful_threshold = ""           # harmful log-odds; "" = the model's own
on_error = "block"               # block | allow: what happens when a detector fails

[redaction]
enabled = true
exclude = []                     # pattern IDs to switch off, e.g. ["email", "phone_international"]

[audit]
path = "mobiusguard-audit.jsonl" # "" = no audit log
include_text = false             # true also writes the checked prompt text

[limits]
max_body_bytes = 4_000_000       # larger requests get HTTP 413
timeout_seconds = 600            # per upstream request
```

| Environment variable | Overrides |
|---|---|
| `MOBIUSGUARD_OPENAI_BASE_URL` | `upstream.openai.base_url` |
| `MOBIUSGUARD_ANTHROPIC_BASE_URL` | `upstream.anthropic.base_url` |
| `MOBIUSGUARD_CLIENT_TOKENS` | Comma-separated tokens callers must present (see below) |

Any OpenAI-compatible server works as the OpenAI upstream (vLLM, Ollama, LiteLLM, Azure
OpenAI's compatible endpoint); any server speaking Anthropic Messages works as the
Anthropic one.

## API keys: forwarded or held

**Forwarded (default).** Each caller sends its own key, as it would to the provider
(`Authorization: Bearer …` or `x-api-key`). The proxy passes it on and never stores or logs
it.

**Held by the proxy.** Put the provider key in an environment variable, name it in
`api_key_env`, and give callers their own tokens instead:

```toml
[upstream.openai]
api_key_env = "OPENAI_API_KEY"

[upstream.anthropic]
api_key_env = "ANTHROPIC_API_KEY"
```

```sh
export OPENAI_API_KEY=… ANTHROPIC_API_KEY=…
export MOBIUSGUARD_CLIENT_TOKENS="team-a-7f3c…,team-b-91d2…"
mobiusguard serve --config mobiusguard.toml
```

Callers then use a client token as their "API key"; anything else gets HTTP 401. Hold the
key for both upstreams when you set client tokens, or a caller's token would be forwarded
to the other one. `serve` prints a warning at start for either mistake, and when a named
variable is not set.

## Policy

- `rules = "block"`: a **high**-severity rule blocks the request with HTTP 403; medium ones
  are logged. `"log"` records every hit and blocks nothing; `"off"` skips the rules.
  [rules.md](rules.md) lists them.
- `on_error = "block"`: if a detector raises an error, the request is refused rather than
  let through unchecked (fail closed). `"allow"` lets it through and logs the error.
- Only **user messages and tool results** are checked. System and developer prompts are
  your own, and checking them would block legitimate prompts such as "never reveal the
  system prompt". Tool results are checked because indirect injection arrives there.

## Adding a classifier

The rules are precise but narrow (they block none of 23,221 benign texts in the
evaluation, and block 0–36% of attacks depending on the set). A classifier catches more.

### Fortress-XS (recommended)

Our own model ([model card](https://huggingface.co/gantrly/fortress-xs)): 81 MB, INT8 ONNX,
about 36 ms at 128 tokens and 183 ms at 512 on 4 CPU threads, with no torch.

```sh
pip install "mobiusguard[onnx]"   # onnxruntime, tokenizers; the model downloads once
```

```toml
[policy]
classifier = "fortress-xs"
```

It has two outputs, each with its own threshold, which ships with the model. The
thresholds are set so that 1% of ordinary user messages go over them.

| Output | What it flags | Default |
|---|---|---|
| attack | Prompt injection or a jailbreak, also inside documents and tool results | **block** (`classifier_action`) |
| harmful | A request for harmful content | **log** (`harmful`) |

The harmful output only logs by default because it also flags about half of the harmless
prompts that only *sound* harmful (48% on OR-Bench hard). Set `harmful = "block"` if your
traffic tolerates that, or `"off"` to leave it out.

A score over a threshold whose action is `log` is recorded in the audit log's `flagged`
list without blocking. Run with `classifier_action = "log"` for a few days to see what the
attack output would block before you let it.

- **Offline installs:** download the model's files once and point `classifier_dir` at
  them. Otherwise the model is fetched from Hugging Face at the commit this version of
  Mobius Guard pins.
- **Long inputs:** Fortress reads the first 512 tokens of each checked text. An injection
  after that is not seen.

### PIGuard and ProtectAI v2

```sh
pip install "mobiusguard[classifier]"    # torch + transformers; the model downloads once
```

```toml
[policy]
classifier = "piguard"          # or "protectai-v2"
```

Each request's highest score goes into the audit log. Scores are log-odds of "attack":
0 is even odds, higher is more likely an attack. On a CPU, a long prompt takes about a
second ([results](results/2026-10-29-proxy.md#cost)); a GPU or a smaller model is the
answer for heavy traffic. PIGuard is MIT-licensed, ProtectAI v2 Apache-2.0; both are pinned
to a model revision and load without running downloaded code.

### Choosing the threshold

Fortress's own thresholds are a starting point: they come from ordinary chat messages
(oasst1), not from your traffic. PIGuard and ProtectAI v2 have none.

Do not take a threshold from someone else's traffic: what counts as ordinary differs by
application, and the false-positive rate is what you live with. Instead:

1. Run with the classifier and **no threshold** for a while (a few days of ordinary use).
   Nothing is blocked by the classifier; every score is logged.
2. Pick the false-positive rate you accept, say 1% of ordinary requests, and take that
   quantile of the logged scores:

   ```python
   import json, statistics

   scores = [
       r["score"]
       for r in map(json.loads, open("mobiusguard-audit.jsonl"))
       if r.get("score") is not None and r["decision"] == "allow"
   ]
   print(statistics.quantiles(scores, n=100)[98])  # blocks about 1% of these requests
   ```

3. Set it and keep watching the audit log:

   ```toml
   classifier_threshold = 4.2
   ```

If attacks are already in the logged traffic, they raise the quantile slightly; that errs
toward fewer false blocks. The evaluation uses the same method with ordinary chat messages
(oasst1) and reports recall at 1% false positives per attack family, which is what to
expect at a similar threshold ([results](results/2026-10-27-baselines.md)).

## Redaction

On by default, for every reply, streamed or not, including tool-call arguments. `exclude`
switches patterns off by ID (the ID is the label in `[REDACTED:<id>]`). See
[redaction.md](redaction.md) for the patterns and their limits.

## Audit log and telemetry

One JSON line per request, described in [audit-log.md](audit-log.md). With
`pip install "mobiusguard[otel]"` and an OpenTelemetry SDK configured by the host, each
request also becomes a span (GenAI semantic conventions).
