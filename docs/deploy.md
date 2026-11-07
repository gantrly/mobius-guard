# Running it as a service

## Container

The repository's `Dockerfile` builds the proxy from source. Dependencies come from
`uv.lock` with their hashes, base images are pinned by digest, and it runs as an
unprivileged user.

```sh
docker build -t mobiusguard .
docker run -d --name mobiusguard -p 127.0.0.1:8787:8787 mobiusguard
curl -s http://127.0.0.1:8787/healthz        # {"status":"ok"}
```

With settings ([configuration.md](configuration.md)) and the audit log on a volume:

```sh
docker run -d --name mobiusguard -p 127.0.0.1:8787:8787 \
  -v "$PWD/mobiusguard.toml:/etc/mobiusguard/mobiusguard.toml:ro" \
  -v mobiusguard-audit:/data \
  mobiusguard --config /etc/mobiusguard/mobiusguard.toml
```

Arguments after the image name go to `mobiusguard serve`. The working directory is
`/data`, so the default audit log is `/data/mobiusguard-audit.jsonl`. The container has a
health check on `/healthz`.

To include Fortress-XS, our classifier (adds onnxruntime and tokenizers, about 60 MB, plus
the 81 MB model):

```sh
docker build -t mobiusguard:fortress --build-arg EXTRAS=onnx .
```

For PIGuard or ProtectAI v2 instead (adds PyTorch, a few GB), use `--build-arg
EXTRAS=classifier`.

Set `policy.classifier` in the settings. The model downloads on first use, so mount a
volume on `/data/.cache/huggingface` to keep it between restarts. Without network access,
copy the model's files in and set `policy.classifier_dir`.

## With a local model

`examples/docker-compose.yml` runs the proxy in front of Ollama:

```sh
docker compose -f examples/docker-compose.yml up -d --build
docker compose -f examples/docker-compose.yml exec ollama ollama pull qwen2.5:3b
```

Then point an SDK at `http://127.0.0.1:8787/v1`. For a hosted API, drop the `ollama`
service and set the base URLs.

## Holding the provider keys

To give teams access to a model without handing out the provider key, keep the key in the
proxy and issue client tokens
([configuration.md](configuration.md#api-keys-forwarded-or-held)):

```sh
docker run -d -p 127.0.0.1:8787:8787 \
  -e OPENAI_API_KEY -e ANTHROPIC_API_KEY \
  -e MOBIUSGUARD_CLIENT_TOKENS="team-a-7f3c…,team-b-91d2…" \
  -v "$PWD/mobiusguard.toml:/etc/mobiusguard/mobiusguard.toml:ro" \
  mobiusguard --config /etc/mobiusguard/mobiusguard.toml
```

`serve` prints a warning at start if the key is held but no client tokens are set, which
would let anyone who can reach the proxy use the key.

## In production

- **TLS and exposure.** The proxy speaks plain HTTP. Put it behind your usual reverse
  proxy or load balancer for TLS, or keep it on a private network next to the app. Do not
  expose it to the internet without client tokens.
- **Several instances.** It keeps no state between requests (the audit log aside), so run
  as many as you need behind a load balancer; give each its own audit file or ship the
  logs.
- **Timeouts.** Long streamed replies are normal: allow at least `timeout_seconds` (600 by
  default) on whatever sits in front, and turn off response buffering there so the stream
  reaches the client as it arrives.
- **Limits.** Requests over `max_body_bytes` (4 MB) are refused with 413; raise it if you
  send large documents or images inline.
- **Cost.** On one CPU core, the request rules take under a millisecond per prompt, and
  the redactor about 0.15 ms per 4-character chunk of the reply at the median (about 150 ms
  over a 1,000-token reply, spread across the stream). Fortress-XS adds 36 ms at 128
  tokens and 183 ms at 512 on 4 CPU threads. PIGuard or ProtectAI v2 add about a second per
  long prompt.
- **Failure.** If a detector fails, the request is refused (`on_error = "block"`). If the
  upstream cannot be reached, the client gets 502 in the API's error format.

What it does and does not protect against: [threat-model.md](threat-model.md).
