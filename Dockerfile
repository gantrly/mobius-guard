# syntax=docker/dockerfile:1
# The Mobius Guard proxy (packages/mobiusguard). See docs/deploy.md.
#
#   docker build -t mobiusguard .
#   docker build -t mobiusguard:classifier --build-arg EXTRAS=classifier .   # + PIGuard/ProtectAI
#   docker run -p 8787:8787 mobiusguard
#
# Dependencies come from uv.lock with their hashes; base images are pinned by digest.

ARG PYTHON_IMAGE=python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

FROM ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 AS uv

FROM ${PYTHON_IMAGE} AS build
ARG EXTRAS=""
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /src
COPY . .
RUN uv build --wheel --package mobiusguard-redact --out-dir /out \
 && uv build --wheel --package mobiusguard --out-dir /out \
 && uv export --frozen --package mobiusguard --no-dev --no-emit-workspace \
      ${EXTRAS:+--extra "$EXTRAS"} --output-file /out/requirements.txt

FROM ${PYTHON_IMAGE}
COPY --from=build /out /tmp/wheels
RUN pip install --no-cache-dir --require-hashes -r /tmp/wheels/requirements.txt \
 && pip install --no-cache-dir --no-deps /tmp/wheels/*.whl \
 && rm -rf /tmp/wheels \
 && useradd --system --uid 10001 --home-dir /data --create-home mobiusguard
USER mobiusguard
WORKDIR /data
ENV PYTHONUNBUFFERED=1
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=2)"]
# Settings: mount a TOML file and add `--config /etc/mobiusguard/mobiusguard.toml`, or use the
# MOBIUSGUARD_* environment variables. The audit log is written to /data.
ENTRYPOINT ["mobiusguard", "serve", "--host", "0.0.0.0", "--port", "8787"]
