# 0011: How v0.1 is packaged and released

- **Status:** accepted, 2026-11-02
- **Builds on:** [0003](0003-v0.1-scope.md) (scope), [0005](0005-workspace-layout.md) (layout),
  [0010](0010-proxy-v0.1.md) (proxy)

## Decision

**One version for the three packages.** `mobiusguard-redact`, `mobiusguard` and
`mobiusguard-eval` are released together at the same version, starting at 0.1.0. Each
package's version lives in one place, its `__init__.py`, which the build reads. The packages
depend on each other within the same minor version (`>=0.1.0,<0.2`), and a test fails if
the versions or these ranges disagree. One number makes "which redactor does this proxy
use" a non-question, at the cost of releasing a package that did not change.

**Published from a tag, by the CI, with trusted publishing.** Merging a release pull
request (a version with a dated changelog section) makes `tag-release.yml` tag the merge
commit and start `.github/workflows/release.yml` on the tag (added 2026-11-03, so that
tagging is not a manual step); a maintainer can also push a `v*` tag. Release runs: the full checks, a check that the tag matches every
package version, the build, an install of the wheels into a clean environment
(`scripts/check_dist.sh`), then the upload with PyPI trusted publishing. No PyPI token
exists anywhere. (2026-11-04: the upload moved from `uv publish` to
`pypa/gh-action-pypi-publish`, which also publishes PEP 740 attestations to PyPI and is the
publisher OpenSSF Scorecard recognises. The build provenance is also attached to each GitHub
release as a Sigstore bundle and an in-toto envelope, so it can be checked offline.) PyPI accepts one publisher configuration per project, so each package is
published by its own job from its own GitHub environment (`pypi-mobiusguard-redact`,
`pypi-mobiusguard`, `pypi-mobiusguard-eval`); each environment requires a person to
approve, and the three jobs wait together, so one approval releases all three. Steps in
[docs/releasing.md](../releasing.md).

**A container image built from source, not published yet.** The `Dockerfile` builds the
wheels from the checkout, installs the dependencies from `uv.lock` with their hashes on a
digest-pinned `python:3.12-slim`, and runs as an unprivileged user with a health check. The
classifier (PyTorch, several GB) is a build argument, off by default. Publishing an image to
a registry (GHCR) is left until people ask for it: building it is one command, and a
published image is one more artefact to keep patched.

**User documentation in the repository** (`docs/quickstart.md`, `configuration.md`,
`rules.md`, `redaction.md`, `audit-log.md`, `deploy.md`), linked from the READMEs with
absolute URLs so that they work on PyPI too. No documentation site yet: Markdown on GitHub
is enough for the size of v0.1.

**A changelog** (`CHANGELOG.md`), one entry per release, covering all three packages.

**Start-up warnings for key settings that are probably mistakes.** `serve` warns when the
proxy holds an upstream key but no client tokens are set (anyone who can reach it can use
the key), when client tokens are set but an upstream has no held key (the tokens would be
forwarded upstream as API keys), and when a named key variable is not set. Warnings, not
errors: a proxy on a private host may hold a key without tokens on purpose.

## Considered

- **Independent versions per package**: the usual choice for unrelated libraries, but
  these are released from one repository and tested together; separate numbers would only
  add a compatibility table.
- **A stored PyPI API token**: simpler to set up, but a long-lived secret in the repository
  settings that can publish any version.
- **Refusing to start with a held key and no client tokens**: safer, but it would break the
  legitimate case of a proxy that only listens on localhost.
