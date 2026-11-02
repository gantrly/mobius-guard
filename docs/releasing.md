# Releasing

For maintainers. The three packages are released together, with one version, from a tag.

## Once: PyPI trusted publishing

1. On PyPI, for each of `mobiusguard-redact`, `mobiusguard` and `mobiusguard-eval`, add a
   *pending publisher* (Account → Publishing): owner `gantrly`, repository `mobius-guard`,
   workflow `release.yml`, environment `pypi`. The first upload then creates the project.
2. In the GitHub repository, create the environment `pypi` (Settings → Environments) and
   require a reviewer, so that every release waits for a person to approve it.

No PyPI token is stored anywhere: the workflow proves who it is with GitHub's OIDC token.

## Each release

1. Set the version in the three `__init__.py` files (`__version__`) and, for a new minor
   version, the ranges between the packages in `packages/mobiusguard/pyproject.toml` and
   `packages/mobiusguard-eval/pyproject.toml`. A test fails if they disagree.
2. Move the changelog entry from "not yet released" to the version and date; for the
   first release, also change "Pre-alpha" in the READMEs to "Alpha".
3. `uv lock`, `make check`, then build and try the wheels in a clean environment:
   `uv build --all-packages && scripts/check_dist.sh dist`.
4. Commit, then tag and push the tag: `git tag -s v0.1.0 -m v0.1.0 && git push origin v0.1.0`.
5. Approve the `pypi` environment when the Release workflow asks. It runs the checks
   again, checks the tag against every package version, builds, tests the wheels in a
   clean environment and publishes.
6. Create the GitHub release from the tag, with the changelog entry.
