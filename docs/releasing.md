# Releasing

For maintainers. The three packages are released together, with one version, from a tag.

## Once: PyPI trusted publishing

1. **A PyPI account** at <https://pypi.org/account/register/> with a verified email and
   two-factor authentication (PyPI requires 2FA to publish).
2. **Three pending publishers**, one per package, at
   <https://pypi.org/manage/account/publishing/> → *Add a new pending publisher* → GitHub.
   PyPI accepts a publisher configuration for one project only, so each package publishes
   from its own GitHub environment:

   | PyPI Project Name | Owner | Repository name | Workflow name | Environment name |
   |---|---|---|---|---|
   | `mobiusguard-redact` | `gantrly` | `mobius-guard` | `release.yml` | `pypi-mobiusguard-redact` |
   | `mobiusguard` | `gantrly` | `mobius-guard` | `release.yml` | `pypi-mobiusguard` |
   | `mobiusguard-eval` | `gantrly` | `mobius-guard` | `release.yml` | `pypi-mobiusguard-eval` |

   A pending publisher reserves nothing: the project is created by the first upload. Upload
   soon after, or someone else can take the name.
3. **The three environments** in the GitHub repository (Settings → Environments → New
   environment), named as in the table: in each, tick *Required reviewers* and add
   yourself, and under *Deployment branches and tags* allow only tags matching `v*`. A
   release then waits for approval; GitHub lists the three environments in one *Review
   deployments* dialog, so they can be approved together. On GitHub's free plan, required
   reviewers work on public repositories only: create the environments after making the
   repository public.

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
5. The Release workflow runs the checks again, checks the tag against every package
   version, builds and tests the wheels in a clean environment, then waits: approve the
   three `pypi-*` deployments in the one *Review deployments* dialog. If an upload fails,
   re-run the failed job: files already on PyPI are skipped.
6. Create the GitHub release from the tag, with the changelog entry.
