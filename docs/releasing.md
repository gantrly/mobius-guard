# Releasing

For maintainers. The three packages are released together, with one version, from a tag.

## Once: PyPI trusted publishing

1. **A PyPI account** at <https://pypi.org/account/register/> with a verified email and
   two-factor authentication (PyPI requires 2FA to publish).
2. **Three pending publishers**, one per package, at
   <https://pypi.org/manage/account/publishing/> → *Add a new pending publisher* → GitHub:

   | Field | Value |
   |---|---|
   | PyPI Project Name | `mobiusguard-redact`, then `mobiusguard`, then `mobiusguard-eval` |
   | Owner | `gantrly` |
   | Repository name | `mobius-guard` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

   A pending publisher reserves nothing: the project is created by the first upload. Upload
   soon after, or someone else can take the name.
3. **The `pypi` environment** in the GitHub repository (Settings → Environments → New
   environment, named `pypi`): tick *Required reviewers* and add yourself, and under
   *Deployment branches and tags* allow only tags matching `v*`. Every release then waits
   for a person to approve it.

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
