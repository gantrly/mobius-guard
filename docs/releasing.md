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

A release is a pull request; merging it starts the release, and nothing reaches PyPI until
you approve it.

1. On a branch, set the version in the three `__init__.py` files (`__version__`) and, for a
   new minor version, the ranges between the packages in `packages/mobiusguard/pyproject.toml`
   and `packages/mobiusguard-eval/pyproject.toml`; a test fails if they disagree.
2. Give the version a **dated** changelog section: `## 0.2.0 (2026-12-01)`. Until it is
   dated, merging does not release anything.
3. `uv lock`, `make check`, and `uv build --all-packages && scripts/check_dist.sh dist`.
4. Open the pull request (label it, put it on the release's milestone) and merge it.
5. **Tag release** (`.github/workflows/tag-release.yml`) sees a ready version without a tag
   on `main`, creates the tag `vX.Y.Z` on the merge commit and starts **Release** on it.
6. Release runs the checks again, checks the tag against every package version, builds,
   tests the wheels in a clean environment, attests where they were built, then waits:
   approve the three `pypi-*` deployments in the one *Review deployments* dialog. If an
   upload fails, re-run the failed job: files already on PyPI are skipped.
7. The last job creates the GitHub release: the changelog entry, install lines, the
   generated list of merged pull requests (grouped by label, `.github/release.yml`) and the
   wheels and sdists (`gh attestation verify <file> -R gantrly/mobius-guard`). Announce it in
   Discussions → Announcements and close the milestone.

A maintainer can still release by hand by pushing a `v*` tag; only admins and GitHub
Actions may create those tags (the *release tags* ruleset).
