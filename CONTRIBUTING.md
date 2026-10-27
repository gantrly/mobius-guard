# Contributing

Thanks for helping. Bug reports, missed attacks, false positives and code are all welcome.

## Before you start

- **Found a bypass you'd rather not publish?** Report it privately (see
  [SECURITY.md](SECURITY.md)), not in an issue.
- **A large change?** Open an issue first so we can agree on the approach. Changes to how
  the project works (scope, architecture, how we measure) get a decision record in
  [docs/decisions/](docs/decisions/).

## Setup

You need [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/imtiaj-007/adaptive-llm-firewall
cd adaptive-llm-firewall
make install
make check
```

`make check` runs the same lint, type check and tests as CI. It must pass before you open
a pull request.

## Rules for code

- **Typed.** Pyright runs in strict mode.
- **Tested.** Every bug fix comes with a test that fails without the fix. The redactor uses
  property-based tests (Hypothesis). If you add a pattern, the split-at-every-point test must
  cover it.
- **No data or model files in git.** Datasets and models are downloaded by scripts.
  Anything you add to training or evaluation data needs its source and licence recorded.
- **Detection changes need held-out numbers.** If a change affects what gets blocked or
  redacted, report its effect on the eval sets it was *not* tuned on, including the
  false-positive sets. Numbers on the examples you tuned against don't count.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/) instead of
a CLA. By signing off you state that you wrote the change or have the right to submit it
under the project's licence. Add the sign-off with `-s`:

```bash
git commit -s -m "Redact Stripe keys split across chunks"
```

This adds `Signed-off-by: Your Name <you@example.com>` to the message. Pull requests with
unsigned commits can't be merged.

## Pull requests

Keep them focused on one change. Fill in the template: what changed, and how you tested it.
