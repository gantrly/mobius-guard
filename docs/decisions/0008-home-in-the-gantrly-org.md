# 0008: Home in the Gantrly organisation

- **Status:** accepted, 2026-10-27

## Decision

Mobius Guard lives at [`gantrly/mobius-guard`](https://github.com/gantrly/mobius-guard), as a
separate security product from the Gantrly project. It started as
`imtiaj-007/adaptive-llm-firewall` and was transferred, so its history, the `prototype`
branch and the `prototype-v0` tag came with it, and the old URL redirects here.

- **Name and packages stay as they are:** Mobius Guard, `mobiusguard`, `mobiusguard-redact`,
  `mobiusguard-eval`. The README says it is a Gantrly project.
- **Licence and contributions stay as decided in 0004:** Apache-2.0 and the DCO. Gantrly's
  CLA covers repositories in the organisation unless they say they use the DCO; this one
  does. The CLA exists so the AGPL Gantrly app can also be licensed commercially. Apache
  already allows any use, including Gantrly's, so a CLA here would only add friction for
  contributors.
- **Gantrly uses it like any other user:** once the proxy exists (Part 3), Gantrly's agents
  point their model base URL at it. No code is shared between the two, and Mobius Guard has no
  dependency on Gantrly.
- **Private until v0.1.** The repository becomes public with the v0.1 release (Part 4), when
  the proxy works and the evaluation numbers are published.

## Why

A security tool is adopted on trust. Living in an organisation, with Gantrly as its first
production user, shows it is maintained and used, not a personal experiment. It also
gives Gantrly a second product under the same name.

## Considered

- **Stay in a personal account:** no reason to, once Gantrly runs on it.
- **A fresh repository in the organisation:** loses the redirect from the old URL, and the
  history would have to be pushed again.
- **Gantrly's CLA for every repository in the organisation:** one rule, but every
  contributor would have to sign before their first pull request, for rights Apache already
  grants.
- **Public now:** earlier feedback, but the first impression would be a pre-alpha with no
  proxy and no numbers.
