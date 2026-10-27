# 0004: Apache-2.0 licence, DCO sign-off

- **Status:** accepted, 2026-10-27

## Decision

All code is Apache-2.0. Contributors sign off commits under the Developer Certificate of
Origin (`git commit -s`); there is no CLA.

## Why

Apache-2.0 includes a patent grant and is the norm for security and infrastructure tools
(garak, LiteLLM's core, agentgateway), so companies can adopt it. The DCO is lighter than a
CLA and is enough for a single-licence project with no plans for an enterprise edition.

## Considered

- **MIT:** simpler, but no patent grant.
- **AGPL or open core:** protects against hosted reuse, but sharply reduces adoption.
