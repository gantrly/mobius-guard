# Security policy

Mobius Guard is a security tool, so a flaw in it can leave the people who rely on it
exposed. Thank you for taking the time to report one.

## Reporting a vulnerability

**Please don't open a public issue, pull request or discussion.** Report privately through
GitHub's private vulnerability reporting:

**<https://github.com/gantrly/mobius-guard/security/advisories/new>**

(or **Security → Report a vulnerability** on the repository page). Only the maintainers can
see the report. Please include:

- what you found and which component it affects (`mobiusguard-redact`, the `mobiusguard`
  proxy, `mobiusguard-eval`, the container image or the release process);
- the version (`pip show mobiusguard`) or commit;
- the smallest input or configuration that reproduces it, for example a streamed reply and
  the chunk boundaries that let a secret through;
- what an attacker could do with it.

If you cannot use GitHub, open an issue that says only that you have a security report and
asks for a private channel; don't include any detail.

## What happens next

| Step | Target |
|---|---|
| We acknowledge your report | within **3 working days** |
| We confirm whether it is a vulnerability and how severe it is | within **7 days** |
| A fix is released | within **30 days** for critical and high severity, **90 days** for the rest |
| The advisory is published | when the fix is released, or at 90 days if no fix is possible |

We keep you informed throughout, agree the disclosure date with you, and credit you in the
advisory and the release notes unless you prefer not to be named. Advisories are published
through GitHub Security Advisories, which request a CVE where one applies. If a fix takes
longer than the targets above, we tell you why and when to expect it.

## Safe harbour

We will not pursue or support legal action against anyone who, in good faith, researches and
reports a vulnerability under this policy: testing against their own installation, not
accessing or changing other people's data, not degrading anyone's service, and giving us
reasonable time to fix the problem before disclosing it.

## Scope

In scope:

- A way to make the proxy forward a request it decided to block, or skip a layer it is
  configured to run.
- A secret or personal-data pattern that the redactor is documented to catch, but that leaks
  through in a streamed reply (for example because of how the reply is split into chunks),
  or a way to make the redactor hold back or drop text it should pass on.
- Anything that exposes the audit log, configuration, upstream API keys, client tokens or
  other users' traffic.
- Crashes or resource exhaustion that a request or a reply can trigger.
- Weaknesses in how releases are built or published (the CI workflows, PyPI trusted
  publishing, the container image).

Out of scope:

- **A new prompt that the rules or a classifier miss.** No detector catches everything, and
  the documentation says so with measured numbers. Please report these with the *Missed
  attack or false positive* issue template so they can join the evaluation sets. If it is a
  broad technique that defeats detection and you'd rather not publish it, report it
  privately as above.
- Free-form personal data (names, addresses) that the redactor does not claim to cover.
- Vulnerabilities in the LLMs or upstream APIs behind the proxy, or in third-party packages
  (report those upstream; we update promptly).
- Deployments that ignore the documented warnings, such as a proxy that holds provider keys,
  is reachable from the internet and has no client tokens.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes: fixes are released as 0.1.y |
| earlier | no |

Before 1.0, only the latest minor series gets security fixes.

## Verifying a release

Releases are built and published by this repository's CI from a tag, with PyPI trusted
publishing (no stored token) and a person approving each upload. Every wheel and source
archive carries a build provenance attestation:

```sh
gh attestation verify mobiusguard-0.1.1-py3-none-any.whl -R gantrly/mobius-guard
```

From 0.1.1, each GitHub release also has the provenance as files: a Sigstore bundle
(`mobius-guard-v0.1.1.sigstore.json`) and its in-toto envelope (`.intoto.jsonl`). To check
a file offline, add `--bundle mobius-guard-v0.1.1.sigstore.json`. PyPI shows a PEP 740
attestation for each file.

The repository's own safeguards (pinned workflow actions, CodeQL, OpenSSF Scorecard, a
weekly fuzz run, secret scanning with push protection, protected `main` and release tags) are described in
[docs/releasing.md](docs/releasing.md) and [docs/threat-model.md](docs/threat-model.md).
