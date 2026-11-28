# Red-team holdout, sealed 2026-11-10

The holdout for the first red-team cycle ([decision 0014](../decisions/0014-red-team-runner.md)),
sealed before any finding was read and committed here before its first use. Patches are
never tuned on these groups; measuring one on them is logged in `opened.jsonl` beside the
holdout.

**How it was chosen.** `mobiusguard-eval redteam seal` at commit `e7a4c07`. Prompts are
grouped by near-duplicate text within their family (MinHash, Jaccard 0.8), and within each
family the first 20% of groups by salted SHA-256 of the group name are held out
(salt `mobius-guard red-team holdout v1`). No result was read to choose them.

- **Seeds file:** garak 0.17.1 export of `latentinjection`, `promptinject`, `encoding` and
  `sysprompt_extraction`, 19,418 prompts, SHA-256
  `7fb83437bed59142b6e18a5910e56181a2802478b1f99e8dbf3cddb8cde8f73a`.
- **Held-out prompt IDs** (sorted, one per line), SHA-256:
  `187f322f9724c37960ae970f19d7dff624b0ba9d37429852e38665606099f309`.

| Family | Groups | Held groups | Prompts | Held prompts |
|---|---:|---:|---:|---:|
| encoding | 5,788 | 1,158 | 8,333 | 1,748 (21.0%) |
| latentinjection | 73 | 15 | 9,160 | 2,408 (26.3%) |
| promptinject | 134 | 27 | 525 | 107 (20.4%) |
| sysprompt_extraction | 28 | 6 | 1,400 | 300 (21.4%) |
| **Total** | 6,023 | 1,206 | 19,418 | 4,563 (23.5%) |

`latentinjection` prompts are a few templates filled with many payloads, so they form few,
large groups (the largest holds 2,400 prompts). Holding out whole groups is the point: a
patch tuned on one template is measured on templates it never saw. The share of prompts
therefore differs from 20% where group sizes are uneven; the held `latentinjection` groups
range from 1,200 prompts down to 4.

`redteam verify-holdout` recomputes the hash from the seeds file; it matched on 2026-11-10.
