# AI tool use disclosure

Required by the assignment; disclosure carries no penalty. Add one row per use, in your own
words, including what you reviewed, changed or rejected. Be specific and truthful: you can be
asked about any of this code at the viva.

## Member A — Avinandan Sil

**Tool:** Claude (Anthropic), via the claude.ai web app, in a Project named "DNS Resolver".

| Date | What the tool was used for | What I did with the output |
|---|---|---|
| [date] | Generated the first standalone version of my component (iterative resolver, small wire codec, socket transport, CLI, pom, README) from the proposal and my task checklist | [e.g. read through it, compiled it, ...] |
| [date] | Reviewed that code and listed defects (failover on bad rcodes, glue bailiwick, redundant CNAME queries, string-only results, shared state) | [e.g. agreed/disagreed with ...] |
| [date] | Patched the resolver for those defects | [what I reviewed / changed] |
| [date] | Restructured into separate classes, rewrote the codec readably with stricter validation, added per-resolution statistics, JUnit tests and `validation/validate.sh`, drafted this file and `validation/VALIDATION.md` | [what I reviewed / changed] |
| [date] | Integrated Member C's transport (reviewed their source, wrote `TransportAdapter`, changed the `Transport` boundary to take a candidate list, moved code to the `dns.*` packages) and drafted INTEGRATION.md | [what I reviewed / changed] |

Notes to keep accurate:
- The tool did not have network access, so it could not run live DNS queries; all live results in
  `validation/VALIDATION.md` must come from my own runs.
- Anything in my report or viva answers that I cannot explain myself should be removed or rewritten.

## Other members
(Each member adds their own section.)
