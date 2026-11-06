# Member A handoff

**Owner:** Avinandan Sil
**Scope:** iterative resolution, CNAME chains, glue records, end-to-end validation.

See README.md (behaviour, build, STATS) and INTEGRATION.md (how B and C plug in, open items).

## Status
- Member C's transport is integrated through `TransportAdapter`; C's files are unchanged.
- Member B's codec is NOT merged yet: the resolver still uses the small stand-in `DnsWire`
  behind the `MessageCodec` seam.
- Unit/integration tests (JUnit 5) cover resolver logic, codec edge cases and C's real transport on loopback.
- Live validation so far (own machine, before this integration): example.com, www.github.com, bbc.co.uk,
  gmail.com MX and an NXDOMAIN resolved correctly. NOT yet done: `validation/validate.sh` vs `dig +trace`,
  re-test after the merge, OS-resolver browsing test (needs the caching server mode).
