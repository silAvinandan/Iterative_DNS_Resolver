# Integration and live validation

## Current implementation

The integrated source tree contains:

- `dns.resolver`: iterative resolution, DNS server mode, CLI, and adapters.
- `dns.transport`: UDP retry/timeout, server selection, and TCP fallback.
- `dns.wire`: DNS wire-format codec and typed resource records.
- `dns.cache`: positive and negative TTL-based caching and resolution-loop protection.

The client-facing server is `dns.resolver.DnsServerMain`. It listens on UDP and TCP port 5353 by default, or on the port supplied as its first argument. The server uses the iterative resolver and shared in-memory cache. It supports IN queries for A, AAAA, NS, CNAME, MX, TXT, and SOA.

## Live validation record

- Date: 2026-11-04 (Asia/Calcutta)
- Environment: Windows, JDK 22.0.1, Maven 3.10.0
- Branch and commit tested: `integration-stage-1`, `92334b4`
- Upstream network: direct UDP and TCP DNS connectivity to public root infrastructure was available.
- `dig`: not used; the local server was queried with a DNS wire-format probe over sockets.

### Build and unit tests

Command: `mvn clean test` (Maven local repository redirected to a writable project workspace because the default `.m2` repository lock could not be opened).

Result: **BUILD SUCCESS — 141 tests, 0 failures, 0 errors, 0 skipped.** The existing tests were preserved. `TransportAdapterTest` exercises UDP and a UDP TC=1 response followed by a successful upstream TCP exchange.

### Client-facing server checks

Started with `dns.resolver.DnsServerMain` on port 15354 for the harness run.

| Check | Observed result |
|---|---|
| UDP `example.com A` | NOERROR, two answers |
| TCP `example.com A` | NOERROR, two answers |
| Repeated positive query | Served from positive cache; cache entry count was 1 |
| Unique `*.invalid A` | NXDOMAIN with one SOA authority record on the initial response |
| Repeated negative query | Served from negative cache; negative cache entry count was 1 |
| Cache hit ratio | 0.60 over five queries (two initial misses and three repeated positive/negative hits) |

A cached negative answer contains NXDOMAIN but does not carry the original SOA authority record; the negative cache entry is based on the SOA TTL and minimum from the upstream response.

### Failure diagnosis

The reported live server query failure **did not reproduce** in this checkout. A fresh local server process accepted both UDP and TCP client queries, returned valid response IDs and DNS response flags, and completed iterative lookups over live upstream DNS. Consequently, this run establishes no project code root cause to fix; no speculative source change was made. The server defaults to port 5353, so clients that assume port 53 must be given the configured port (for example, `dig @127.0.0.1 -p 5353 example.com`). If the failure persists in the target setup, its exact client command and observed error will be needed to distinguish a port/configuration issue from a different environment-specific failure.

## Cross-check against `dig +trace`

`validation/validate.sh` compares delegation chains and A/AAAA answers against `dig +trace`. It requires `dig` and a network that permits iterative DNS requests. Failure cases can take a long time with the default retry/backoff policy; use the documented tuning options when measuring unreachable-server behavior.
