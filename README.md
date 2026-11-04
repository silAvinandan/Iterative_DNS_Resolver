# Iterative DNS Resolver — team repo (integration branch)

An iterative DNS resolver written from raw sockets up: it starts at the root servers and follows
referrals itself (root → TLD → authoritative) and never forwards to another resolver.

| Package | Owner | Contents |
|---|---|---|
| `dns.resolver` | Member A (Avinandan) | iterative engine, CNAME chains, glue, failover, CLI, stand-in codec, adapters |
| `dns.transport` | Member C | UDP retry/timeout, server ranking, TCP fallback (**files unchanged**) |
| `dns.wire` | Member B | wire-format codec — **not merged yet**, see INTEGRATION.md |
| caching server mode | Member D | not merged yet |

## Build, test, run
Requires JDK 17+ and Maven 3.8+.
```bash
mvn clean package                    # compiles, runs the JUnit tests, builds target/dns-resolver-1.0.0.jar
java -jar target/dns-resolver-1.0.0.jar example.com A
java -jar target/dns-resolver-1.0.0.jar gmail.com MX --stats
```
Options: `--stats` (one machine-readable `STATS` line), `--timeout-ms N` (default 2000),
`--retries N` (default 2), `--no-backoff`. See "Experiment settings" in INTEGRATION.md before timing
failure cases.

Member C's own test program (loopback fake server, not run by `mvn test`):
```bash
java -cp target/classes:target/test-classes dns.transport.TransportTests
```

## Resolver behaviour (Member A)
- Root → TLD → authoritative walk, choosing the closest enclosing delegation.
- **Two-level failover.** The transport (C) handles network failure: ranking, timeouts, retries, TCP.
  The resolver judges the answer and, if a server gave an unusable one — SERVFAIL/REFUSED, lame
  (AA=0, no answer, no referral), NXDOMAIN without AA, a referral that does not descend from the
  current zone, or an undecodable reply — drops that server and asks the rest.
- **Glue:** Additional-section addresses are trusted only if the NS name lies within the zone of the
  server that sent the referral (the root is the parent of everything). Otherwise, or with no glue,
  NS hostnames are resolved iteratively (first one that works). IPv4 candidates are listed before IPv6.
- **CNAME chains** across zones; records already in the response are used, only the unresolved final
  target is queried; loops and over-long chains detected; a CNAME-type query returns the alias itself.
- Loop/depth protection: 32 hops/links, in-progress set for CNAME/NS recursion, visited zone@server set.
- Stateless resolver (per-query context): one instance is safe for concurrent queries.
- Server addresses are passed as IP literals only; the adapter refuses hostnames so no system name
  lookup (`getaddrinfo`) can ever happen.
- Per-resolution statistics (`Resolution.Stats`) and the delegation chain for comparison with `dig +trace`.

### STATS fields
| field | meaning |
|---|---|
| `upstream_queries` | calls to the transport = DNS queries asked (compare with dig's "Received" lines) |
| `packets_sent` | UDP datagrams + TCP connections actually sent (retries, failover, TCP fallback included) |
| `failed_queries` / `timeouts` | transport calls where no server answered / of which due to timeout |
| `unusable` | answers the resolver rejected |
| `udp_sent`, `tcp_sent`, `transport_timeouts` | totals from C's `DnsTransport` counters |
| `chain` | zones walked for the original name, e.g. `.>com.>example.com.` |

## Validation against dig
```bash
validation/validate.sh        # needs dig; use WSL on Windows
```
Compares delegation chains (must match) and A/AAAA answers (may legitimately differ), records query
counts and latency in `validation/results-<timestamp>/summary.md`. Record real observations in
`validation/VALIDATION.md`.

## Known limitations
- Iterative engine only: no DNSSEC, EDNS, QNAME minimisation, DoT/DoH; it does not yet serve clients on port 53.
- The response's question section is not compared with the query (transport checks ID + QR only).
- Glue-less NS lookups ask for A records only.
- Root hints are embedded (IANA set); refresh from the official file for long-term use.
- Observed live: `bbc.co.uk` gives chain `. > uk. > bbc.co.uk.` (the `.uk` servers also serve `co.uk`).
