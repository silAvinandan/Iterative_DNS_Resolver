# Iterative DNS Resolver

An iterative DNS resolver that walks root, TLD, and authoritative servers directly. The project also includes a client-facing DNS server with UDP and TCP listeners and positive and negative response caching.

## Build and tests

Requires JDK 17+ and Maven 3.8+.

```bash
mvn clean test
mvn package
```

The test suite includes wire-format and resolver tests, a local UDP/TCP transport adapter test, a UDP truncation test that verifies upstream TCP fallback, and cache tests.

## Run the iterative resolver

```bash
java -jar target/dns-resolver-1.0.0.jar example.com A
java -jar target/dns-resolver-1.0.0.jar gmail.com MX --stats
```

Options include `--stats`, `--timeout-ms N` (default 2000), `--retries N` (default 2), and `--no-backoff`.

## Run the local DNS server

```bash
java -cp target/classes dns.resolver.DnsServerMain [port]
```

The default listening port is **5353**. The server accepts DNS queries over both UDP and TCP on the selected port. For example, with `dig`:

```bash
dig @127.0.0.1 -p 5353 example.com A
dig +tcp @127.0.0.1 -p 5353 example.com A
```

Use a port option with DNS clients when the server is not listening on their default port 53. Binding to port 53 may require elevated privileges on some systems. The server supports A, AAAA, NS, CNAME, MX, TXT, and SOA queries in class IN. Positive answers are cached according to their TTL. NXDOMAIN and authoritative NODATA results with SOA records are negatively cached using the smaller of the SOA TTL and SOA minimum.

## Resolver behavior

- Iterative root → TLD → authoritative resolution with closest-delegation selection.
- UDP retries and upstream TCP fallback when a UDP response is truncated.
- Failover when a server times out or returns an unusable response.
- In-bailiwick glue validation and iterative resolution of glue-less name servers.
- CNAME chains, loop/depth protection, positive and negative caching.
- Per-resolution statistics and delegation paths with `--stats`.

The resolver currently does not implement DNSSEC, EDNS, QNAME minimisation, DoT, or DoH. Root hints are embedded in the source. Glue-less name server lookups request A records only.

## Validation

The recorded clean build and local server checks are in [INTEGRATION.md](INTEGRATION.md). A live query failure was not reproducible during that run; the tested server returned valid UDP and TCP responses. See the integration notes for the exact commands and observed cache results.
