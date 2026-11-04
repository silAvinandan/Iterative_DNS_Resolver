# Integration notes (Member A)

## Layout and what was done
```
src/main/java/dns/transport/   Member C's 8 files, byte-identical to what was received
src/main/java/dns/resolver/    Member A: IterativeResolver, Resolution, Main, adapters, stand-in codec
src/main/java/dns/wire/        EMPTY - put Member B's files here (see below)
src/test/java/dns/transport/   C's TransportTests (plain main(), run manually)
src/test/java/dns/resolver/    JUnit 5 tests (resolver, codec, and C's real transport over loopback)
```
Only `Transport.java` (the boundary) changed shape: it now receives the whole candidate list so
C's `ServerSelector` ranks servers and C's retry rounds apply, instead of the resolver looping over
servers itself. `TransportAdapter` connects it to `dns.transport.DnsTransport`:
encodes the query (random transaction ID), passes IP literals as socket addresses, decodes the
reply, and maps results/exceptions.

## Merging Member B's codec (pending)
Needed from B: the **source** of `DnsHeader`, `DnsQuestion`, `DnsResourceRecord`, `DnsNameCodec`,
`DnsRdataCodec` (a file-tree screenshot does not show signatures) and the team `pom.xml`.
The resolver only needs the `MessageCodec` interface:
```java
byte[] encodeQuery(int id, String qname, int qtype);        // iterative query, RD bit clear
DnsWire.Message decode(byte[] packet) throws IOException;   // QR/AA/TC flags, rcode, 3 record sections
```
`DnsWire.Message` / `DnsWire.Record(name, type, ttl, data)` is the resolver's neutral model. RDATA text
format the resolver expects: A dotted quad; AAAA textual; NS/CNAME absolute name with trailing dot;
MX `"<pref> <name>"`; TXT quoted strings; SOA `"mname rname serial refresh retry expire minimum"`.
Plan: write `BWireCodec implements MessageCodec` over B's classes, swap it into `Main`, keep
`DnsWireCodec` only for tests, and add a test decoding B's captured fixtures
(`fixtures/dns-response.hex`) through the resolver's model. B's tree shows no class that assembles a
whole message (header + sections), so that assembly may live in this adapter.

## Experiment settings (read before timing failure cases)
C's retry loop makes a full round over ALL candidate servers per retry and doubles the timeout each
round. Against 13 unreachable root servers with the defaults (2000 ms, 2 retries, backoff) one query
takes about 13 x (2+4+8) = 182 s. For the "authoritative unreachable" and tuning experiments use e.g.
`--timeout-ms 500 --retries 1 --no-backoff` (about 13 s), and report the settings used.

## Observations on Member C's code (suggestions, nothing was changed)
1. **IPv6 without a route** is retried every round (`Network is unreachable` is an `IOException`).
   Suggest skipping retries for `NoRouteToHostException`, `PortUnreachableException` and
   "network is unreachable" messages. The resolver already lists IPv4 first, and the selector penalises
   failures, so the effect is small but visible in query counts.
2. **`TransportException` carries no attempt count.** The adapter estimates `servers x (retries+1)` on
   failure; adding an `attempts` field would make `packets_sent` exact.
3. **Two classes named `DnsHeader`** (C's package-private one and B's `dns.wire.DnsHeader`). No compile clash
   (different packages) but confusing; consider renaming C's to `TransportHeader`.
4. `TransportTests` is a `main()` program, so `mvn test` skips it; wrapping it in JUnit would let CI run it.
5. `TransportException` has no `serialVersionUID` (compiler warning); C's README is empty.
6. Replies are accepted on ID + QR only (the connected UDP socket already filters the source); comparing
   the question section too would be a cheap hardening step.
7. After a TC=1 reply the selector records a success for the UDP exchange even if the TCP retry then fails.

## Open items
- Merge B's codec (above) and D's cache layer; re-run `mvn clean package` and `validation/validate.sh`
  on the merged result.
- Merge this `pom.xml` into the team pom (JUnit 5, surefire, `mainClass dns.resolver.Main`); keep one pom.
