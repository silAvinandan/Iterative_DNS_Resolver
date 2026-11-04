package dns.resolver;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

/**
 * Resolver logic tested against hand-built responses (no network). Each test supplies a
 * fake Transport that plays the role of root/TLD/authoritative servers.
 */
class IterativeResolverTest {

    private static final String ROOT1 = "198.41.0.4", ROOT2 = "170.247.170.2", ROOT3 = "192.33.4.12";

    // ---- helpers

    @FunctionalInterface interface Server { DnsWire.Message answer(String ip, String qname, int qtype) throws IOException; }

    /**
     * Stand-in for the real transport: tries the given servers in order (like Member C's failover),
     * logs every attempt as "ip qname qtype", and reports how many packets it "sent".
     * A Server that throws TransportFailure has it passed straight through to the resolver.
     */
    static final class Fake implements Transport {
        final List<String> log = Collections.synchronizedList(new ArrayList<>());
        final Server server;
        Fake(Server server) { this.server = server; }
        @Override public TransportReply query(List<String> servers, String qname, int qtype) throws IOException {
            IOException last = null;
            int packets = 0;
            for (String ip : servers) {
                log.add(ip + " " + qname + " " + qtype);
                packets++;
                try {
                    return new TransportReply(server.answer(ip, qname, qtype), ip, packets, false);
                } catch (TransportFailure e) {
                    throw e;
                } catch (IOException e) {
                    last = e;
                }
            }
            throw new TransportFailure("all servers failed", last, packets, null);
        }
    }

    static DnsWire.Record rec(String name, int type, String data) { return new DnsWire.Record(name, type, 300, data); }

    static DnsWire.Message msg(int rcode, boolean aa) {
        DnsWire.Message m = new DnsWire.Message();
        m.rcode = rcode; m.authoritative = aa; m.qr = true;
        return m;
    }

    static DnsWire.Message referral(String zone, String nsName, String glueIp) {
        DnsWire.Message m = msg(0, false);
        m.authority.add(rec(zone, DnsWire.NS, nsName));
        if (glueIp != null) m.additional.add(rec(nsName, DnsWire.A, glueIp));
        return m;
    }

    static DnsWire.Message answer(String name, int type, String data) {
        DnsWire.Message m = msg(0, true);
        m.answers.add(rec(name, type, data));
        return m;
    }

    /** root -> com. (glue a.gtld-servers.net) -> example.com. (glue ns.example.com) -> A 9.9.9.9 */
    static final Server TREE = (ip, q, t) -> {
        switch (ip) {
            case ROOT1: return referral("com.", "a.gtld-servers.net.", "1.1.1.1");
            case "1.1.1.1": return referral("example.com.", "ns.example.com.", "2.2.2.2");
            case "2.2.2.2": return answer("example.com.", DnsWire.A, "9.9.9.9");
            default: throw new IOException("unreachable " + ip);
        }
    };

    // ---- the basic walk

    @Test void walksRootTldAuthoritative() throws Exception {
        Fake f = new Fake(TREE);
        Resolution r = new IterativeResolver(f).resolve("example.com", DnsWire.A);
        assertEquals(0, r.rcode);
        assertEquals(1, r.answers.size());
        assertEquals("9.9.9.9", r.answers.get(0).data);
        assertEquals(3, f.log.size());
        assertEquals(List.of(".", "com.", "example.com."), r.delegations);
    }

    @Test void rootSuppliedGlueForOtherTldIsAccepted() throws Exception {
        // a.gtld-servers.net is not under com., but the root is the parent of every name.
        Fake f = new Fake(TREE);
        new IterativeResolver(f).resolve("example.com", DnsWire.A);
        assertTrue(f.log.contains("1.1.1.1 example.com. 1"));
    }

    @Test void statsCountQueries() throws Exception {
        Resolution r = new IterativeResolver(new Fake(TREE)).resolve("example.com", DnsWire.A);
        assertEquals(3, r.stats.upstreamQueries());
        assertEquals(3, r.stats.packetsSent());
        assertEquals(0, r.stats.failedQueries());
        assertEquals(0, r.stats.timeouts());
        assertTrue(r.stats.elapsedMs() >= 0);
    }

    // ---- failover

    @Test void failsOverWhenServerRefuses() throws Exception {
        Fake f = new Fake((ip, q, t) -> ip.equals(ROOT1) ? msg(5, false) : answer("a.com.", DnsWire.A, "7.7.7.7"));
        Resolution r = new IterativeResolver(f).resolve("a.com", DnsWire.A);
        assertEquals("7.7.7.7", r.answers.get(0).data);
        assertEquals(2, f.log.size());
        assertEquals(1, r.stats.unusableResponses());
    }

    @Test void failsOverOnServfailThenLameServer() throws Exception {
        Fake f = new Fake((ip, q, t) -> {
            if (ip.equals(ROOT1)) return msg(2, false);          // SERVFAIL
            if (ip.equals(ROOT2)) return msg(0, false);          // lame: no answer, no referral, AA=0
            return answer("a.com.", DnsWire.A, "7.7.7.7");
        });
        Resolution r = new IterativeResolver(f).resolve("a.com", DnsWire.A);
        assertEquals(3, f.log.size());
        assertEquals(2, r.stats.unusableResponses());
    }

    @Test void networkFailoverInsideTransportShowsUpOnlyAsExtraPackets() throws Exception {
        Fake f = new Fake((ip, q, t) -> {
            if (ip.equals(ROOT1)) throw new SocketTimeoutException("Receive timed out");
            return answer("a.com.", DnsWire.A, "7.7.7.7");
        });
        Resolution r = new IterativeResolver(f).resolve("a.com", DnsWire.A);
        assertEquals(1, r.stats.upstreamQueries());     // one question asked of the transport
        assertEquals(2, r.stats.packetsSent());         // ... which took two packets (ROOT1 timed out)
        assertEquals(0, r.stats.failedQueries());
    }

    @Test void totalTimeoutIsCountedAsFailedQueryWithTimeout() {
        Fake f = new Fake((ip, q, t) -> { throw new SocketTimeoutException("Receive timed out"); });
        ResolutionException e = assertThrows(ResolutionException.class,
                () -> new IterativeResolver(f).resolve("a.com", DnsWire.A));
        assertEquals(1, e.stats.upstreamQueries());
        assertEquals(13, e.stats.packetsSent());
        assertEquals(1, e.stats.failedQueries());
        assertEquals(1, e.stats.timeouts());
    }

    @Test void malformedReplyFromOneServerIsSkippedAndOthersAreAsked() throws Exception {
        Fake f = new Fake((ip, q, t) -> {
            if (ip.equals(ROOT1)) throw new TransportFailure("malformed reply from " + ROOT1, null, 1, ROOT1);
            return answer("a.com.", DnsWire.A, "7.7.7.7");
        });
        Resolution r = new IterativeResolver(f).resolve("a.com", DnsWire.A);
        assertEquals("7.7.7.7", r.answers.get(0).data);
        assertEquals(List.of(ROOT1 + " a.com. 1", ROOT2 + " a.com. 1"), f.log);   // ROOT1 not asked again
        assertEquals(1, r.stats.unusableResponses());
        assertEquals(2, r.stats.upstreamQueries());
    }

    @Test void tcpFallbackAndRetransmissionsAreVisibleInPathAndStats() throws Exception {
        Transport t = (servers, q, type) -> new Transport.TransportReply(answer("a.com.", DnsWire.A, "7.7.7.7"), servers.get(0), 2, true);
        Resolution r = new IterativeResolver(t).resolve("a.com", DnsWire.A);
        assertTrue(r.path.stream().anyMatch(s -> s.contains("[TCP fallback]")));
        assertEquals(2, r.stats.packetsSent());
        assertEquals(1, r.stats.upstreamQueries());
    }

    @Test void allServersBadGivesCleanFailureWithPath() {
        ResolutionException e = assertThrows(ResolutionException.class,
                () -> new IterativeResolver(new Fake((ip, q, t) -> msg(5, false))).resolve("a.com", DnsWire.A));
        assertFalse(e.path.isEmpty());
        assertEquals(13, e.stats.upstreamQueries());
    }

    @Test void sidewaysReferralIsRejectedNotLooped() {
        Fake f = new Fake((ip, q, t) -> ip.equals(ROOT1)
                ? referral("com.", "a.gtld-servers.net.", "1.1.1.1")
                : referral("com.", "a.gtld-servers.net.", "1.1.1.1"));   // com. server refers to com. again
        assertThrows(ResolutionException.class, () -> new IterativeResolver(f).resolve("example.com", DnsWire.A));
        assertEquals(2, f.log.size());
    }

    // ---- glue

    @Test void outOfBailiwickGlueFromTldIsIgnoredAndNsResolvedProperly() throws Exception {
        Fake f = new Fake((ip, q, t) -> {
            if (q.equals("ns.evil.org.")) {
                if (ip.equals("3.3.3.3")) return answer("ns.evil.org.", DnsWire.A, "8.8.8.8");
                if (ip.equals(ROOT1)) return referral("org.", "a0.org.", "3.3.3.3");
            }
            if (ip.equals(ROOT1)) return referral("com.", "a.gtld-servers.net.", "1.1.1.1");
            if (ip.equals("1.1.1.1")) return referral("example.com.", "ns.evil.org.", "6.6.6.6");  // spoofed glue
            if (ip.equals("8.8.8.8")) return answer("example.com.", DnsWire.A, "1.2.3.4");
            if (ip.equals("6.6.6.6")) return answer("example.com.", DnsWire.A, "6.6.6.6");
            throw new IOException("unreachable " + ip);
        });
        Resolution r = new IterativeResolver(f).resolve("example.com", DnsWire.A);
        assertEquals("1.2.3.4", r.answers.get(0).data);
        assertFalse(f.log.contains("6.6.6.6 example.com. 1"));
        assertTrue(r.path.stream().anyMatch(s -> s.contains("ignored out-of-bailiwick glue")));
    }

    @Test void gluelessDelegationResolvesNsOnceAndStops() throws Exception {
        Fake f = new Fake((ip, q, t) -> {
            if (ip.equals(ROOT1) && q.equals("example.com.")) {
                DnsWire.Message m = msg(0, false);
                m.authority.add(rec("example.com.", DnsWire.NS, "ns1.dns.net."));
                m.authority.add(rec("example.com.", DnsWire.NS, "ns2.dns.net."));
                return m;
            }
            if (ip.equals(ROOT1) && q.equals("ns1.dns.net.")) return answer("ns1.dns.net.", DnsWire.A, "5.5.5.5");
            if (ip.equals("5.5.5.5")) return answer("example.com.", DnsWire.A, "9.9.9.9");
            throw new IOException("unreachable " + ip);
        });
        Resolution r = new IterativeResolver(f).resolve("example.com", DnsWire.A);
        assertEquals("9.9.9.9", r.answers.get(0).data);
        assertEquals(3, f.log.size());                      // no lookup of ns2.dns.net.
        assertEquals(List.of(".", "example.com."), r.delegations);   // NS lookup not in chain
    }

    @Test void ipv4GlueIsTriedBeforeIpv6() throws Exception {
        Fake f = new Fake((ip, q, t) -> {
            if (ip.equals(ROOT1)) {
                DnsWire.Message m = msg(0, false);
                m.authority.add(rec("example.com.", DnsWire.NS, "ns.example.com."));
                m.additional.add(rec("ns.example.com.", DnsWire.AAAA, "2001:db8::1"));   // listed first on purpose
                m.additional.add(rec("ns.example.com.", DnsWire.A, "2.2.2.2"));
                return m;
            }
            if (ip.equals("2.2.2.2")) return answer("example.com.", DnsWire.A, "9.9.9.9");
            throw new IOException("Network is unreachable: sendto");
        });
        Resolution r = new IterativeResolver(f).resolve("example.com", DnsWire.A);
        assertEquals("9.9.9.9", r.answers.get(0).data);
        assertEquals(2, f.log.size());                         // root + the IPv4 server; IPv6 never tried
        assertEquals(0, r.stats.failedQueries());
    }

    @Test void ipv6IsStillUsedWhenIpv4Fails() throws Exception {
        Fake f = new Fake((ip, q, t) -> {
            if (ip.equals(ROOT1)) {
                DnsWire.Message m = msg(0, false);
                m.authority.add(rec("example.com.", DnsWire.NS, "ns.example.com."));
                m.additional.add(rec("ns.example.com.", DnsWire.A, "2.2.2.2"));
                m.additional.add(rec("ns.example.com.", DnsWire.AAAA, "2001:db8::1"));
                return m;
            }
            if (ip.equals("2.2.2.2")) throw new SocketTimeoutException("Receive timed out");
            return answer("example.com.", DnsWire.A, "9.9.9.9");
        });
        Resolution r = new IterativeResolver(f).resolve("example.com", DnsWire.A);
        assertEquals("9.9.9.9", r.answers.get(0).data);
        assertEquals(List.of(ROOT1 + " example.com. 1", "2.2.2.2 example.com. 1", "2001:db8::1 example.com. 1"), f.log);
    }

    // ---- CNAMEs

    @Test void cnameWithTargetInSameResponseCostsOneQuery() throws Exception {
        Fake f = new Fake((ip, q, t) -> {
            DnsWire.Message m = msg(0, true);
            m.answers.add(rec("www.x.com.", DnsWire.CNAME, "cdn.x.com."));
            m.answers.add(rec("cdn.x.com.", DnsWire.A, "5.5.5.5"));
            return m;
        });
        Resolution r = new IterativeResolver(f).resolve("www.x.com", DnsWire.A);
        assertEquals(1, f.log.size());
        assertEquals(2, r.answers.size());
    }

    @Test void cnameChainAcrossZonesIsFollowed() throws Exception {
        Fake f = new Fake((ip, q, t) -> {
            switch (q) {
                case "www.a.com.": return answer(q, DnsWire.CNAME, "mid.b.net.");
                case "mid.b.net.": return answer(q, DnsWire.CNAME, "end.c.org.");
                case "end.c.org.": return answer(q, DnsWire.A, "4.4.4.4");
                default: throw new IOException("?");
            }
        });
        Resolution r = new IterativeResolver(f).resolve("www.a.com", DnsWire.A);
        assertEquals(3, f.log.size());
        assertEquals(3, r.answers.size());
        assertEquals("4.4.4.4", r.answers.get(2).data);
    }

    @Test void cnameLoopAcrossQueriesIsDetected() {
        Fake f = new Fake((ip, q, t) -> q.equals("a.com.")
                ? answer(q, DnsWire.CNAME, "b.com.") : answer(q, DnsWire.CNAME, "a.com."));
        assertThrows(ResolutionException.class, () -> new IterativeResolver(f).resolve("a.com", DnsWire.A));
    }

    @Test void cnameLoopInsideOneResponseIsDetected() {
        Fake f = new Fake((ip, q, t) -> {
            DnsWire.Message m = msg(0, true);
            m.answers.add(rec("a.com.", DnsWire.CNAME, "b.com."));
            m.answers.add(rec("b.com.", DnsWire.CNAME, "a.com."));
            return m;
        });
        assertThrows(ResolutionException.class, () -> new IterativeResolver(f).resolve("a.com", DnsWire.A));
        assertEquals(1, f.log.size());
    }

    @Test void cnameQueryReturnsAliasWithoutChasing() throws Exception {
        Fake f = new Fake((ip, q, t) -> answer("www.x.com.", DnsWire.CNAME, "cdn.x.com."));
        Resolution r = new IterativeResolver(f).resolve("www.x.com", DnsWire.CNAME);
        assertEquals(1, f.log.size());
        assertEquals(1, r.answers.size());
    }

    @Test void cnameToNxdomainKeepsAliasAndSoa() throws Exception {
        Fake f = new Fake((ip, q, t) -> {
            if (q.equals("www.x.com.")) return answer(q, DnsWire.CNAME, "gone.y.com.");
            DnsWire.Message m = msg(3, true);
            m.authority.add(rec("y.com.", DnsWire.SOA, "ns. host. 1 2 3 4 5"));
            return m;
        });
        Resolution r = new IterativeResolver(f).resolve("www.x.com", DnsWire.A);
        assertEquals(3, r.rcode);
        assertEquals(1, r.answers.size());
        assertEquals(1, r.authority.size());
        assertEquals(DnsWire.SOA, r.authority.get(0).type);
    }

    // ---- NODATA / invalid input / concurrency

    @Test void authoritativeNodataIsReturnedWithSoa() throws Exception {
        Fake f = new Fake((ip, q, t) -> {
            DnsWire.Message m = msg(0, true);
            m.authority.add(rec("a.com.", DnsWire.SOA, "x y 1 2 3 4 5"));
            return m;
        });
        Resolution r = new IterativeResolver(f).resolve("a.com", DnsWire.AAAA);
        assertTrue(r.answers.isEmpty());
        assertEquals(1, r.authority.size());
    }

    @Test void invalidNameFailsWithoutQueryingAnyone() {
        Fake f = new Fake((ip, q, t) -> msg(0, true));
        assertThrows(ResolutionException.class, () -> new IterativeResolver(f).resolve("a..com", DnsWire.A));
        assertThrows(ResolutionException.class, () -> new IterativeResolver(f).resolve("a".repeat(64) + ".com", DnsWire.A));
        assertEquals(0, f.log.size());
    }

    @Test void oneResolverServesConcurrentQueriesWithoutCrossTalk() throws Exception {
        IterativeResolver shared = new IterativeResolver(new Fake((ip, q, t) -> {
            try { Thread.sleep(1); } catch (InterruptedException ignored) { }
            return answer(q, DnsWire.A, "1.1.1.1");
        }));
        ExecutorService pool = Executors.newFixedThreadPool(16);
        List<Future<Boolean>> results = new ArrayList<>();
        for (int i = 0; i < 200; i++) {
            final String name = "h" + i + ".test";
            results.add(pool.submit(() -> {
                Resolution r = shared.resolve(name, DnsWire.A);
                boolean pathOk = r.path.stream().filter(s -> s.startsWith("->")).allMatch(s -> s.contains(name + "."));
                return pathOk && r.answers.get(0).name.equals(name + ".");
            }));
        }
        for (Future<Boolean> f : results) assertTrue(f.get());
        pool.shutdown();
    }
}
