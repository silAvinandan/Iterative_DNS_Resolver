package dns.resolver;

import java.util.List;

/**
 * Result of a resolution. Records are structured (with TTLs) so the cache and server
 * layers can use them directly; the authority section carries the SOA needed for
 * negative caching when the answer is empty or NXDOMAIN.
 */
final class Resolution {

    /**
     * Counters for experiments.
     *  upstreamQueries   calls made to the transport = DNS queries that got an answer or a final failure
     *                    (comparable with the number of "Received" lines in dig +trace)
     *  packetsSent       UDP datagrams + TCP connections actually sent, including retransmissions and failover
     *  failedQueries     transport calls where no server answered at all
     *  timeouts          failed calls whose cause was a timeout
     *  unusableResponses answers rejected by the resolver (REFUSED, lame, bad referral, malformed)
     */
    record Stats(int upstreamQueries, int packetsSent, int failedQueries, int timeouts, int unusableResponses, long elapsedMs) {}

    final int rcode;
    final List<DnsWire.Record> answers, authority;
    final List<String> path;          // human-readable query log
    final List<String> delegations;   // zone chain for the original name, e.g. [., com., example.com.]
    final Stats stats;

    Resolution(DnsWire.Message m, List<String> path, List<String> delegations, Stats stats) {
        this.rcode = m.rcode;
        this.answers = List.copyOf(m.answers);
        this.authority = List.copyOf(m.authority);
        this.path = List.copyOf(path);
        this.delegations = List.copyOf(delegations);
        this.stats = stats;
    }
}
