package dns.transport;

import java.net.InetSocketAddress;

/** What the resolver gets back: the raw reply plus metadata the experiments need. */
public final class TransportResult {
    public final byte[] response;
    public final InetSocketAddress server;
    public final boolean usedTcp;
    /** Datagrams/connections sent for THIS query (feeds "upstream queries per resolution"). */
    public final int attempts;
    public final long elapsedMs;

    TransportResult(byte[] response, InetSocketAddress server, boolean usedTcp, int attempts, long elapsedMs) {
        this.response = response;
        this.server = server;
        this.usedTcp = usedTcp;
        this.attempts = attempts;
        this.elapsedMs = elapsedMs;
    }
}
