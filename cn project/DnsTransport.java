package dns.transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Member C's public entry point. Contract with the resolver (Member A):
 *
 *   TransportResult r = transport.query(candidateServers, encodedQueryBytes);
 *
 * Strategy: UDP to the best-ranked server; on timeout/error move to the next
 * server; after a full round, retry (optionally with doubled timeout). If a reply
 * has TC=1, repeat the same query over TCP to the same server.
 */
public final class DnsTransport {
    private final TransportConfig cfg;
    private final ServerSelector selector;
    private final UdpClient udp = new UdpClient();
    private final TcpClient tcp = new TcpClient();

    private final AtomicLong udpSent = new AtomicLong();
    private final AtomicLong tcpSent = new AtomicLong();
    private final AtomicLong timeouts = new AtomicLong();

    public DnsTransport(TransportConfig cfg, ServerSelector selector) {
        this.cfg = cfg;
        this.selector = selector;
    }

    public DnsTransport() { this(TransportConfig.defaults(), new ServerSelector()); }

    public TransportResult query(List<InetSocketAddress> candidates, byte[] packet) throws TransportException {
        if (candidates.isEmpty()) throw new IllegalArgumentException("no candidate servers");
        if (packet.length < 12) throw new IllegalArgumentException("not a DNS message");

        final int id = DnsHeader.id(packet);
        final long start = System.nanoTime();
        int attempts = 0;
        int timeout = cfg.timeoutMs;
        Exception last = null;

        for (int round = 0; round <= cfg.retries; round++) {
            for (InetSocketAddress server : selector.order(candidates)) { // re-rank each round
                attempts++;
                udpSent.incrementAndGet();
                long t0 = System.nanoTime();
                try {
                    byte[] resp = udp.exchange(server, packet, id, timeout);
                    selector.recordSuccess(server, (System.nanoTime() - t0) / 1e6);

                    if (!DnsHeader.isTruncated(resp)) {
                        return new TransportResult(resp, server, false, attempts, msSince(start));
                    }
                    // TC bit set: UDP answer was cut off, ask again over TCP
                    attempts++;
                    tcpSent.incrementAndGet();
                    byte[] full = tcp.exchange(server, packet, id, timeout);
                    return new TransportResult(full, server, true, attempts, msSince(start));
                } catch (SocketTimeoutException e) {
                    timeouts.incrementAndGet();
                    selector.recordFailure(server);
                    last = e;
                } catch (IOException e) { // unreachable, TCP failure, etc.
                    selector.recordFailure(server);
                    last = e;
                }
            }
            if (cfg.exponentialBackoff) timeout = Math.min(timeout * 2, 30_000);
        }
        throw new TransportException("all " + candidates.size() + " server(s) failed after "
                + attempts + " attempt(s)", last);
    }

    private static long msSince(long startNanos) { return (System.nanoTime() - startNanos) / 1_000_000L; }

    public long udpSent()  { return udpSent.get(); }
    public long tcpSent()  { return tcpSent.get(); }
    public long timeouts() { return timeouts.get(); }
}
