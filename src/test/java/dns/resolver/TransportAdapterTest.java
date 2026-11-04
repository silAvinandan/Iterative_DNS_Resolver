package dns.resolver;

import static org.junit.jupiter.api.Assertions.*;

import dns.transport.DnsTransport;
import dns.transport.ServerSelector;
import dns.transport.TransportConfig;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Integration of the resolver's boundary with Member C's REAL transport classes (UDP, TCP,
 * retries, selector), talking to a fake DNS server on loopback. No internet needed.
 */
class TransportAdapterTest {

    private static final InetAddress LOOPBACK;
    static { try { LOOPBACK = InetAddress.getByAddress(new byte[] {127, 0, 0, 1}); } catch (Exception e) { throw new ExceptionInInitializerError(e); } }

    /** Fake authoritative server: UDP + TCP on the same loopback port, with switchable misbehaviour. */
    static final class FakeServer implements AutoCloseable {
        final DatagramSocket udp;
        final ServerSocket tcp;
        final int port;
        volatile int dropFirst = 0;          // ignore this many UDP queries
        volatile boolean truncate = false;   // answer UDP with TC=1 and no records
        volatile boolean garbage = false;    // answer with a valid header but a broken record section
        final AtomicInteger udpSeen = new AtomicInteger();

        FakeServer() throws IOException {
            udp = new DatagramSocket(0, LOOPBACK);
            tcp = new ServerSocket(udp.getLocalPort(), 5, LOOPBACK);
            port = udp.getLocalPort();
            daemon(this::udpLoop);
            daemon(this::tcpLoop);
        }

        static void daemon(Runnable r) { Thread t = new Thread(r); t.setDaemon(true); t.start(); }

        /** Echo the query as a response; adds one A record (4.3.2.1) unless truncating or sending garbage. */
        byte[] reply(byte[] q, boolean tc, boolean forceFull) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            byte[] r = q.clone();
            r[2] |= (byte) 0x84;                                   // QR + AA
            if (tc) r[2] |= 0x02;
            if (garbage) r[7] = 1;                                 // ANCOUNT=1 but no record follows
            else if (!tc || forceFull) r[7] = 1;
            b.writeBytes(r);
            if (!garbage && (!tc || forceFull)) {
                b.writeBytes(new byte[] {(byte) 0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 4, 3, 2, 1});
            }
            return b.toByteArray();
        }

        void udpLoop() {
            byte[] buf = new byte[512];
            try {
                while (true) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    udp.receive(p);
                    if (udpSeen.incrementAndGet() <= dropFirst) continue;
                    byte[] r = reply(Arrays.copyOf(buf, p.getLength()), truncate, false);
                    udp.send(new DatagramPacket(r, r.length, p.getSocketAddress()));
                }
            } catch (IOException ignored) { }
        }

        void tcpLoop() {
            try {
                while (true) {
                    try (Socket s = tcp.accept()) {
                        DataInputStream in = new DataInputStream(s.getInputStream());
                        byte[] q = new byte[in.readUnsignedShort()];
                        in.readFully(q);
                        byte[] r = reply(q, false, true);
                        DataOutputStream out = new DataOutputStream(s.getOutputStream());
                        out.writeShort(r.length);
                        out.write(r);
                        out.flush();
                    } catch (IOException ignored) { }
                }
            } catch (Exception ignored) { }
        }

        @Override public void close() throws IOException { udp.close(); tcp.close(); }
    }

    private static TransportAdapter adapter(TransportConfig cfg, int port) {
        return new TransportAdapter(new DnsTransport(cfg, new ServerSelector()), cfg, new DnsWireCodec(), port);
    }

    @Test void udpRoundTripReturnsDecodedMessage() throws Exception {
        try (FakeServer s = new FakeServer()) {
            Transport.TransportReply r = adapter(new TransportConfig(500, 1, false), s.port)
                    .query(List.of("127.0.0.1"), "example.com.", DnsWire.A);
            assertEquals("127.0.0.1", r.server());
            assertEquals(1, r.packetsSent());
            assertFalse(r.usedTcp());
            assertTrue(r.message().authoritative);
            assertEquals("4.3.2.1", r.message().answers.get(0).data);
            assertEquals(300, r.message().answers.get(0).ttl);
        }
    }

    @Test void retriesThroughDroppedPackets() throws Exception {
        try (FakeServer s = new FakeServer()) {
            s.dropFirst = 2;
            Transport.TransportReply r = adapter(new TransportConfig(150, 3, false), s.port)
                    .query(List.of("127.0.0.1"), "example.com.", DnsWire.A);
            assertEquals(3, r.packetsSent());
        }
    }

    @Test void truncatedUdpReplyFallsBackToTcp() throws Exception {
        try (FakeServer s = new FakeServer()) {
            s.truncate = true;
            Transport.TransportReply r = adapter(new TransportConfig(500, 1, false), s.port)
                    .query(List.of("127.0.0.1"), "example.com.", DnsWire.A);
            assertTrue(r.usedTcp());
            assertEquals(2, r.packetsSent());                         // UDP + TCP
            assertFalse(r.message().truncated);
            assertEquals("4.3.2.1", r.message().answers.get(0).data); // full answer arrived over TCP
        }
    }

    @Test void deadServerGivesTransportFailureWithTimeoutCauseAndPacketEstimate() throws Exception {
        try (FakeServer s = new FakeServer()) {
            s.dropFirst = Integer.MAX_VALUE;
            TransportFailure e = assertThrows(TransportFailure.class, () -> adapter(new TransportConfig(100, 1, false), s.port)
                    .query(List.of("127.0.0.1"), "example.com.", DnsWire.A));
            assertNull(e.badServer);
            assertEquals(2, e.packetsSent);                           // 1 server x (1 retry + 1)
            assertTrue(e.getCause().getCause() instanceof SocketTimeoutException);   // TransportException -> timeout
        }
    }

    @Test void undecodableReplyIsReportedAgainstThatServer() throws Exception {
        try (FakeServer s = new FakeServer()) {
            s.garbage = true;
            TransportFailure e = assertThrows(TransportFailure.class, () -> adapter(new TransportConfig(500, 1, false), s.port)
                    .query(List.of("127.0.0.1"), "example.com.", DnsWire.A));
            assertEquals("127.0.0.1", e.badServer);
            assertEquals(1, e.packetsSent);
        }
    }

    @Test void hostnamesAreRejectedSoNoNameLookupCanHappen() {
        TransportAdapter a = adapter(new TransportConfig(100, 0, false), 53);
        IOException e = assertThrows(IOException.class, () -> a.query(List.of("ns1.example.com"), "example.com.", DnsWire.A));
        assertTrue(e.getMessage().contains("not an IP address literal"));    // rejected by the guard, not by a failed lookup
        assertThrows(IOException.class, () -> a.query(List.of(), "example.com.", DnsWire.A));
    }

    @Test void resolverCountsTimeoutThroughTheAdapter() throws Exception {
        try (FakeServer s = new FakeServer()) {
            s.dropFirst = Integer.MAX_VALUE;
            // the resolver's root hints are fixed IPs, so drive the adapter via a one-server hop
            TransportAdapter a = adapter(new TransportConfig(100, 0, false), s.port);
            IterativeResolver r = new IterativeResolver((servers, q, t) -> a.query(List.of("127.0.0.1"), q, t));
            ResolutionException e = assertThrows(ResolutionException.class, () -> r.resolve("example.com", DnsWire.A));
            assertEquals(1, e.stats.timeouts());
            assertEquals(1, e.stats.failedQueries());
        }
    }
}
