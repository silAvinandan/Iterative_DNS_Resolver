package dns.transport;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Member C tests. Runs against a fake DNS server on loopback, so no internet needed.
 * Run: java -cp out dns.transport.TransportTests
 */
public class TransportTests {
    static int failures = 0;

    static void check(String name, boolean ok) {
        System.out.println((ok ? "PASS  " : "FAIL  ") + name);
        if (!ok) failures++;
    }

    /** Minimal valid query for example.com A, with the given ID. */
    static byte[] query(int id) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int[] hdr = {id >> 8, id & 0xFF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
        for (int x : hdr) b.write(x);
        for (String label : new String[]{"example", "com"}) {
            b.write(label.length());
            b.writeBytes(label.getBytes());
        }
        b.write(0); b.write(0); b.write(1); b.write(0); b.write(1); // QTYPE=A, QCLASS=IN
        return b.toByteArray();
    }

    /** Loopback fake authoritative server with switchable misbehaviour. */
    static final class FakeServer implements AutoCloseable {
        final DatagramSocket udp;
        final ServerSocket tcp;
        final InetSocketAddress addr;
        volatile int dropFirst = 0;          // ignore this many UDP queries
        volatile boolean truncate = false;   // answer UDP with TC=1
        volatile boolean spoofFirst = false; // send a wrong-ID reply before the real one
        volatile int tcpPayload = 0;         // pad TCP replies up to this many bytes
        final AtomicInteger udpSeen = new AtomicInteger();

        FakeServer() throws IOException {
            udp = new DatagramSocket(0, InetAddress.getLoopbackAddress());
            tcp = new ServerSocket(udp.getLocalPort(), 5, InetAddress.getLoopbackAddress());
            addr = new InetSocketAddress(InetAddress.getLoopbackAddress(), udp.getLocalPort());
            daemon(this::udpLoop);
            daemon(this::tcpLoop);
        }

        static void daemon(Runnable r) { Thread t = new Thread(r); t.setDaemon(true); t.start(); }

        void reset(int drop) { dropFirst = drop; udpSeen.set(0); }

        byte[] reply(byte[] q, boolean tc) {
            byte[] r = q.clone();
            r[2] |= 0x80;                       // QR = response
            if (tc) r[2] |= 0x02; else r[2] &= ~0x02;
            return r;
        }

        void udpLoop() {
            byte[] buf = new byte[512];
            try {
                while (true) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    udp.receive(p);
                    int n = udpSeen.incrementAndGet();
                    if (n <= dropFirst) continue;
                    byte[] q = Arrays.copyOf(buf, p.getLength());
                    if (spoofFirst && n == dropFirst + 1) {
                        byte[] bad = reply(q, false);
                        bad[0] ^= 0xFF;         // wrong ID
                        udp.send(new DatagramPacket(bad, bad.length, p.getSocketAddress()));
                    }
                    byte[] r = reply(q, truncate);
                    udp.send(new DatagramPacket(r, r.length, p.getSocketAddress()));
                }
            } catch (IOException ignored) {}
        }

        void tcpLoop() {
            try {
                while (true) {
                    try (Socket s = tcp.accept()) {
                        DataInputStream in = new DataInputStream(s.getInputStream());
                        byte[] q = new byte[in.readUnsignedShort()];
                        in.readFully(q);
                        byte[] r = Arrays.copyOf(reply(q, false), Math.max(q.length, tcpPayload));
                        DataOutputStream out = new DataOutputStream(s.getOutputStream());
                        out.writeShort(r.length);
                        out.write(r);
                        out.flush();
                    } catch (IOException ignored) {}
                }
            } catch (Exception ignored) {}
        }

        @Override public void close() throws IOException { udp.close(); tcp.close(); }
    }

    static DnsTransport transport(int timeout, int retries, boolean backoff) {
        return new DnsTransport(new TransportConfig(timeout, retries, backoff), new ServerSelector());
    }

    public static void main(String[] args) throws Exception {
        // 1. Happy path
        try (FakeServer s = new FakeServer()) {
            TransportResult r = transport(500, 2, false).query(List.of(s.addr), query(0x1234));
            check("1. basic UDP round trip", r.attempts == 1 && !r.usedTcp && DnsHeader.id(r.response) == 0x1234);
        }

        // 2. Retry after packet loss
        try (FakeServer s = new FakeServer()) {
            s.dropFirst = 2;
            TransportResult r = transport(150, 3, false).query(List.of(s.addr), query(0x2222));
            check("2. retries through 2 dropped packets (attempts=3)", r.attempts == 3 && r.elapsedMs >= 280);
        }

        // 3. Server selection: dead server first, live second; then selector learns
        try (FakeServer dead = new FakeServer(); FakeServer live = new FakeServer()) {
            dead.dropFirst = Integer.MAX_VALUE;
            DnsTransport t = transport(150, 1, false);
            TransportResult r1 = t.query(List.of(dead.addr, live.addr), query(0x3001));
            TransportResult r2 = t.query(List.of(dead.addr, live.addr), query(0x3002));
            check("3a. fails over from dead to live server in same round",
                    r1.attempts == 2 && r1.server.equals(live.addr));
            check("3b. selector now ranks live server first (attempts=1)",
                    r2.attempts == 1 && r2.server.equals(live.addr));
        }

        // 4. Everything dead => TransportException after (retries+1) attempts, with backoff timing
        try (FakeServer dead = new FakeServer()) {
            dead.dropFirst = Integer.MAX_VALUE;
            DnsTransport t = transport(100, 2, true);   // waits 100 + 200 + 400 ms
            long t0 = System.nanoTime();
            boolean threw = false;
            try { t.query(List.of(dead.addr), query(0x4444)); } catch (TransportException e) { threw = true; }
            long ms = (System.nanoTime() - t0) / 1_000_000;
            check("4. all servers dead => TransportException, 3 attempts, backoff >= 700ms (" + ms + "ms)",
                    threw && t.udpSent() == 3 && ms >= 690);
        }

        // 5. Wrong-ID (spoofed) reply is ignored
        try (FakeServer s = new FakeServer()) {
            s.spoofFirst = true;
            TransportResult r = transport(500, 1, false).query(List.of(s.addr), query(0x5555));
            check("5. spoofed wrong-ID reply ignored, real one accepted",
                    r.attempts == 1 && DnsHeader.id(r.response) == 0x5555);
        }

        // 6. TCP fallback on TC bit
        try (FakeServer s = new FakeServer()) {
            s.truncate = true;
            s.tcpPayload = 1500;
            DnsTransport t = transport(500, 1, false);
            TransportResult r = t.query(List.of(s.addr), query(0x6666));
            check("6a. TC=1 triggers TCP fallback", r.usedTcp && t.tcpSent() == 1 && r.attempts == 2);
            check("6b. TCP reply is full-size (" + r.response.length + " B) and TC cleared",
                    r.response.length == 1500 && (r.response[2] & 0x02) == 0);
        }

        // 7. Retry/timeout tuning sweep (server drops first 2 packets => needs retries >= 2)
        System.out.println("\n--- tuning sweep: server drops first 2 UDP packets ---");
        System.out.printf("%-10s %-8s %-9s %-9s %s%n", "timeoutMs", "retries", "success", "attempts", "elapsedMs");
        boolean sweepOk = true;
        try (FakeServer s = new FakeServer()) {
            for (int timeout : new int[]{50, 100, 200}) {
                for (int retries : new int[]{0, 1, 2, 3}) {
                    s.reset(2);
                    DnsTransport t = transport(timeout, retries, false);
                    long t0 = System.nanoTime();
                    boolean ok;
                    int attempts;
                    try { TransportResult r = t.query(List.of(s.addr), query(0x7000 + retries)); ok = true; attempts = r.attempts; }
                    catch (TransportException e) { ok = false; attempts = (int) t.udpSent(); }
                    long ms = (System.nanoTime() - t0) / 1_000_000;
                    System.out.printf("%-10d %-8d %-9s %-9d %d%n", timeout, retries, ok, attempts, ms);
                    if (ok != (retries >= 2)) sweepOk = false;
                }
            }
        }
        check("7. sweep: succeeds iff retries >= 2, for every timeout value", sweepOk);

        System.out.println(failures == 0 ? "\nALL TESTS PASSED" : "\n" + failures + " TEST(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
