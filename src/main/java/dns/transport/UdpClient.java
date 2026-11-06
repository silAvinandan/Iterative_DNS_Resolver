package dns.transport;

import java.io.IOException;
import java.net.*;
import java.util.Arrays;

/** One UDP request/response exchange. */
final class UdpClient {
    private static final int RECV_BUFFER = 4096;

    byte[] exchange(InetSocketAddress server, byte[] query, int id, int timeoutMs) throws IOException {
        // New socket per query => fresh random source port (harder to spoof).
        try (DatagramSocket s = new DatagramSocket()) {
            s.connect(server); // OS/JVM now drops datagrams from any other source
            s.send(new DatagramPacket(query, query.length));

            byte[] buf = new byte[RECV_BUFFER];
            long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
            while (true) {
                long remainingMs = (deadline - System.nanoTime()) / 1_000_000L;
                if (remainingMs <= 0) throw new SocketTimeoutException("no valid reply within " + timeoutMs + " ms");
                s.setSoTimeout((int) remainingMs);
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                s.receive(p); // may throw SocketTimeoutException / PortUnreachableException
                if (DnsHeader.isValidResponse(p.getData(), p.getLength(), id)) {
                    return Arrays.copyOf(buf, p.getLength());
                }
                // wrong ID or not a response: ignore it and keep waiting until the deadline
            }
        }
    }
}
