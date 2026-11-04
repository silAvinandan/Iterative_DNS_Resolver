package dns.transport;

import java.io.*;
import java.net.*;

/** One DNS-over-TCP exchange (RFC 1035 s4.2.2: 2-byte length prefix on each message). */
final class TcpClient {
    byte[] exchange(InetSocketAddress server, byte[] query, int id, int timeoutMs) throws IOException {
        try (Socket s = new Socket()) {
            s.connect(server, timeoutMs);
            s.setSoTimeout(timeoutMs);

            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
            out.writeShort(query.length);
            out.write(query);
            out.flush();

            DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
            int len = in.readUnsignedShort();
            if (len < 12) throw new IOException("TCP reply too short: " + len);
            byte[] resp = new byte[len];
            in.readFully(resp); // loops until all bytes arrive (TCP is a stream)
            if (!DnsHeader.isValidResponse(resp, len, id)) throw new IOException("TCP reply failed ID/QR check");
            return resp;
        }
    }
}
