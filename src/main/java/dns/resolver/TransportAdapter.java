package dns.resolver;

import dns.transport.DnsTransport;
import dns.transport.TransportConfig;
import dns.transport.TransportException;
import dns.transport.TransportResult;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Plugs Member C's {@link DnsTransport} into the resolver's {@link Transport} boundary.
 * C's classes are used unchanged; this adapter only
 *  - turns IP strings into socket addresses (literals only, so no name lookup can happen),
 *  - encodes the query with a random transaction ID and decodes the raw reply (via {@link MessageCodec}),
 *  - maps results/exceptions to what the resolver needs.
 */
final class TransportAdapter implements Transport {
    private static final Pattern IP_LITERAL = Pattern.compile("[0-9A-Fa-f:.]+");

    private final DnsTransport transport;
    private final TransportConfig config;
    private final MessageCodec codec;
    private final int port;
    private final SecureRandom random = new SecureRandom();

    /** @param config must be the same config the DnsTransport was built with (used to estimate packets on failure) */
    TransportAdapter(DnsTransport transport, TransportConfig config, MessageCodec codec, int port) {
        this.transport = transport;
        this.config = config;
        this.codec = codec;
        this.port = port;
    }

    TransportAdapter(DnsTransport transport, TransportConfig config, MessageCodec codec) {
        this(transport, config, codec, 53);
    }

    @Override public TransportReply query(List<String> servers, String qname, int qtype) throws IOException {
        if (servers.isEmpty()) throw new IOException("no candidate servers");

        List<InetSocketAddress> candidates = new ArrayList<>();
        Map<InetSocketAddress, String> original = new HashMap<>();   // C returns one of these objects back
        for (String ip : servers) {
            if (!IP_LITERAL.matcher(ip).matches()) throw new IOException("not an IP address literal: " + ip);
            InetSocketAddress a = new InetSocketAddress(InetAddress.getByName(ip), port);   // literal: no DNS lookup
            candidates.add(a);
            original.put(a, ip);
        }

        byte[] packet;
        try {
            packet = codec.encodeQuery(random.nextInt(65536), qname, qtype);
        } catch (IllegalArgumentException e) {
            throw new IOException("cannot encode query for " + qname + ": " + e.getMessage(), e);
        }

        TransportResult result;
        try {
            result = transport.query(candidates, packet);
        } catch (TransportException e) {
            // C's exception does not carry the attempt count; every server is tried (retries + 1) times.
            throw new TransportFailure(e.getMessage(), e, servers.size() * (config.retries + 1), null);
        }

        String server = original.getOrDefault(result.server, result.server.getAddress().getHostAddress());
        try {
            return new TransportReply(codec.decode(result.response), server, result.attempts, result.usedTcp);
        } catch (IOException e) {
            throw new TransportFailure("malformed reply from " + server + ": " + e.getMessage(), e, result.attempts, server);
        }
    }
}
