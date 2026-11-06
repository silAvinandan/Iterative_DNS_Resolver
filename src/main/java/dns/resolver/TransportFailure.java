package dns.resolver;

import java.io.IOException;

/** A transport call that produced no usable response, with extra detail for the resolver's statistics. */
final class TransportFailure extends IOException {
    private static final long serialVersionUID = 1L;

    /** Best known number of packets sent before giving up (may be an estimate). */
    final int packetsSent;
    /** Non-null when this one server answered with an undecodable packet; the resolver skips it and goes on. */
    final String badServer;

    TransportFailure(String message, Throwable cause, int packetsSent, String badServer) {
        super(message, cause);
        this.packetsSent = packetsSent;
        this.badServer = badServer;
    }
}
