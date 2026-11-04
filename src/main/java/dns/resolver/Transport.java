package dns.resolver;

import java.io.IOException;
import java.util.List;

/**
 * Boundary between the resolution algorithm and the network.
 *
 * The resolver hands over ALL candidate server addresses for a delegation; the transport
 * decides the order, retries, timeouts and TCP fallback (Member C's job) and returns the first
 * response it gets from one of them. The resolver then judges the response (REFUSED, lame,
 * bad referral ...) and, if unusable, calls again with that server removed.
 *
 * Failure contract: throw IOException when no server answered. Throw {@link TransportFailure}
 * to also report packets sent, or that one specific server sent an undecodable reply.
 * Implementations must be thread-safe if the resolver is shared between threads.
 */
interface Transport {

    TransportReply query(List<String> servers, String qname, int qtype) throws IOException;

    /**
     * @param message     decoded response
     * @param server      which of the candidate addresses answered (same string as passed in)
     * @param packetsSent UDP datagrams + TCP connections sent for this call, including retries
     * @param usedTcp     true if the answer came over TCP after a truncated UDP reply
     */
    record TransportReply(DnsWire.Message message, String server, int packetsSent, boolean usedTcp) {}
}
