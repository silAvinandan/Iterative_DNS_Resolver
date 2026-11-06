package dns.resolver;

import java.io.IOException;

/**
 * Wire-format seam. Member B's codec plugs in here (see INTEGRATION.md); until then
 * {@link DnsWireCodec} wraps the small stand-in codec in {@link DnsWire}.
 */
interface MessageCodec {
    /** Builds an ITERATIVE query packet (recursion-desired bit clear) with the given transaction ID. */
    byte[] encodeQuery(int id, String qname, int qtype);

    /** Decodes a response packet; throws IOException if it is malformed or truncated. */
    DnsWire.Message decode(byte[] packet) throws IOException;
}
