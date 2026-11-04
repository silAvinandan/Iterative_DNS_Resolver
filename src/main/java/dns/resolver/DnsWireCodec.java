package dns.resolver;

import java.io.IOException;

/** {@link MessageCodec} backed by the stand-in {@link DnsWire}. Replace with an adapter over Member B's classes. */
final class DnsWireCodec implements MessageCodec {
    @Override public byte[] encodeQuery(int id, String qname, int qtype) { return DnsWire.query(id, qname, qtype); }
    @Override public DnsWire.Message decode(byte[] packet) throws IOException { return DnsWire.parse(packet); }
}
