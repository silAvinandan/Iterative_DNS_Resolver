package dns.resolver;

import dns.wire.DnsHeader;
import dns.wire.DnsNameCodec;
import dns.wire.DnsResourceRecord;
import dns.wire.DnsRdataCodec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

final class BWireCodec implements MessageCodec {

    @Override
    public byte[] encodeQuery(int id, String qname, int qtype) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        DnsHeader header = new DnsHeader(id, 0, 1, 0, 0, 0);
        out.writeBytes(header.toBytes());

        DnsNameCodec.encode(qname, out, new HashMap<>());
        out.write((qtype >>> 8) & 0xFF);
        out.write(qtype & 0xFF);
        out.write(0);
        out.write(1);

        return out.toByteArray();
    }

    @Override
    public DnsWire.Message decode(byte[] packet) throws IOException {
        if (packet == null || packet.length < DnsHeader.HEADER_LENGTH) {
            throw new IOException("DNS packet shorter than header");
        }

        DnsHeader header;
        try {
            header = DnsHeader.fromBytes(packet);
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid DNS header", e);
        }

        DnsWire.Message message = new DnsWire.Message();
        message.id = header.getId();

        int flags = header.getFlags();
        message.qr = (flags & 0x8000) != 0;
        message.authoritative = (flags & 0x0400) != 0;
        message.truncated = (flags & 0x0200) != 0;
        message.rcode = flags & 0x000F;

        int[] position = {DnsHeader.HEADER_LENGTH};

        try {
            for (int i = 0; i < header.getQdCount(); i++) {
                DnsNameCodec.Decoded question =
                        DnsNameCodec.decode(packet, position[0]);

                position[0] = question.nextOffset();

                if (position[0] > packet.length - 4) {
                    throw new IOException("Truncated DNS question");
                }

                position[0] += 4;
            }

            readRecords(packet, position, header.getAnCount(), message.answers);
            readRecords(packet, position, header.getNsCount(), message.authority);
            readRecords(packet, position, header.getArCount(), message.additional);

        } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
            throw new IOException("Malformed DNS response: " + e.getMessage(), e);
        }

        return message;
    }

    private void readRecords(
            byte[] packet,
            int[] position,
            int count,
            List<DnsWire.Record> output) throws IOException {

        for (int i = 0; i < count; i++) {
            int start = position[0];

            DnsResourceRecord.Decoded decoded;
            try {
                decoded = DnsResourceRecord.decodeTyped(packet, start);
            } catch (IllegalArgumentException e) {
                throw new IOException("Malformed DNS resource record", e);
            }

            DnsResourceRecord record = decoded.record();
            position[0] = decoded.nextOffset();

            if (record.getRecordClass() != DnsResourceRecord.CLASS_IN) {
                continue;
            }

            int type = record.getType();
            if (type != DnsRdataCodec.TYPE_A
                    && type != DnsRdataCodec.TYPE_AAAA
                    && type != DnsRdataCodec.TYPE_NS
                    && type != DnsRdataCodec.TYPE_CNAME
                    && type != DnsRdataCodec.TYPE_MX
                    && type != DnsRdataCodec.TYPE_TXT
                    && type != DnsRdataCodec.TYPE_SOA) {
                continue;
            }

            long rawTtl = record.getTtl();
            int ttl = rawTtl > Integer.MAX_VALUE ? 0 : (int) rawTtl;

            Object value = record.getRdataValue();
            String data = formatRdata(type, value);

            output.add(new DnsWire.Record(
                    record.getName(), type, ttl, data, record
            ));
        }
    }

    private String formatRdata(int type, Object value) throws IOException {
        try {
            return switch (type) {
                case DnsRdataCodec.TYPE_A,
                     DnsRdataCodec.TYPE_AAAA ->
                        InetAddress.getByAddress((byte[]) value).getHostAddress();

                case DnsRdataCodec.TYPE_NS,
                     DnsRdataCodec.TYPE_CNAME ->
                        (String) value;

                case DnsRdataCodec.TYPE_MX -> {
                    DnsRdataCodec.MxData mx =
                            (DnsRdataCodec.MxData) value;
                    yield mx.preference() + " " + mx.exchange();
                }

                case DnsRdataCodec.TYPE_SOA -> {
                    DnsRdataCodec.SoaData soa =
                            (DnsRdataCodec.SoaData) value;
                    yield soa.mname() + " " + soa.rname() + " "
                            + soa.serial() + " " + soa.refresh() + " "
                            + soa.retry() + " " + soa.expire() + " "
                            + soa.minimum();
                }

                case DnsRdataCodec.TYPE_TXT -> {
                    @SuppressWarnings("unchecked")
                    List<String> strings = (List<String>) value;

                    List<String> quoted = new ArrayList<>();
                    for (String s : strings) {
                        quoted.add("\"" + s + "\"");
                    }
                    yield String.join(" ", quoted);
                }

                default -> throw new IOException(
                        "Unsupported DNS record type: " + type
                );
            };
        } catch (Exception e) {
            throw new IOException("Cannot format DNS RDATA for type " + type, e);
        }
    }
}
