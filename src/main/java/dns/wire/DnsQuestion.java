
package dns.wire;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents a DNS question section.
 */
public final class DnsQuestion {

    public static final int CLASS_IN = 1;

    public static final int TYPE_A = 1;
    public static final int TYPE_NS = 2;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_SOA = 6;
    public static final int TYPE_MX = 15;
    public static final int TYPE_TXT = 16;
    public static final int TYPE_AAAA = 28;

    private final String qname;
    private final int qtype;
    private final int qclass;

    public DnsQuestion(String qname, int qtype, int qclass) {

        if (qname == null) {
            throw new IllegalArgumentException(
                    "QNAME cannot be null"
            );
        }

        validate(qtype, "QTYPE");
        validate(qclass, "QCLASS");

        this.qname = qname;
        this.qtype = qtype;
        this.qclass = qclass;
    }

    private static void validate(int value, String field) {
        if (value < 0 || value > 65535) {
            throw new IllegalArgumentException(
                    field + " must be between 0 and 65535"
            );
        }
    }

    /**
     * Encodes the question using a new compression context.
     */
    public byte[] toBytes() {

        ByteArrayOutputStream output =
                new ByteArrayOutputStream();

        encodeTo(output, new HashMap<>());

        return output.toByteArray();
    }

    /**
     * Encodes the question into an existing DNS message.
     * The compression map must be shared across message sections.
     */
    public void encodeTo(
            ByteArrayOutputStream output,
            Map<String, Integer> compressionMap) {

        if (output == null || compressionMap == null) {
            throw new IllegalArgumentException(
                    "Arguments cannot be null"
            );
        }

        DnsNameCodec.encode(qname, output, compressionMap);

        writeUnsignedShort(output, qtype);
        writeUnsignedShort(output, qclass);
    }

    /**
     * Decodes a question using the shared DNS name codec.
     */
    public static Decoded decode(byte[] data, int offset) {

        if (data == null) {
            throw new IllegalArgumentException(
                    "Input cannot be null"
            );
        }

        DnsNameCodec.Decoded decodedName =
                DnsNameCodec.decode(data, offset);

        int position = decodedName.nextOffset();

        if (position < 0 || position > data.length - 4) {
            throw new IllegalArgumentException(
                    "Truncated DNS question fields"
            );
        }

        int qtype = readUnsignedShort(data, position);
        int qclass = readUnsignedShort(data, position + 2);

        DnsQuestion question = new DnsQuestion(
                decodedName.name(),
                qtype,
                qclass
        );

        return new Decoded(question, position + 4);
    }

    private static void writeUnsignedShort(
            ByteArrayOutputStream output, int value) {

        output.write((value >>> 8) & 0xFF);
        output.write(value & 0xFF);
    }

    private static int readUnsignedShort(
            byte[] data, int offset) {

        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    public String getQname() {
        return qname;
    }

    public int getQtype() {
        return qtype;
    }

    public int getQclass() {
        return qclass;
    }

    public record Decoded(
            DnsQuestion question,
            int nextOffset) {
    }
}
