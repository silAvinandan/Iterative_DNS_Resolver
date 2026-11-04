
package dns.wire;

/**
 * Represents the fixed 12-byte header of a DNS message.
 * All fields are unsigned 16-bit values.
 */
public final class DnsHeader {

    public static final int HEADER_LENGTH = 12;

    private final int id;
    private final int flags;
    private final int qdCount;
    private final int anCount;
    private final int nsCount;
    private final int arCount;

    public DnsHeader(int id, int flags, int qdCount,
                     int anCount, int nsCount, int arCount) {

        this.id = validate(id, "id");
        this.flags = validate(flags, "flags");
        this.qdCount = validate(qdCount, "qdCount");
        this.anCount = validate(anCount, "anCount");
        this.nsCount = validate(nsCount, "nsCount");
        this.arCount = validate(arCount, "arCount");
    }

    private static int validate(int value, String field) {
        if (value < 0 || value > 65535) {
            throw new IllegalArgumentException(
                field + " must be between 0 and 65535"
            );
        }
        return value;
    }

    /**
     * Encodes the header into exactly 12 bytes.
     */
    public byte[] toBytes() {
        byte[] data = new byte[HEADER_LENGTH];

        writeUnsignedShort(data, 0, id);
        writeUnsignedShort(data, 2, flags);
        writeUnsignedShort(data, 4, qdCount);
        writeUnsignedShort(data, 6, anCount);
        writeUnsignedShort(data, 8, nsCount);
        writeUnsignedShort(data, 10, arCount);

        return data;
    }

    /**
     * Decodes a DNS header from the beginning of a byte array.
     */
    public static DnsHeader fromBytes(byte[] data) {
        return fromBytes(data, 0);
    }

    /**
     * Decodes a DNS header beginning at the specified offset.
     */
    public static DnsHeader fromBytes(byte[] data, int offset) {

        if (data == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }

        if (offset < 0 || offset > data.length - HEADER_LENGTH) {
            throw new IllegalArgumentException(
                "Insufficient data for DNS header"
            );
        }

        return new DnsHeader(
            readUnsignedShort(data, offset),
            readUnsignedShort(data, offset + 2),
            readUnsignedShort(data, offset + 4),
            readUnsignedShort(data, offset + 6),
            readUnsignedShort(data, offset + 8),
            readUnsignedShort(data, offset + 10)
        );
    }

    private static int readUnsignedShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    private static void writeUnsignedShort(
            byte[] data, int offset, int value) {

        data[offset] = (byte) ((value >>> 8) & 0xFF);
        data[offset + 1] = (byte) (value & 0xFF);
    }

    public int getId() {
        return id;
    }

    public int getFlags() {
        return flags;
    }

    public int getQdCount() {
        return qdCount;
    }

    public int getAnCount() {
        return anCount;
    }

    public int getNsCount() {
        return nsCount;
    }

    public int getArCount() {
        return arCount;
    }
}
