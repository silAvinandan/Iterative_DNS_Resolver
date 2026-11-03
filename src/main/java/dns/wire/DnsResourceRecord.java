
package dns.wire;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents a DNS Resource Record.
 *
 * Supports raw RDATA and typed RDATA encoding/decoding.
 */
public final class DnsResourceRecord {

    public static final int TYPE_A = 1;
    public static final int TYPE_NS = 2;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_SOA = 6;
    public static final int TYPE_MX = 15;
    public static final int TYPE_TXT = 16;
    public static final int TYPE_AAAA = 28;

    public static final int CLASS_IN = 1;

    private final String name;
    private final int type;
    private final int recordClass;
    private final long ttl;
    private final byte[] rdata;
    private final Object rdataValue;

    /**
     * Creates a record using raw RDATA bytes.
     */
    public DnsResourceRecord(
            String name,
            int type,
            int recordClass,
            long ttl,
            byte[] rdata) {

        this(name, type, recordClass, ttl, rdata, null);
    }

    /**
     * Internal constructor supporting typed RDATA.
     */
    private DnsResourceRecord(
            String name,
            int type,
            int recordClass,
            long ttl,
            byte[] rdata,
            Object rdataValue) {

        if (name == null || rdata == null) {
            throw new IllegalArgumentException(
                    "Name and RDATA cannot be null"
            );
        }

        validateUnsignedShort(type, "TYPE");
        validateUnsignedShort(recordClass, "CLASS");

        if (ttl < 0 || ttl > 0xFFFFFFFFL) {
            throw new IllegalArgumentException(
                    "TTL must be between 0 and 4294967295"
            );
        }

        if (rdata.length > 65535) {
            throw new IllegalArgumentException(
                    "RDATA exceeds maximum length"
            );
        }

        this.name = name;
        this.type = type;
        this.recordClass = recordClass;
        this.ttl = ttl;
        this.rdata = Arrays.copyOf(rdata, rdata.length);
        this.rdataValue = rdataValue;
    }

    /**
     * Creates a record using type-specific RDATA.
     *
     * Expected values:
     * A/AAAA: byte[]
     * NS/CNAME: String
     * MX: DnsRdataCodec.MxData
     * SOA: DnsRdataCodec.SoaData
     * TXT: List<String>
     */
    public static DnsResourceRecord fromTypedData(
            String name,
            int type,
            int recordClass,
            long ttl,
            Object rdataValue) {

        if (rdataValue == null) {
            throw new IllegalArgumentException(
                    "RDATA value cannot be null"
            );
        }

        validateUnsignedShort(type, "TYPE");
        validateUnsignedShort(recordClass, "CLASS");

        if (ttl < 0 || ttl > 0xFFFFFFFFL) {
            throw new IllegalArgumentException(
                    "Invalid TTL"
            );
        }

        return new DnsResourceRecord(
                name,
                type,
                recordClass,
                ttl,
                new byte[0],
                rdataValue
        );
    }

    private static void validateUnsignedShort(
            int value, String field) {

        if (value < 0 || value > 65535) {
            throw new IllegalArgumentException(
                    field + " must be between 0 and 65535"
            );
        }
    }

    /**
     * Encodes the record using a new compression context.
     */
    public byte[] toBytes() {

        ByteArrayOutputStream output =
                new ByteArrayOutputStream();

        encodeTo(output, new HashMap<>());

        return output.toByteArray();
    }

    /**
     * Encodes the record into an existing DNS message.
     *
     * Uses a shared compression map and calculates RDLENGTH
     * after encoding the RDATA.
     */
    public void encodeTo(
            ByteArrayOutputStream output,
            Map<String, Integer> compressionMap) {

        if (output == null || compressionMap == null) {
            throw new IllegalArgumentException(
                    "Arguments cannot be null"
            );
        }

        // Work on copies so a failed encoding does not partially
        // modify the original message or compression map.
        ByteArrayOutputStream working =
                new ByteArrayOutputStream();

        working.writeBytes(output.toByteArray());

        Map<String, Integer> workingMap =
                new HashMap<>(compressionMap);

        // Encode the owner name.
        DnsNameCodec.encode(
                name, working, workingMap
        );

        // Encode the fixed Resource Record fields.
        writeUnsignedShort(working, type);
        writeUnsignedShort(working, recordClass);
        writeUnsignedInt(working, ttl);

        // Reserve two bytes for RDLENGTH.
        int rdLengthOffset = working.size();

        writeUnsignedShort(working, 0);

        int rdataStart = working.size();

        if (rdataValue != null) {

            DnsRdataCodec.encode(
                    type,
                    rdataValue,
                    working,
                    workingMap
            );

        } else {

            working.writeBytes(rdata);
        }

        int rdLength = working.size() - rdataStart;

        if (rdLength > 65535) {
            throw new IllegalArgumentException(
                    "RDATA exceeds maximum length"
            );
        }

        // Patch the actual RDLENGTH.
        byte[] encoded = working.toByteArray();

        encoded[rdLengthOffset] =
                (byte) ((rdLength >>> 8) & 0xFF);

        encoded[rdLengthOffset + 1] =
                (byte) (rdLength & 0xFF);

        // Commit the completed message.
        output.reset();
        output.writeBytes(encoded);

        compressionMap.clear();
        compressionMap.putAll(workingMap);
    }

    /**
     * Decodes a Resource Record while preserving raw RDATA.
     */
    public static Decoded decode(
            byte[] data, int offset) {

        return decodeInternal(data, offset, false);
    }

    /**
     * Decodes a Resource Record and its type-specific RDATA.
     *
     * Requires the complete DNS message because RDATA names
     * may contain compression pointers to earlier message offsets.
     */
    public static Decoded decodeTyped(
            byte[] data, int offset) {

        return decodeInternal(data, offset, true);
    }

    private static Decoded decodeInternal(
            byte[] data,
            int offset,
            boolean decodeTyped) {

        if (data == null) {
            throw new IllegalArgumentException(
                    "Input cannot be null"
            );
        }

        DnsNameCodec.Decoded decodedName =
                DnsNameCodec.decode(data, offset);

        int position = decodedName.nextOffset();

        if (position < 0 || position > data.length - 10) {
            throw new IllegalArgumentException(
                    "Truncated Resource Record fields"
            );
        }

        int type = readUnsignedShort(data, position);
        position += 2;

        int recordClass = readUnsignedShort(data, position);
        position += 2;

        long ttl = readUnsignedInt(data, position);
        position += 4;

        int rdLength = readUnsignedShort(data, position);
        position += 2;

        if (rdLength > data.length - position) {
            throw new IllegalArgumentException(
                    "Truncated RDATA"
            );
        }

        int rdataEnd = position + rdLength;

        byte[] rdata = Arrays.copyOfRange(
                data,
                position,
                rdataEnd
        );

        Object decodedValue = null;

        if (decodeTyped) {

            DnsRdataCodec.Decoded decodedRdata =
                    DnsRdataCodec.decode(
                            type,
                            data,
                            position,
                            rdLength
                    );

            if (decodedRdata.nextOffset() != rdataEnd) {
                throw new IllegalArgumentException(
                        "RDATA decoding did not consume its declared length"
                );
            }

            decodedValue = decodedRdata.value();
        }

        DnsResourceRecord record =
                new DnsResourceRecord(
                        decodedName.name(),
                        type,
                        recordClass,
                        ttl,
                        rdata,
                        decodedValue
                );

        return new Decoded(record, rdataEnd);
    }

    private static void writeUnsignedShort(
            ByteArrayOutputStream output, int value) {

        output.write((value >>> 8) & 0xFF);
        output.write(value & 0xFF);
    }

    private static void writeUnsignedInt(
            ByteArrayOutputStream output, long value) {

        output.write((int) ((value >>> 24) & 0xFF));
        output.write((int) ((value >>> 16) & 0xFF));
        output.write((int) ((value >>> 8) & 0xFF));
        output.write((int) (value & 0xFF));
    }

    private static int readUnsignedShort(
            byte[] data, int offset) {

        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    private static long readUnsignedInt(
            byte[] data, int offset) {

        return ((long) (data[offset] & 0xFF) << 24)
                | ((long) (data[offset + 1] & 0xFF) << 16)
                | ((long) (data[offset + 2] & 0xFF) << 8)
                | (long) (data[offset + 3] & 0xFF);
    }

    public String getName() {
        return name;
    }

    public int getType() {
        return type;
    }

    public int getRecordClass() {
        return recordClass;
    }

    public long getTtl() {
        return ttl;
    }

    /**
     * Returns a defensive copy of the original RDATA bytes.
     */
    public byte[] getRdata() {
        return Arrays.copyOf(rdata, rdata.length);
    }

    /**
     * Returns typed RDATA when available.
     * Otherwise returns the original raw RDATA bytes.
     */
    public Object getRdataValue() {
        if (rdataValue != null) {
            return rdataValue;
        }

        return getRdata();
    }

    public record Decoded(
            DnsResourceRecord record,
            int nextOffset) {
    }
}
