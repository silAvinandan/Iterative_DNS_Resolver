
package dns.wire;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Encodes and decodes DNS Resource Record Data (RDATA).
 *
 * Supported types:
 * A, NS, CNAME, SOA, MX, TXT and AAAA.
 */
public final class DnsRdataCodec {

    private DnsRdataCodec() {
    }

    public static final int TYPE_A = 1;
    public static final int TYPE_NS = 2;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_SOA = 6;
    public static final int TYPE_MX = 15;
    public static final int TYPE_TXT = 16;
    public static final int TYPE_AAAA = 28;

    /**
     * MX record data.
     */
    public record MxData(int preference, String exchange) {

        public MxData {
            if (preference < 0 || preference > 65535
                    || exchange == null) {
                throw new IllegalArgumentException(
                        "Invalid MX data"
                );
            }
        }
    }

    /**
     * SOA record data.
     */
    public record SoaData(
            String mname,
            String rname,
            long serial,
            long refresh,
            long retry,
            long expire,
            long minimum) {

        public SoaData {
            if (mname == null || rname == null) {
                throw new IllegalArgumentException(
                        "SOA names cannot be null"
                );
            }

            validateUnsignedInt(serial);
            validateUnsignedInt(refresh);
            validateUnsignedInt(retry);
            validateUnsignedInt(expire);
            validateUnsignedInt(minimum);
        }
    }

    /**
     * Decoded RDATA and the next position in the DNS message.
     */
    public record Decoded(Object value, int nextOffset) {
    }

    /**
     * Encodes RDATA into an existing DNS message.
     *
     * Domain-name compression uses the shared message-level map.
     * The caller is responsible for writing the RDLENGTH field.
     *
     * A and AAAA values must be byte arrays.
     * NS and CNAME values must be Strings.
     * MX values must be MxData.
     * SOA values must be SoaData.
     * TXT values must be List<String>.
     */
    public static int encode(
            int type,
            Object value,
            ByteArrayOutputStream output,
            Map<String, Integer> compressionMap) {

        if (value == null || output == null
                || compressionMap == null) {
            throw new IllegalArgumentException(
                    "Arguments cannot be null"
            );
        }

        int start = output.size();

        switch (type) {

            case TYPE_A -> {
                byte[] address = requireBytes(value, 4, "A");
                output.writeBytes(address);
            }

            case TYPE_AAAA -> {
                byte[] address = requireBytes(value, 16, "AAAA");
                output.writeBytes(address);
            }

            case TYPE_NS, TYPE_CNAME -> {
                if (!(value instanceof String name)) {
                    throw new IllegalArgumentException(
                            "NS and CNAME require a domain name"
                    );
                }

                DnsNameCodec.encode(
                        name, output, compressionMap
                );
            }

            case TYPE_MX -> {
                if (!(value instanceof MxData mx)) {
                    throw new IllegalArgumentException(
                            "MX requires MxData"
                    );
                }

                writeUnsignedShort(output, mx.preference());

                DnsNameCodec.encode(
                        mx.exchange(), output, compressionMap
                );
            }

            case TYPE_SOA -> {
                if (!(value instanceof SoaData soa)) {
                    throw new IllegalArgumentException(
                            "SOA requires SoaData"
                    );
                }

                DnsNameCodec.encode(
                        soa.mname(), output, compressionMap
                );

                DnsNameCodec.encode(
                        soa.rname(), output, compressionMap
                );

                writeUnsignedInt(output, soa.serial());
                writeUnsignedInt(output, soa.refresh());
                writeUnsignedInt(output, soa.retry());
                writeUnsignedInt(output, soa.expire());
                writeUnsignedInt(output, soa.minimum());
            }

            case TYPE_TXT -> {
                if (!(value instanceof List<?> strings)) {
                    throw new IllegalArgumentException(
                            "TXT requires List<String>"
                    );
                }

                if (strings.isEmpty()) {
                    throw new IllegalArgumentException(
                            "TXT must contain at least one string"
                    );
                }

                for (Object item : strings) {

                    if (!(item instanceof String text)) {
                        throw new IllegalArgumentException(
                                "TXT entries must be strings"
                        );
                    }

                    byte[] bytes = text.getBytes(
                            StandardCharsets.UTF_8
                    );

                    if (bytes.length > 255) {
                        throw new IllegalArgumentException(
                                "TXT string exceeds 255 bytes"
                        );
                    }

                    output.write(bytes.length);
                    output.writeBytes(bytes);
                }
            }

            default -> throw new IllegalArgumentException(
                    "Unsupported DNS record type: " + type
            );
        }

        int length = output.size() - start;

        if (length > 65535) {
            throw new IllegalArgumentException(
                    "RDATA exceeds maximum length"
            );
        }

        return length;
    }

    /**
     * Decodes RDATA from a complete DNS message.
     *
     * offset identifies the beginning of RDATA.
     * rdLength specifies its encoded length.
     */
    public static Decoded decode(
            int type,
            byte[] message,
            int offset,
            int rdLength) {

        if (message == null) {
            throw new IllegalArgumentException(
                    "Message cannot be null"
            );
        }

        if (offset < 0 || rdLength < 0
                || offset > message.length
                || rdLength > message.length - offset) {
            throw new IllegalArgumentException(
                    "Invalid RDATA boundaries"
            );
        }

        int end = offset + rdLength;

        Object value;
        int position = offset;

        switch (type) {

            case TYPE_A -> {
                requireLength(rdLength, 4, "A");

                value = Arrays.copyOfRange(
                        message, offset, end
                );

                position = end;
            }

            case TYPE_AAAA -> {
                requireLength(rdLength, 16, "AAAA");

                value = Arrays.copyOfRange(
                        message, offset, end
                );

                position = end;
            }

            case TYPE_NS, TYPE_CNAME -> {
                DnsNameCodec.Decoded name =
                        DnsNameCodec.decode(message, offset);

                position = name.nextOffset();

                if (position != end) {
                    throw new IllegalArgumentException(
                            "Invalid NS/CNAME RDATA length"
                    );
                }

                value = name.name();
            }

            case TYPE_MX -> {
                requireMinimumLength(rdLength, 3, "MX");

                int preference =
                        readUnsignedShort(message, position);

                position += 2;

                DnsNameCodec.Decoded exchange =
                        DnsNameCodec.decode(message, position);

                position = exchange.nextOffset();

                if (position != end) {
                    throw new IllegalArgumentException(
                            "Invalid MX RDATA length"
                    );
                }

                value = new MxData(
                        preference,
                        exchange.name()
                );
            }

            case TYPE_SOA -> {
                DnsNameCodec.Decoded mname =
                        DnsNameCodec.decode(message, position);

                position = mname.nextOffset();

                if (position > end) {
                    throw new IllegalArgumentException(
                            "Invalid SOA MNAME"
                    );
                }

                DnsNameCodec.Decoded rname =
                        DnsNameCodec.decode(message, position);

                position = rname.nextOffset();

                if (position > end - 20) {
                    throw new IllegalArgumentException(
                            "Truncated SOA numeric fields"
                    );
                }

                long serial = readUnsignedInt(message, position);
                position += 4;

                long refresh = readUnsignedInt(message, position);
                position += 4;

                long retry = readUnsignedInt(message, position);
                position += 4;

                long expire = readUnsignedInt(message, position);
                position += 4;

                long minimum = readUnsignedInt(message, position);
                position += 4;

                if (position != end) {
                    throw new IllegalArgumentException(
                            "Invalid SOA RDATA length"
                    );
                }

                value = new SoaData(
                        mname.name(),
                        rname.name(),
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum
                );
            }

            case TYPE_TXT -> {
                if (rdLength == 0) {
                    throw new IllegalArgumentException(
                            "TXT RDATA cannot be empty"
                    );
                }

                List<String> strings = new ArrayList<>();

                while (position < end) {

                    int length = message[position++] & 0xFF;

                    if (length > end - position) {
                        throw new IllegalArgumentException(
                                "Truncated TXT character string"
                        );
                    }

                    strings.add(new String(
                            message,
                            position,
                            length,
                            StandardCharsets.UTF_8
                    ));

                    position += length;
                }

                value = List.copyOf(strings);
            }

            default -> throw new IllegalArgumentException(
                    "Unsupported DNS record type: " + type
            );
        }

        return new Decoded(value, position);
    }

    private static byte[] requireBytes(
            Object value, int expectedLength, String type) {

        if (!(value instanceof byte[] bytes)
                || bytes.length != expectedLength) {
            throw new IllegalArgumentException(
                    type + " requires exactly "
                            + expectedLength + " bytes"
            );
        }

        return bytes;
    }

    private static void requireLength(
            int actual, int expected, String type) {

        if (actual != expected) {
            throw new IllegalArgumentException(
                    type + " RDATA must be "
                            + expected + " bytes"
            );
        }
    }

    private static void requireMinimumLength(
            int actual, int minimum, String type) {

        if (actual < minimum) {
            throw new IllegalArgumentException(
                    "Truncated " + type + " RDATA"
            );
        }
    }

    private static void validateUnsignedInt(long value) {
        if (value < 0 || value > 0xFFFFFFFFL) {
            throw new IllegalArgumentException(
                    "Value must be an unsigned 32-bit integer"
            );
        }
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
}
