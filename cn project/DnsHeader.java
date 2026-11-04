package dns.transport;

/**
 * The transport layer deliberately understands ONLY the 12-byte DNS header
 * (ID, QR, TC). Everything else is Member B's codec's job.
 */
final class DnsHeader {
    private DnsHeader() {}

    static int id(byte[] b) { return ((b[0] & 0xFF) << 8) | (b[1] & 0xFF); }

    static boolean isResponse(byte[] b, int len) { return len >= 12 && (b[2] & 0x80) != 0; }

    static boolean isTruncated(byte[] b) { return (b[2] & 0x02) != 0; }

    /** A reply is acceptable only if it is a response AND echoes our query ID. */
    static boolean isValidResponse(byte[] b, int len, int expectedId) {
        return isResponse(b, len) && id(b) == expectedId;
    }
}
