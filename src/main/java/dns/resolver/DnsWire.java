package dns.resolver;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.StringJoiner;

/**
 * Minimal DNS wire codec (RFC 1035) so this module runs standalone.
 * Member B's full codec replaces this at the integration boundary; the public surface
 * the resolver uses is: query(...), parse(...), Message, Record and the name helpers.
 */
final class DnsWire {
    private DnsWire() {}

    // Record types (RFC 1035 / RFC 3596) and class IN
    static final int A = 1, NS = 2, CNAME = 5, SOA = 6, MX = 15, TXT = 16, AAAA = 28, IN = 1;

    static final int MAX_LABEL_LENGTH = 63;
    static final int MAX_NAME_WIRE_LENGTH = 255;   // length bytes + labels + final root byte

    // ------------------------------------------------------------------ data types

    /** One resource record. Immutable; {@code data} is the RDATA rendered as text. */
    static final class Record {
    final String name, data;
    final int type, ttl;

    // Original Member B record, retained for cache storage.
    final dns.wire.DnsResourceRecord sourceRecord;

    Record(String name, int type, int ttl, String data) {
        this(name, type, ttl, data, null);
    }

    Record(
            String name,
            int type,
            int ttl,
            String data,
            dns.wire.DnsResourceRecord sourceRecord) {

        this.name = name;
        this.type = type;
        this.ttl = ttl;
        this.data = data;
        this.sourceRecord = sourceRecord;
    }

    @Override
    public String toString() {
        return name + " " + ttl + " IN "
                + typeName(type) + " " + data;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Record r
                && name.equalsIgnoreCase(r.name)
                && type == r.type
                && data.equals(r.data);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                name.toLowerCase(Locale.ROOT),
                type,
                data
        );
    }
}

    /** A decoded DNS message (header flags + the three record sections we use). */
    static final class Message {
        int id, rcode;
        boolean qr, truncated, authoritative;
        List<Record> answers = new ArrayList<>();
        List<Record> authority = new ArrayList<>();
        List<Record> additional = new ArrayList<>();

        Message copy() {
            Message x = new Message();
            x.id = id; x.rcode = rcode; x.qr = qr;
            x.truncated = truncated; x.authoritative = authoritative;
            x.answers = new ArrayList<>(answers);
            x.authority = new ArrayList<>(authority);
            x.additional = new ArrayList<>(additional);
            return x;
        }
    }

    // ------------------------------------------------------------------ names and types

    /** Makes a name absolute (trailing dot). Throws on an empty name. */
    static String absolute(String name) {
        String s = name.trim();
        if (s.isEmpty()) throw new IllegalArgumentException("Empty DNS name");
        return s.endsWith(".") ? s : s + ".";
    }

    /** True if {@code name} is {@code zone} itself or lies below it. Every name is in the root zone. */
    static boolean isSubdomain(String name, String zone) {
        String n = absolute(name).toLowerCase(Locale.ROOT);
        String z = absolute(zone).toLowerCase(Locale.ROOT);
        return z.equals(".") || n.equals(z) || n.endsWith("." + z);
    }

    static String typeName(int t) {
        return switch (t) {
            case A -> "A"; case NS -> "NS"; case CNAME -> "CNAME"; case SOA -> "SOA";
            case MX -> "MX"; case TXT -> "TXT"; case AAAA -> "AAAA";
            default -> "TYPE" + t;
        };
    }

    static int typeCode(String s) {
        return switch (s.toUpperCase(Locale.ROOT)) {
            case "A" -> A; case "NS" -> NS; case "CNAME" -> CNAME; case "SOA" -> SOA;
            case "MX" -> MX; case "TXT" -> TXT; case "AAAA" -> AAAA;
            default -> throw new IllegalArgumentException("Unsupported type: " + s);
        };
    }

    // ------------------------------------------------------------------ encoding

    /**
     * Encodes a name as length-prefixed labels ending in a zero byte.
     * The root name "." encodes as the single byte 0.
     * Rejects empty labels ("a..com"), labels over 63 bytes, non-ASCII characters
     * (use punycode "xn--" form) and names longer than 255 bytes on the wire.
     */
    static byte[] encodeName(String name) {
        String abs = absolute(name);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        if (!abs.equals(".")) {
            String body = abs.substring(0, abs.length() - 1);          // drop trailing dot
            for (String label : body.split("\\.", -1)) {               // -1 keeps empty labels
                if (label.isEmpty()) throw new IllegalArgumentException("Empty label in name: " + name);
                if (label.length() > MAX_LABEL_LENGTH) throw new IllegalArgumentException("DNS label too long: " + label);
                for (int i = 0; i < label.length(); i++)
                    if (label.charAt(i) > 127) throw new IllegalArgumentException("Non-ASCII name (use punycode xn--): " + name);
                out.write(label.length());
                out.writeBytes(label.getBytes(StandardCharsets.US_ASCII));
            }
        }
        out.write(0);                                                  // root label
        if (out.size() > MAX_NAME_WIRE_LENGTH) throw new IllegalArgumentException("DNS name longer than 255 bytes: " + name);
        return out.toByteArray();
    }

    /** Builds an iterative query: ID, flags all zero (RD=0), one question of class IN. */
    static byte[] query(int id, String name, int type) {
        byte[] qname = encodeName(name);
        ByteBuffer b = ByteBuffer.allocate(12 + qname.length + 4);
        b.putShort((short) id);
        b.putShort((short) 0);          // flags: standard query, recursion NOT desired
        b.putShort((short) 1);          // QDCOUNT
        b.putShort((short) 0);          // ANCOUNT
        b.putShort((short) 0);          // NSCOUNT
        b.putShort((short) 0);          // ARCOUNT
        b.put(qname);
        b.putShort((short) type);
        b.putShort((short) IN);
        return b.array();
    }

    // ------------------------------------------------------------------ decoding

    static Message parse(byte[] p) throws IOException {
        if (p.length < 12) throw new IOException("DNS packet shorter than header");
        Message m = new Message();
        int flags = u16(p, 2);
        int qd = u16(p, 4), an = u16(p, 6), ns = u16(p, 8), ar = u16(p, 10);
        m.id = u16(p, 0);
        m.qr = (flags & 0x8000) != 0;
        m.authoritative = (flags & 0x0400) != 0;
        m.truncated = (flags & 0x0200) != 0;
        m.rcode = flags & 0x000F;

        int[] pos = {12};                                   // read cursor, shared with helpers
        for (int i = 0; i < qd; i++) {                      // skip the echoed question(s)
            readName(p, pos);
            need(p, pos[0], 4);                             // QTYPE + QCLASS
            pos[0] += 4;
        }
        readRecords(p, pos, an, m.answers);
        readRecords(p, pos, ns, m.authority);
        readRecords(p, pos, ar, m.additional);
        return m;
    }

    private static void readRecords(byte[] p, int[] pos, int count, List<Record> out) throws IOException {
        for (int i = 0; i < count; i++) {
            String name = readName(p, pos);
            need(p, pos[0], 10);
            int type = u16(p, pos[0]);
            int clazz = u16(p, pos[0] + 2);
            long ttl = u32(p, pos[0] + 4);
            int len = u16(p, pos[0] + 8);
            pos[0] += 10;
            need(p, pos[0], len);
            int start = pos[0], end = start + len;
            pos[0] = end;                                   // always advance past RDATA

            if (clazz != IN) continue;                      // ignore non-IN records (e.g. OPT)
            // RFC 2181 section 8: a TTL with the top bit set must be treated as 0.
            int safeTtl = ttl > Integer.MAX_VALUE ? 0 : (int) ttl;
            out.add(new Record(name, type, safeTtl, readRdata(p, type, start, end)));
        }
    }

    /** Decodes RDATA for the seven supported types; others become an opaque placeholder. */
    private static String readRdata(byte[] p, int type, int start, int end) throws IOException {
        int len = end - start;
        switch (type) {
            case A: {
                if (len != 4) throw new IOException("Malformed A RDATA");
                return (p[start] & 255) + "." + (p[start + 1] & 255) + "." + (p[start + 2] & 255) + "." + (p[start + 3] & 255);
            }
            case AAAA: {
                if (len != 16) throw new IOException("Malformed AAAA RDATA");
                return InetAddress.getByAddress(Arrays.copyOfRange(p, start, end)).getHostAddress();
            }
            case NS:
            case CNAME: {
                int[] q = {start};
                String target = readName(p, q);
                requireEnd(q[0], end, typeName(type));
                return target;
            }
            case MX: {
                if (len < 3) throw new IOException("Malformed MX RDATA");
                int pref = u16(p, start);
                int[] q = {start + 2};
                String exchange = readName(p, q);
                requireEnd(q[0], end, "MX");
                return pref + " " + exchange;
            }
            case TXT: {
                StringJoiner parts = new StringJoiner(" ");
                int q = start;
                while (q < end) {                           // sequence of length-prefixed strings
                    int l = p[q++] & 255;
                    if (q + l > end) throw new IOException("Malformed TXT RDATA");
                    parts.add("\"" + new String(p, q, l, StandardCharsets.UTF_8) + "\"");
                    q += l;
                }
                return parts.toString();
            }
            case SOA: {
                int[] q = {start};
                String mname = readName(p, q);
                String rname = readName(p, q);
                need(p, q[0], 20);                          // serial, refresh, retry, expire, minimum
                requireEnd(q[0] + 20, end, "SOA");
                return mname + " " + rname + " " + u32(p, q[0]) + " " + u32(p, q[0] + 4) + " "
                        + u32(p, q[0] + 8) + " " + u32(p, q[0] + 12) + " " + u32(p, q[0] + 16);
            }
            default:
                return "\\# " + len + " (unsupported RDATA)";
        }
    }

    /**
     * Reads a (possibly compressed) domain name starting at {@code offset[0]} and leaves
     * {@code offset[0]} just after the name as it appears at that position.
     *
     * Safeguards against hostile packets:
     *  - a compression pointer must point strictly BACKWARDS (to an earlier name),
     *  - at most 127 pointer jumps (defence in depth against cycles),
     *  - decoded name may not exceed 255 bytes on the wire,
     *  - every read is bounds-checked.
     */
    static String readName(byte[] p, int[] offset) throws IOException {
        StringBuilder name = new StringBuilder();
        int cursor = offset[0];
        int resume = -1;        // where to continue after the first pointer jump
        int wireLength = 1;     // starts at 1 for the terminating root byte
        int jumps = 0;
        while (true) {
            need(p, cursor, 1);
            int len = p[cursor] & 0xFF;
            if ((len & 0xC0) == 0xC0) {                     // compression pointer: 11xxxxxx xxxxxxxx
                need(p, cursor, 2);
                int target = ((len & 0x3F) << 8) | (p[cursor + 1] & 0xFF);
                if (target >= cursor) throw new IOException("Compression pointer must point backwards");
                if (resume < 0) resume = cursor + 2;
                if (++jumps > 127) throw new IOException("Compression pointer loop");
                cursor = target;
                continue;
            }
            if ((len & 0xC0) != 0) throw new IOException("Invalid DNS label type");
            cursor++;
            if (len == 0) {                                 // root label: end of name
                offset[0] = resume >= 0 ? resume : cursor;
                return name.length() == 0 ? "." : name + ".";
            }
            need(p, cursor, len);
            wireLength += len + 1;
            if (wireLength > MAX_NAME_WIRE_LENGTH) throw new IOException("DNS name exceeds 255 bytes");
            if (name.length() > 0) name.append('.');
            name.append(new String(p, cursor, len, StandardCharsets.US_ASCII));
            cursor += len;
        }
    }

    // ------------------------------------------------------------------ helpers

    private static void requireEnd(int actual, int expected, String what) throws IOException {
        if (actual != expected) throw new IOException("Malformed " + what + " RDATA (length mismatch)");
    }

    static int u16(byte[] b, int p) {
        return ((b[p] & 255) << 8) | (b[p + 1] & 255);
    }

    static long u32(byte[] b, int p) {
        return ((long) (b[p] & 255) << 24) | ((long) (b[p + 1] & 255) << 16)
                | ((long) (b[p + 2] & 255) << 8) | (b[p + 3] & 255L);
    }

    static void need(byte[] b, int pos, int n) throws IOException {
        if (pos < 0 || n < 0 || pos + n > b.length) throw new IOException("Truncated DNS packet");
    }
}
