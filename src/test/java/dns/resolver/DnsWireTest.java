package dns.resolver;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.junit.jupiter.api.Test;

/** Codec tests on hand-built packets: encoding limits, compression pointers, malformed RDATA. */
class DnsWireTest {

    // ---- packet builder: header + question "example.com A IN", then caller-appended records

    static final class Pkt {
        final ByteArrayOutputStream b = new ByteArrayOutputStream();
        Pkt(int flags, int an, int ns, int ar) {
            u16(0x1234); u16(flags); u16(1); u16(an); u16(ns); u16(ar);
            raw(7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0);   // question name at offset 12
            u16(1); u16(1);
        }
        Pkt u16(int v) { b.write(v >> 8); b.write(v); return this; }
        Pkt u32(long v) { u16((int) (v >> 16) & 0xFFFF); u16((int) v & 0xFFFF); return this; }
        Pkt raw(int... bytes) { for (int x : bytes) b.write(x); return this; }
        /** Record header with name = pointer to offset 12 ("example.com"). */
        Pkt rr(int type, long ttl, int rdlen) { raw(0xC0, 12); u16(type); u16(1); u32(ttl); u16(rdlen); return this; }
        byte[] bytes() { return b.toByteArray(); }
    }

    // ---- encoding

    @Test void encodesExampleComQueryExactly() {
        byte[] q = DnsWire.query(0x1234, "example.com", DnsWire.A);
        StringBuilder hex = new StringBuilder();
        for (byte x : q) hex.append(String.format("%02x", x));
        assertEquals("123400000001000000000000076578616d706c6503636f6d0000010001", hex.toString());
    }

    @Test void queryHasRecursionDesiredClear() {
        byte[] q = DnsWire.query(1, "example.com", DnsWire.A);
        assertEquals(0, q[2]);
        assertEquals(0, q[3]);
    }

    @Test void rootNameEncodesAsSingleZeroByte() {
        assertArrayEquals(new byte[] {0}, DnsWire.encodeName("."));
        assertEquals(12 + 1 + 4, DnsWire.query(1, ".", DnsWire.NS).length);
    }

    @Test void rejectsEmptyLabels() {
        assertThrows(IllegalArgumentException.class, () -> DnsWire.encodeName("a..com"));
        assertThrows(IllegalArgumentException.class, () -> DnsWire.encodeName(".com"));
        assertThrows(IllegalArgumentException.class, () -> DnsWire.encodeName(".."));
    }

    @Test void rejectsOverlongLabelButAcceptsMax() {
        assertEquals(63, DnsWire.encodeName("a".repeat(63) + ".com")[0]);
        assertThrows(IllegalArgumentException.class, () -> DnsWire.encodeName("a".repeat(64) + ".com"));
    }

    @Test void enforces255ByteNameLimit() {
        String ok = ("a".repeat(63) + ".").repeat(3) + "a".repeat(61);       // 3*64 + 62 + 1 = 255
        assertEquals(255, DnsWire.encodeName(ok).length);
        String tooLong = ("a".repeat(63) + ".").repeat(3) + "a".repeat(62);  // 256
        assertThrows(IllegalArgumentException.class, () -> DnsWire.encodeName(tooLong));
    }

    @Test void rejectsNonAsciiNames() {
        assertThrows(IllegalArgumentException.class, () -> DnsWire.encodeName("bücher.example"));
    }

    @Test void isSubdomainHandlesRootAndLabelBoundaries() {
        assertTrue(DnsWire.isSubdomain("example.com.", "."));
        assertTrue(DnsWire.isSubdomain("www.example.com.", "example.com."));
        assertTrue(DnsWire.isSubdomain("EXAMPLE.com", "example.COM."));
        assertFalse(DnsWire.isSubdomain("badexample.com.", "example.com."));
    }

    // ---- decoding: all seven record types

    @Test void parsesARecordWithCompressedName() throws Exception {
        byte[] p = new Pkt(0x8400, 1, 0, 0).rr(1, 60, 4).raw(1, 2, 3, 4).bytes();
        DnsWire.Message m = DnsWire.parse(p);
        assertTrue(m.qr);
        assertTrue(m.authoritative);
        assertEquals("example.com.", m.answers.get(0).name);
        assertEquals("1.2.3.4", m.answers.get(0).data);
        assertEquals(60, m.answers.get(0).ttl);
    }

    @Test void parsesAAAA() throws Exception {
        int[] addr = new int[16]; addr[0] = 0x20; addr[1] = 0x01; addr[2] = 0x0d; addr[3] = 0xb8; addr[15] = 1;
        byte[] p = new Pkt(0x8400, 1, 0, 0).rr(28, 60, 16).raw(addr).bytes();
        assertEquals("2001:db8:0:0:0:0:0:1", DnsWire.parse(p).answers.get(0).data);
    }

    @Test void parsesNsAndCnameWithPointerInRdata() throws Exception {
        // RDATA = "ns1" + pointer to example.com (offset 12)
        byte[] p = new Pkt(0x8400, 2, 0, 0)
                .rr(2, 300, 6).raw(3, 'n', 's', '1', 0xC0, 12)
                .rr(5, 300, 6).raw(3, 'w', 'w', 'w', 0xC0, 12).bytes();
        DnsWire.Message m = DnsWire.parse(p);
        assertEquals("ns1.example.com.", m.answers.get(0).data);
        assertEquals("www.example.com.", m.answers.get(1).data);
    }

    @Test void parsesMx() throws Exception {
        byte[] p = new Pkt(0x8400, 1, 0, 0).rr(15, 300, 2 + 1 + 4 + 2).u16(10).raw(4, 'm', 'a', 'i', 'l', 0xC0, 12).bytes();
        assertEquals("10 mail.example.com.", DnsWire.parse(p).answers.get(0).data);
    }

    @Test void parsesTxtWithMultipleStrings() throws Exception {
        byte[] p = new Pkt(0x8400, 1, 0, 0).rr(16, 300, 1 + 2 + 1 + 3).raw(2, 'h', 'i', 3, 'y', 'o', 'u').bytes();
        assertEquals("\"hi\" \"you\"", DnsWire.parse(p).answers.get(0).data);
    }

    @Test void parsesSoaInAuthoritySection() throws Exception {
        Pkt k = new Pkt(0x8400, 0, 1, 0);
        // mname "ns" + ptr, rname "h" + ptr, then 5 x u32
        k.rr(6, 300, 5 + 4 + 20).raw(2, 'n', 's', 0xC0, 12).raw(1, 'h', 0xC0, 12)
         .u32(2024).u32(3600).u32(600).u32(86400).u32(300);
        DnsWire.Record soa = DnsWire.parse(k.bytes()).authority.get(0);
        assertEquals(DnsWire.SOA, soa.type);
        assertEquals("ns.example.com. h.example.com. 2024 3600 600 86400 300", soa.data);
    }

    @Test void unknownTypesBecomeOpaquePlaceholder() throws Exception {
        byte[] p = new Pkt(0x8400, 1, 0, 0).rr(99, 60, 3).raw(1, 2, 3).bytes();
        assertTrue(DnsWire.parse(p).answers.get(0).data.contains("unsupported"));
    }

    @Test void nonInClassRecordsAreSkipped() throws Exception {
        Pkt k = new Pkt(0x8400, 1, 0, 0);
        k.raw(0xC0, 12).u16(1).u16(3 /* CH */).u32(60).u16(4).raw(1, 2, 3, 4);
        assertTrue(DnsWire.parse(k.bytes()).answers.isEmpty());
    }

    @Test void ttlWithTopBitSetIsTreatedAsZero() throws Exception {      // RFC 2181 section 8
        byte[] p = new Pkt(0x8400, 1, 0, 0).rr(1, 0x80000000L, 4).raw(1, 2, 3, 4).bytes();
        assertEquals(0, DnsWire.parse(p).answers.get(0).ttl);
    }

    @Test void parsesFlagsAndRcode() throws Exception {
        DnsWire.Message m = DnsWire.parse(new Pkt(0x8203, 0, 0, 0).bytes());   // QR, TC, RCODE=3
        assertTrue(m.qr);
        assertTrue(m.truncated);
        assertFalse(m.authoritative);
        assertEquals(3, m.rcode);
    }

    // ---- decoding: malformed / hostile packets

    @Test void rejectsPacketShorterThanHeader() {
        assertThrows(IOException.class, () -> DnsWire.parse(new byte[5]));
    }

    @Test void rejectsTruncatedRecord() {
        byte[] full = new Pkt(0x8400, 1, 0, 0).rr(1, 60, 4).raw(1, 2, 3, 4).bytes();
        for (int cut = 1; cut < 10; cut++) {                       // chop bytes off the end
            byte[] shorter = java.util.Arrays.copyOf(full, full.length - cut);
            assertThrows(IOException.class, () -> DnsWire.parse(shorter));
        }
    }

    @Test void rejectsSelfReferencingPointer() {
        byte[] p = {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, (byte) 0xC0, 12, 0, 1, 0, 1};
        assertThrows(IOException.class, () -> DnsWire.parse(p));
    }

    @Test void rejectsForwardPointer() {
        // question name = pointer to offset 16 (ahead of itself)
        byte[] p = {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, (byte) 0xC0, 16, 0, 1, 0, 1, 0, 0};
        assertThrows(IOException.class, () -> DnsWire.parse(p));
    }

    @Test void rejectsPointerPastEndOfPacket() {
        byte[] p = {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, (byte) 0xC3, (byte) 0xFF, 0, 1, 0, 1};
        assertThrows(IOException.class, () -> DnsWire.parse(p));
    }

    @Test void rejectsPointerCycleBetweenTwoNames() {
        // offset 12: label "a" then pointer to 12 -> reading forward from 12 hits the pointer at 14 -> back to 12 ...
        byte[] p = {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', (byte) 0xC0, 12, 0, 1, 0, 1};
        assertThrows(IOException.class, () -> DnsWire.parse(p));
    }

    @Test void rejectsReservedLabelType() {
        byte[] p = {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, (byte) 0x80, 0, 0, 1, 0, 1};
        assertThrows(IOException.class, () -> DnsWire.parse(p));
    }

    @Test void rejectsNameLongerThan255InPacket() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0); o.write(1); o.write(0); o.write(0); o.write(0); o.write(1);
        for (int i = 0; i < 6; i++) o.write(0);
        for (int i = 0; i < 5; i++) { o.write(63); for (int j = 0; j < 63; j++) o.write('a'); }  // 320 bytes of labels
        o.write(0); o.write(0); o.write(1); o.write(0); o.write(1);
        assertThrows(IOException.class, () -> DnsWire.parse(o.toByteArray()));
    }

    @Test void rejectsBadARdataLength() {
        byte[] p = new Pkt(0x8400, 1, 0, 0).rr(1, 60, 3).raw(1, 2, 3).bytes();
        assertThrows(IOException.class, () -> DnsWire.parse(p));
    }

    @Test void rejectsBadAaaaRdataLength() {
        byte[] p = new Pkt(0x8400, 1, 0, 0).rr(28, 60, 4).raw(1, 2, 3, 4).bytes();
        assertThrows(IOException.class, () -> DnsWire.parse(p));
    }

    @Test void rejectsRdataLengthShorterThanItsName() {
        // declares RDLENGTH 2 but the name inside is longer (3+'ns1'+ptr = 6 bytes)
        byte[] p = new Pkt(0x8400, 1, 0, 0).rr(2, 300, 2).raw(3, 'n', 's', '1', 0xC0, 12).bytes();
        assertThrows(IOException.class, () -> DnsWire.parse(p));
    }

    @Test void rejectsTxtStringRunningPastRdata() {
        byte[] p = new Pkt(0x8400, 1, 0, 0).rr(16, 300, 3).raw(9, 'h', 'i').bytes();
        assertThrows(IOException.class, () -> DnsWire.parse(p));
    }

    @Test void rejectsRecordCountLargerThanPacket() {
        byte[] p = new Pkt(0x8400, 5000, 0, 0).bytes();
        assertThrows(IOException.class, () -> DnsWire.parse(p));
    }
}
