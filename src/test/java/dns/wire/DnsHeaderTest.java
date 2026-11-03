
package dns.wire;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DnsHeaderTest {

    @Test
    void testHeaderEncoding() {

        DnsHeader header = new DnsHeader(
                1234, 0x0100, 1, 0, 0, 0
        );

        byte[] expected = {
                0x04, (byte) 0xD2,
                0x01, 0x00,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00
        };

        assertArrayEquals(expected, header.toBytes());
    }

    @Test
    void testHeaderDecoding() {

        byte[] data = {
                0x04, (byte) 0xD2,
                0x01, 0x00,
                0x00, 0x01,
                0x00, 0x02,
                0x00, 0x03,
                0x00, 0x04
        };

        DnsHeader header = DnsHeader.fromBytes(data);

        assertEquals(1234, header.getId());
        assertEquals(0x0100, header.getFlags());
        assertEquals(1, header.getQdCount());
        assertEquals(2, header.getAnCount());
        assertEquals(3, header.getNsCount());
        assertEquals(4, header.getArCount());
    }

    @Test
    void testEncodingAndDecodingRoundTrip() {

        DnsHeader original = new DnsHeader(
                54321, 0x8180, 2, 3, 4, 5
        );

        byte[] encoded = original.toBytes();

        DnsHeader decoded = DnsHeader.fromBytes(encoded);

        assertEquals(original.getId(), decoded.getId());
        assertEquals(original.getFlags(), decoded.getFlags());
        assertEquals(original.getQdCount(), decoded.getQdCount());
        assertEquals(original.getAnCount(), decoded.getAnCount());
        assertEquals(original.getNsCount(), decoded.getNsCount());
        assertEquals(original.getArCount(), decoded.getArCount());
    }

    @Test
    void testHeaderLength() {

        DnsHeader header = new DnsHeader(
                100, 0, 1, 0, 0, 0
        );

        assertEquals(12, header.toBytes().length);
    }

    @Test
    void testDecodingWithOffset() {

        byte[] data = {
                0x55, 0x66,
                0x04, (byte) 0xD2,
                0x01, 0x00,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00
        };

        DnsHeader header = DnsHeader.fromBytes(data, 2);

        assertEquals(1234, header.getId());
        assertEquals(1, header.getQdCount());
    }

    @Test
    void testRejectInvalidId() {

        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsHeader(-1, 0, 0, 0, 0, 0)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsHeader(65536, 0, 0, 0, 0, 0)
        );
    }

    @Test
    void testRejectTruncatedHeader() {

        byte[] incomplete = new byte[11];

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsHeader.fromBytes(incomplete)
        );
    }

    @Test
    void testRejectNullInput() {

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsHeader.fromBytes(null)
        );
    }
}
