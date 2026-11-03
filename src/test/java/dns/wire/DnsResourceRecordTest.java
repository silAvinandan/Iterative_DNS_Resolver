
package dns.wire;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DnsResourceRecordTest {

    @Test
    void testARecordEncoding() {

        byte[] ipAddress = {
                (byte) 142, (byte) 250,
                (byte) 183, 14
        };

        DnsResourceRecord record = new DnsResourceRecord(
                "google.com",
                DnsResourceRecord.TYPE_A,
                DnsResourceRecord.CLASS_IN,
                300,
                ipAddress
        );

        byte[] encoded = record.toBytes();

        assertEquals(26, encoded.length);

        // The RDATA begins after the 12-byte owner name
        // and the 10-byte fixed RR header.
        assertEquals(0x00, encoded[12] & 0xFF);
        assertEquals(0x01, encoded[13] & 0xFF);
        assertEquals(0x00, encoded[20] & 0xFF);
        assertEquals(0x04, encoded[21] & 0xFF);
    }

    @Test
    void testRecordDecoding() {

        byte[] data = {
                0x06, 'g', 'o', 'o', 'g', 'l', 'e',
                0x03, 'c', 'o', 'm', 0x00,

                0x00, 0x01,
                0x00, 0x01,

                0x00, 0x00, 0x01, 0x2C,

                0x00, 0x04,

                (byte) 142, (byte) 250,
                (byte) 183, 14
        };

        DnsResourceRecord.Decoded decoded =
                DnsResourceRecord.decode(data, 0);

        DnsResourceRecord record = decoded.record();

        assertEquals("google.com", record.getName());
        assertEquals(1, record.getType());
        assertEquals(1, record.getRecordClass());
        assertEquals(300, record.getTtl());

        assertArrayEquals(
                new byte[]{
                        (byte) 142, (byte) 250,
                        (byte) 183, 14
                },
                record.getRdata()
        );

        assertEquals(data.length, decoded.nextOffset());
    }

    @Test
    void testRecordRoundTrip() {

        DnsResourceRecord original = new DnsResourceRecord(
                "example.com",
                DnsResourceRecord.TYPE_AAAA,
                DnsResourceRecord.CLASS_IN,
                3600,
                new byte[16]
        );

        DnsResourceRecord decoded =
                DnsResourceRecord.decode(
                        original.toBytes(), 0
                ).record();

        assertEquals(original.getName(), decoded.getName());
        assertEquals(original.getType(), decoded.getType());
        assertEquals(original.getRecordClass(),
                decoded.getRecordClass());
        assertEquals(original.getTtl(), decoded.getTtl());

        assertArrayEquals(
                original.getRdata(),
                decoded.getRdata()
        );
    }

    @Test
    void testMaximumTtl() {

        DnsResourceRecord record = new DnsResourceRecord(
                "example.com",
                1,
                1,
                4294967295L,
                new byte[]{1, 2, 3, 4}
        );

        DnsResourceRecord decoded =
                DnsResourceRecord.decode(
                        record.toBytes(), 0
                ).record();

        assertEquals(4294967295L, decoded.getTtl());
    }

    @Test
    void testEmptyRootDomain() {

        DnsResourceRecord record = new DnsResourceRecord(
                ".",
                1,
                1,
                60,
                new byte[]{1, 2, 3, 4}
        );

        DnsResourceRecord decoded =
                DnsResourceRecord.decode(
                        record.toBytes(), 0
                ).record();

        assertEquals("", decoded.getName());
    }

    @Test
    void testRejectInvalidTtl() {

        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsResourceRecord(
                        "example.com", 1, 1,
                        -1, new byte[4]
                )
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsResourceRecord(
                        "example.com", 1, 1,
                        4294967296L, new byte[4]
                )
        );
    }

    @Test
    void testRejectNullRdata() {

        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsResourceRecord(
                        "example.com", 1, 1,
                        300, null
                )
        );
    }

    @Test
    void testRejectTruncatedRdata() {

        byte[] incomplete = {
                0x03, 'w', 'w', 'w', 0x00,
                0x00, 0x01,
                0x00, 0x01,
                0x00, 0x00, 0x00, 0x3C,
                0x00, 0x04,
                0x01, 0x02
        };

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsResourceRecord.decode(incomplete, 0)
        );
    }
}
