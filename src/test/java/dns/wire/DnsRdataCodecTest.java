
package dns.wire;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DnsRdataCodecTest {

    private DnsRdataCodec.Decoded roundTrip(
            int type, Object value) {

        ByteArrayOutputStream output =
                new ByteArrayOutputStream();

        Map<String, Integer> compressionMap =
                new HashMap<>();

        int length = DnsRdataCodec.encode(
                type, value, output, compressionMap
        );

        return DnsRdataCodec.decode(
                type, output.toByteArray(), 0, length
        );
    }

    @Test
    void testARecord() {

        byte[] address = {
                (byte) 192, (byte) 168, 1, 1
        };

        assertArrayEquals(
                address,
                (byte[]) roundTrip(
                        DnsRdataCodec.TYPE_A,
                        address
                ).value()
        );
    }

    @Test
    void testAAAARecord() {

        byte[] address = new byte[16];

        address[0] = 0x20;
        address[1] = 0x01;

        assertArrayEquals(
                address,
                (byte[]) roundTrip(
                        DnsRdataCodec.TYPE_AAAA,
                        address
                ).value()
        );
    }

    @Test
    void testNSRecord() {

        assertEquals(
                "ns1.example.com",
                roundTrip(
                        DnsRdataCodec.TYPE_NS,
                        "ns1.example.com"
                ).value()
        );
    }

    @Test
    void testCNAMERecord() {

        assertEquals(
                "target.example.com",
                roundTrip(
                        DnsRdataCodec.TYPE_CNAME,
                        "target.example.com"
                ).value()
        );
    }

    @Test
    void testMXRecord() {

        DnsRdataCodec.MxData mx =
                new DnsRdataCodec.MxData(
                        10, "mail.example.com"
                );

        assertEquals(mx, roundTrip(
                DnsRdataCodec.TYPE_MX, mx
        ).value());
    }

    @Test
    void testSOARecord() {

        DnsRdataCodec.SoaData soa =
                new DnsRdataCodec.SoaData(
                        "ns.example.com",
                        "admin.example.com",
                        2026110401L,
                        3600,
                        600,
                        1209600,
                        300
                );

        assertEquals(soa, roundTrip(
                DnsRdataCodec.TYPE_SOA, soa
        ).value());
    }

    @Test
    void testTXTRecord() {

        List<String> strings = List.of(
                "Hello",
                "DNS Resolver",
                "Testing"
        );

        assertEquals(strings, roundTrip(
                DnsRdataCodec.TYPE_TXT,
                strings
        ).value());
    }

    @Test
    void testRejectInvalidARecordLength() {

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsRdataCodec.encode(
                        DnsRdataCodec.TYPE_A,
                        new byte[]{1, 2, 3},
                        new ByteArrayOutputStream(),
                        new HashMap<>()
                )
        );
    }

    @Test
    void testRejectTruncatedAAAARecord() {

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsRdataCodec.decode(
                        DnsRdataCodec.TYPE_AAAA,
                        new byte[8],
                        0,
                        8
                )
        );
    }

    @Test
    void testRejectTruncatedTXTRecord() {

        byte[] data = {
                0x05, 'H', 'i'
        };

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsRdataCodec.decode(
                        DnsRdataCodec.TYPE_TXT,
                        data, 0, data.length
                )
        );
    }
}
