
package dns.wire;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DnsResourceRecordTypedTest {

    private DnsResourceRecord roundTrip(
            int type, Object value) {

        DnsResourceRecord original =
                DnsResourceRecord.fromTypedData(
                        "example.com",
                        type,
                        DnsResourceRecord.CLASS_IN,
                        300,
                        value
                );

        byte[] encoded = original.toBytes();

        DnsResourceRecord.Decoded decoded =
                DnsResourceRecord.decodeTyped(
                        encoded, 0
                );

        return decoded.record();
    }

    @Test
    void testTypedARecord() {

        byte[] address = {
                (byte) 192, (byte) 168, 1, 1
        };

        DnsResourceRecord record = roundTrip(
                DnsResourceRecord.TYPE_A, address
        );

        assertArrayEquals(
                address,
                (byte[]) record.getRdataValue()
        );
    }

    @Test
    void testTypedAAAARecord() {

        byte[] address = new byte[16];

        address[0] = 0x20;
        address[1] = 0x01;

        DnsResourceRecord record = roundTrip(
                DnsResourceRecord.TYPE_AAAA, address
        );

        assertArrayEquals(
                address,
                (byte[]) record.getRdataValue()
        );
    }

    @Test
    void testTypedNSRecord() {

        DnsResourceRecord record = roundTrip(
                DnsResourceRecord.TYPE_NS,
                "ns1.example.com"
        );

        assertEquals(
                "ns1.example.com",
                record.getRdataValue()
        );
    }

    @Test
    void testTypedCNAMERecord() {

        DnsResourceRecord record = roundTrip(
                DnsResourceRecord.TYPE_CNAME,
                "target.example.com"
        );

        assertEquals(
                "target.example.com",
                record.getRdataValue()
        );
    }

    @Test
    void testTypedMXRecord() {

        DnsRdataCodec.MxData mx =
                new DnsRdataCodec.MxData(
                        10,
                        "mail.example.com"
                );

        DnsResourceRecord record = roundTrip(
                DnsResourceRecord.TYPE_MX, mx
        );

        assertEquals(mx, record.getRdataValue());
    }

    @Test
    void testTypedSOARecord() {

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

        DnsResourceRecord record = roundTrip(
                DnsResourceRecord.TYPE_SOA, soa
        );

        assertEquals(soa, record.getRdataValue());
    }

    @Test
    void testTypedTXTRecord() {

        List<String> strings = List.of(
                "Hello",
                "DNS Resolver",
                "Testing"
        );

        DnsResourceRecord record = roundTrip(
                DnsResourceRecord.TYPE_TXT, strings
        );

        assertEquals(strings, record.getRdataValue());
    }

    @Test
    void testRecordMetadata() {

        DnsResourceRecord record = roundTrip(
                DnsResourceRecord.TYPE_A,
                new byte[]{1, 2, 3, 4}
        );

        assertEquals("example.com", record.getName());
        assertEquals(1, record.getType());
        assertEquals(1, record.getRecordClass());
        assertEquals(300, record.getTtl());
    }

    @Test
    void testRawRdataCompatibility() {

        byte[] address = {8, 8, 8, 8};

        DnsResourceRecord original =
                new DnsResourceRecord(
                        "example.com",
                        DnsResourceRecord.TYPE_A,
                        DnsResourceRecord.CLASS_IN,
                        300,
                        address
                );

        DnsResourceRecord.Decoded decoded =
                DnsResourceRecord.decode(
                        original.toBytes(), 0
                );

        assertArrayEquals(
                address,
                decoded.record().getRdata()
        );
    }

    @Test
    void testSharedCompressionForTypedRecords() {

        ByteArrayOutputStream message =
                new ByteArrayOutputStream();

        message.writeBytes(new byte[12]);

        Map<String, Integer> compressionMap =
                new HashMap<>();

        DnsQuestion question = new DnsQuestion(
                "example.com",
                DnsQuestion.TYPE_A,
                DnsQuestion.CLASS_IN
        );

        question.encodeTo(message, compressionMap);

        DnsResourceRecord cname =
                DnsResourceRecord.fromTypedData(
                        "example.com",
                        DnsResourceRecord.TYPE_CNAME,
                        DnsResourceRecord.CLASS_IN,
                        300,
                        "target.example.com"
                );

        cname.encodeTo(message, compressionMap);

        DnsResourceRecord.Decoded decoded =
                DnsResourceRecord.decodeTyped(
                        message.toByteArray(),
                        29
                );

        assertEquals(
                "example.com",
                decoded.record().getName()
        );

        assertEquals(
                "target.example.com",
                decoded.record().getRdataValue()
        );
    }
}
