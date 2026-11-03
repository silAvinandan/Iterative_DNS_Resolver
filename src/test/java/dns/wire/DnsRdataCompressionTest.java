
package dns.wire;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DnsRdataCompressionTest {

    private void writeQuestion(
            ByteArrayOutputStream message,
            Map<String, Integer> map) {

        DnsQuestion question = new DnsQuestion(
                "example.com",
                DnsQuestion.TYPE_A,
                DnsQuestion.CLASS_IN
        );

        question.encodeTo(message, map);
    }

    private DnsResourceRecord decodeAnswer(
            ByteArrayOutputStream message) {

        byte[] packet = message.toByteArray();

        DnsQuestion.Decoded question =
                DnsQuestion.decode(packet, 12);

        return DnsResourceRecord.decodeTyped(
                packet, question.nextOffset()
        ).record();
    }

    @Test
    void testCompressedNSRecord() {

        ByteArrayOutputStream message =
                new ByteArrayOutputStream();

        message.writeBytes(new byte[12]);

        Map<String, Integer> map = new HashMap<>();

        writeQuestion(message, map);

        DnsResourceRecord record =
                DnsResourceRecord.fromTypedData(
                        "example.com",
                        DnsResourceRecord.TYPE_NS,
                        1, 300,
                        "example.com"
                );

        record.encodeTo(message, map);

        DnsResourceRecord decoded =
                decodeAnswer(message);

        assertEquals(
                "example.com",
                decoded.getRdataValue()
        );
    }

    @Test
    void testCompressedCNAMERecord() {

        ByteArrayOutputStream message =
                new ByteArrayOutputStream();

        message.writeBytes(new byte[12]);

        Map<String, Integer> map = new HashMap<>();

        writeQuestion(message, map);

        DnsResourceRecord record =
                DnsResourceRecord.fromTypedData(
                        "example.com",
                        DnsResourceRecord.TYPE_CNAME,
                        1, 300,
                        "example.com"
                );

        record.encodeTo(message, map);

        DnsResourceRecord decoded =
                decodeAnswer(message);

        assertEquals(
                "example.com",
                decoded.getRdataValue()
        );
    }

    @Test
    void testCompressedMXRecord() {

        ByteArrayOutputStream message =
                new ByteArrayOutputStream();

        message.writeBytes(new byte[12]);

        Map<String, Integer> map = new HashMap<>();

        writeQuestion(message, map);

        DnsRdataCodec.MxData mx =
                new DnsRdataCodec.MxData(
                        10, "example.com"
                );

        DnsResourceRecord record =
                DnsResourceRecord.fromTypedData(
                        "example.com",
                        DnsResourceRecord.TYPE_MX,
                        1, 300, mx
                );

        record.encodeTo(message, map);

        DnsResourceRecord decoded =
                decodeAnswer(message);

        assertEquals(mx, decoded.getRdataValue());
    }

    @Test
    void testCompressedSOARecord() {

        ByteArrayOutputStream message =
                new ByteArrayOutputStream();

        message.writeBytes(new byte[12]);

        Map<String, Integer> map = new HashMap<>();

        writeQuestion(message, map);

        DnsRdataCodec.SoaData soa =
                new DnsRdataCodec.SoaData(
                        "example.com",
                        "example.com",
                        100, 200, 300, 400, 500
                );

        DnsResourceRecord record =
                DnsResourceRecord.fromTypedData(
                        "example.com",
                        DnsResourceRecord.TYPE_SOA,
                        1, 300, soa
                );

        record.encodeTo(message, map);

        DnsResourceRecord decoded =
                decodeAnswer(message);

        assertEquals(soa, decoded.getRdataValue());
    }

    @Test
    void testCompressedRdataLength() {

        ByteArrayOutputStream message =
                new ByteArrayOutputStream();

        message.writeBytes(new byte[12]);

        Map<String, Integer> map = new HashMap<>();

        writeQuestion(message, map);

        int answerOffset = message.size();

        DnsResourceRecord record =
                DnsResourceRecord.fromTypedData(
                        "example.com",
                        DnsResourceRecord.TYPE_CNAME,
                        1, 300,
                        "example.com"
                );

        record.encodeTo(message, map);

        byte[] packet = message.toByteArray();

        // Owner name is a two-byte pointer.
        // Fixed RR header is ten bytes.
        // CNAME RDATA is another two-byte pointer.
        int rdLengthOffset = answerOffset + 4 + 6;

        int rdLength =
                ((packet[rdLengthOffset] & 0xFF) << 8)
                        | (packet[rdLengthOffset + 1] & 0xFF);

        assertEquals(2, rdLength);

        assertEquals(
                packet.length,
                DnsResourceRecord.decodeTyped(
                        packet, answerOffset
                ).nextOffset()
        );
    }
}
