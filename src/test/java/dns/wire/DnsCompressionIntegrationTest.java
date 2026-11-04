
package dns.wire;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DnsCompressionIntegrationTest {

    @Test
    void testCompressedQuestionDecoding() {

        byte[] data = {
                // Original name at offset 0.
                0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                0x03, 'c', 'o', 'm', 0x00,

                // Compressed name at offset 13.
                (byte) 0xC0, 0x00,

                // QTYPE = A, QCLASS = IN.
                0x00, 0x01,
                0x00, 0x01
        };

        DnsQuestion.Decoded decoded =
                DnsQuestion.decode(data, 13);

        assertEquals(
                "example.com",
                decoded.question().getQname()
        );

        assertEquals(1, decoded.question().getQtype());
        assertEquals(1, decoded.question().getQclass());

        assertEquals(19, decoded.nextOffset());
    }

    @Test
    void testResourceRecordPointsToQuestionName() {

        ByteArrayOutputStream message =
                new ByteArrayOutputStream();

        // Reserve the first 12 bytes for the DNS header.
        message.writeBytes(new byte[12]);

        Map<String, Integer> compressionMap =
                new HashMap<>();

        // Encode the Question section.
        DnsQuestion question = new DnsQuestion(
                "google.com",
                DnsQuestion.TYPE_A,
                DnsQuestion.CLASS_IN
        );

        question.encodeTo(message, compressionMap);

        int answerOffset = message.size();

        // Encode the Answer section.
        byte[] ipAddress = {
                (byte) 142,
                (byte) 250,
                (byte) 183,
                14
        };

        DnsResourceRecord answer =
                new DnsResourceRecord(
                        "google.com",
                        DnsResourceRecord.TYPE_A,
                        DnsResourceRecord.CLASS_IN,
                        300,
                        ipAddress
                );

        answer.encodeTo(message, compressionMap);

        byte[] packet = message.toByteArray();

        // The answer owner name should use a pointer to offset 12.
        assertEquals(
                0xC0,
                packet[answerOffset] & 0xC0
        );

        int pointer =
                ((packet[answerOffset] & 0x3F) << 8)
                        | (packet[answerOffset + 1] & 0xFF);

        assertEquals(12, pointer);

        // Decode the Question.
        DnsQuestion.Decoded decodedQuestion =
                DnsQuestion.decode(packet, 12);

        assertEquals(
                "google.com",
                decodedQuestion.question().getQname()
        );

        // Decode the Answer.
        DnsResourceRecord.Decoded decodedAnswer =
                DnsResourceRecord.decode(
                        packet,
                        decodedQuestion.nextOffset()
                );

        assertEquals(
                "google.com",
                decodedAnswer.record().getName()
        );

        assertEquals(
                DnsResourceRecord.TYPE_A,
                decodedAnswer.record().getType()
        );

        assertEquals(300, decodedAnswer.record().getTtl());

        assertArrayEquals(
                ipAddress,
                decodedAnswer.record().getRdata()
        );

        assertEquals(packet.length, decodedAnswer.nextOffset());
    }
}
