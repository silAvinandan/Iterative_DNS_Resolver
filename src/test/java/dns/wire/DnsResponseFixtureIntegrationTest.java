package dns.wire;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class DnsResponseFixtureIntegrationTest {

    @Test
    void shouldDecodeCapturedDnsResponse() throws IOException {

        // Read the captured DNS response.
        String hex;

        try (InputStream input = getClass().getResourceAsStream(
                "/fixtures/dns-response.hex")) {

            assertNotNull(input, "DNS response fixture not found");

            hex = new String(
                    input.readAllBytes(),
                    StandardCharsets.UTF_8
            ).trim();
        }

        byte[] message = decodeHex(hex);

        // Verify packet length.
        assertEquals(183, message.length);

        // Decode DNS header.
        DnsHeader header = DnsHeader.fromBytes(message);

        assertEquals(0xD71D, header.getId());
        assertEquals(0x8180, header.getFlags());
        assertEquals(1, header.getQdCount());
        assertEquals(5, header.getAnCount());
        assertEquals(0, header.getNsCount());
        assertEquals(0, header.getArCount());

        // Decode DNS question.
        DnsQuestion.Decoded questionDecoded =
                DnsQuestion.decode(message, DnsHeader.HEADER_LENGTH);

        DnsQuestion question = questionDecoded.question();

        assertEquals("www.bing.com", question.getQname());
        assertEquals(DnsQuestion.TYPE_A, question.getQtype());
        assertEquals(DnsQuestion.CLASS_IN, question.getQclass());

        // Expected answer records.
        String[] expectedNames = {
                "www.bing.com",
                "www-www.bing.com.trafficmanager.net",
                "www.bing.com.edgekey.net",
                "e86303.dscx.akamaiedge.net",
                "e86303.dscx.akamaiedge.net"
        };

        int[] expectedTypes = {
                5, 5, 5, 1, 1
        };

        long[] expectedTtls = {
                20728, 41, 8828, 9, 9
        };

        String[] expectedValues = {
                "www-www.bing.com.trafficmanager.net",
                "www.bing.com.edgekey.net",
                "e86303.dscx.akamaiedge.net",
                "23.57.76.23",
                "23.57.76.69"
        };

        // Decode all five resource records.
        int offset = questionDecoded.nextOffset();

        for (int i = 0; i < header.getAnCount(); i++) {

            DnsResourceRecord.Decoded decoded =
                    DnsResourceRecord.decodeTyped(message, offset);

            DnsResourceRecord record = decoded.record();

            assertEquals(expectedNames[i], record.getName());
            assertEquals(expectedTypes[i], record.getType());
            assertEquals(DnsResourceRecord.CLASS_IN,
                    record.getRecordClass());
            assertEquals(expectedTtls[i], record.getTtl());

            if (record.getType() == DnsResourceRecord.TYPE_CNAME) {

                assertEquals(
                        expectedValues[i],
                        record.getRdataValue()
                );

            } else {

                byte[] expectedAddress = ipToBytes(expectedValues[i]);

                assertArrayEquals(
                        expectedAddress,
                        (byte[]) record.getRdataValue()
                );
            }

            offset = decoded.nextOffset();
        }

        // Ensure the complete DNS message was consumed.
        assertEquals(message.length, offset);
    }

    private static byte[] decodeHex(String hex) {

        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal input"
            );
        }

        byte[] result = new byte[hex.length() / 2];

        for (int i = 0; i < result.length; i++) {

            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);

            if (high < 0 || low < 0) {
                throw new IllegalArgumentException(
                        "Invalid hexadecimal character"
                );
            }

            result[i] = (byte) ((high << 4) | low);
        }

        return result;
    }

    private static byte[] ipToBytes(String ip) {

        String[] parts = ip.split("\\.");
        byte[] result = new byte[4];

        for (int i = 0; i < 4; i++) {
            result[i] = (byte) Integer.parseInt(parts[i]);
        }

        return result;
    }
    @Test
void shouldRejectTruncatedCapturedDnsResponse() throws IOException {

    String hex;

    try (InputStream input = getClass().getResourceAsStream(
            "/fixtures/dns-response.hex")) {

        assertNotNull(input, "DNS response fixture not found");

        hex = new String(
                input.readAllBytes(),
                StandardCharsets.UTF_8
        ).trim();
    }

    byte[] originalMessage = decodeHex(hex);

    // Remove the final byte from the captured DNS response.
    byte[] truncatedMessage = java.util.Arrays.copyOf(
            originalMessage,
            originalMessage.length - 1
    );

    DnsHeader header = DnsHeader.fromBytes(truncatedMessage);

    DnsQuestion.Decoded question =
            DnsQuestion.decode(
                    truncatedMessage,
                    DnsHeader.HEADER_LENGTH
            );

    int offset = question.nextOffset();

    // Decode the first four complete answer records.
    for (int i = 0; i < 4; i++) {

        DnsResourceRecord.Decoded decoded =
                DnsResourceRecord.decodeTyped(
                        truncatedMessage,
                        offset
                );

        offset = decoded.nextOffset();
    }

    // The final A record is missing its last RDATA byte.
    final int finalOffset = offset;
    assertThrows(
            IllegalArgumentException.class,
            () -> DnsResourceRecord.decodeTyped(
                    truncatedMessage,
                    finalOffset
            )
    );
}
}