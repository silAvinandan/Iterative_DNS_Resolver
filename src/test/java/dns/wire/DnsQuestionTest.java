
package dns.wire;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DnsQuestionTest {

    @Test
    void testQuestionEncoding() {

        DnsQuestion question = new DnsQuestion(
                "google.com", DnsQuestion.TYPE_A,
                DnsQuestion.CLASS_IN
        );

        byte[] expected = {
                0x06, 'g', 'o', 'o', 'g', 'l', 'e',
                0x03, 'c', 'o', 'm', 0x00,
                0x00, 0x01,
                0x00, 0x01
        };

        assertArrayEquals(expected, question.toBytes());
    }

    @Test
    void testQuestionDecoding() {

        byte[] data = {
                0x06, 'g', 'o', 'o', 'g', 'l', 'e',
                0x03, 'c', 'o', 'm', 0x00,
                0x00, 0x01,
                0x00, 0x01
        };

        DnsQuestion.Decoded decoded =
                DnsQuestion.decode(data, 0);

        DnsQuestion question = decoded.question();

        assertEquals("google.com", question.getQname());
        assertEquals(DnsQuestion.TYPE_A, question.getQtype());
        assertEquals(DnsQuestion.CLASS_IN, question.getQclass());
        assertEquals(data.length, decoded.nextOffset());
    }

    @Test
    void testQuestionRoundTrip() {

        DnsQuestion original = new DnsQuestion(
                "example.com",
                DnsQuestion.TYPE_AAAA,
                DnsQuestion.CLASS_IN
        );

        DnsQuestion.Decoded decoded =
                DnsQuestion.decode(original.toBytes(), 0);

        DnsQuestion result = decoded.question();

        assertEquals(original.getQname(), result.getQname());
        assertEquals(original.getQtype(), result.getQtype());
        assertEquals(original.getQclass(), result.getQclass());
    }

    @Test
    void testQuestionWithOffset() {

        byte[] data = {
                0x55, 0x66,
                0x03, 'w', 'w', 'w',
                0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                0x03, 'c', 'o', 'm',
                0x00, 0x00, 0x01, 0x00, 0x01
        };

        DnsQuestion.Decoded decoded =
                DnsQuestion.decode(data, 2);

        assertEquals("www.example.com",
                decoded.question().getQname());

        assertEquals(data.length, decoded.nextOffset());
    }

    @Test
    void testRootDomain() {

        DnsQuestion question = new DnsQuestion(
                ".", DnsQuestion.TYPE_NS, DnsQuestion.CLASS_IN
        );

        byte[] expected = {
                0x00, 0x00, 0x02, 0x00, 0x01
        };

        assertArrayEquals(expected, question.toBytes());

        assertEquals("",
                DnsQuestion.decode(expected, 0)
                        .question().getQname());
    }

    @Test
    void testRejectInvalidQtype() {

        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsQuestion("google.com", -1, 1)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsQuestion("google.com", 65536, 1)
        );
    }

    @Test
    void testRejectNullDomain() {

        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsQuestion(null, 1, 1)
        );
    }

    @Test
    void testRejectTruncatedQuestion() {

        byte[] incomplete = {
                0x06, 'g', 'o', 'o'
        };

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsQuestion.decode(incomplete, 0)
        );
    }
}
