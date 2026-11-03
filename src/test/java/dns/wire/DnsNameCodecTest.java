
package dns.wire;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DnsNameCodecTest {

    @Test
    void testBasicEncoding() {

        ByteArrayOutputStream output =
                new ByteArrayOutputStream();

        DnsNameCodec.encode(
                "google.com", output, new HashMap<>()
        );

        byte[] expected = {
                0x06, 'g', 'o', 'o', 'g', 'l', 'e',
                0x03, 'c', 'o', 'm', 0x00
        };

        assertArrayEquals(expected, output.toByteArray());
    }

    @Test
    void testBasicDecoding() {

        byte[] data = {
                0x06, 'g', 'o', 'o', 'g', 'l', 'e',
                0x03, 'c', 'o', 'm', 0x00
        };

        DnsNameCodec.Decoded decoded =
                DnsNameCodec.decode(data, 0);

        assertEquals("google.com", decoded.name());
        assertEquals(data.length, decoded.nextOffset());
    }

    
@Test
void testCompressionEncoding() {

    ByteArrayOutputStream output =
            new ByteArrayOutputStream();

    Map<String, Integer> map = new HashMap<>();

    DnsNameCodec.encode("example.com", output, map);

    int secondNameOffset = output.size();

    DnsNameCodec.encode("www.example.com", output, map);

    byte[] result = output.toByteArray();

    // The first label is www.
    assertEquals(3, result[secondNameOffset] & 0xFF);

    assertEquals('w', result[secondNameOffset + 1]);
    assertEquals('w', result[secondNameOffset + 2]);
    assertEquals('w', result[secondNameOffset + 3]);

    // The next two bytes must form a compression pointer.
    int pointerHigh = result[secondNameOffset + 4] & 0xFF;
    int pointerLow = result[secondNameOffset + 5] & 0xFF;

    assertEquals(0xC0, pointerHigh & 0xC0);

    int pointer = ((pointerHigh & 0x3F) << 8)
            | pointerLow;

    // example.com was originally stored at offset zero.
    assertEquals(0, pointer);
}


    @Test
    void testCompressionDecoding() {

        byte[] data = {
                0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                0x03, 'c', 'o', 'm', 0x00,

                0x03, 'w', 'w', 'w',
                (byte) 0xC0, 0x00
        };

        DnsNameCodec.Decoded decoded =
                DnsNameCodec.decode(data, 13);

        assertEquals("www.example.com", decoded.name());
        assertEquals(19, decoded.nextOffset());
    }

    @Test
    void testRootDomain() {

        byte[] data = {0x00};

        DnsNameCodec.Decoded decoded =
                DnsNameCodec.decode(data, 0);

        assertEquals("", decoded.name());
        assertEquals(1, decoded.nextOffset());
    }

    @Test
    void testRejectPointerLoop() {

        byte[] data = {
                (byte) 0xC0, 0x00
        };

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsNameCodec.decode(data, 0)
        );
    }

    @Test
    void testRejectForwardPointer() {

        byte[] data = {
                (byte) 0xC0, 0x02,
                0x00
        };

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsNameCodec.decode(data, 0)
        );
    }

    @Test
    void testRejectTruncatedPointer() {

        byte[] data = {
                (byte) 0xC0
        };

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsNameCodec.decode(data, 0)
        );
    }

    @Test
    void testRejectNullInput() {

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsNameCodec.decode(null, 0)
        );
    }

    @Test
    void testRejectInvalidOffset() {

        byte[] data = {0x00};

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsNameCodec.decode(data, 1)
        );
    }
}
