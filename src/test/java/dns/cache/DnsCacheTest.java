
package dns.cache;

import dns.wire.DnsResourceRecord;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DnsCacheTest {

    private DnsResourceRecord createRecord(long ttl) {
        return new DnsResourceRecord(
                "example.com",
                DnsResourceRecord.TYPE_A,
                DnsResourceRecord.CLASS_IN,
                ttl,
                new byte[]{93, (byte) 184, (byte) 216, 34}
        );
    }

    @Test
    void testPositiveCache() {

        DnsCache cache = new DnsCache();

        DnsResourceRecord record = createRecord(60);

        cache.put(
                "example.com", 1, 1,
                List.of(record)
        );

        List<DnsResourceRecord> result =
                cache.get("example.com", 1, 1);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("example.com", result.get(0).getName());
    }

    @Test
    void testCacheIsCaseInsensitive() {

        DnsCache cache = new DnsCache();

        cache.put(
                "example.com", 1, 1,
                List.of(createRecord(60))
        );

        assertNotNull(cache.get("EXAMPLE.COM", 1, 1));
    }

    @Test
    void testTtlExpiration() throws InterruptedException {

        DnsCache cache = new DnsCache();

        cache.put(
                "example.com", 1, 1,
                List.of(createRecord(1))
        );

        assertNotNull(cache.get("example.com", 1, 1));

        Thread.sleep(1100);

        assertNull(cache.get("example.com", 1, 1));
    }

    @Test
    void testNxdomainNegativeCaching() {

        DnsCache cache = new DnsCache();

        cache.putNegative(
                "missing.example.com",
                1, 1,
                3,
                300,
                120
        );

        assertEquals(
                3,
                cache.getNegative(
                        "missing.example.com", 28, 1
                )
        );
    }

    @Test
    void testNodataNegativeCaching() {

        DnsCache cache = new DnsCache();

        cache.putNegative(
                "example.com",
                28, 1,
                0,
                300,
                60
        );

        assertEquals(
                0,
                cache.getNegative("example.com", 28, 1)
        );

        assertNull(
                cache.getNegative("example.com", 1, 1)
        );
    }

    @Test
    void testNegativeTtlExpiration() throws InterruptedException {

        DnsCache cache = new DnsCache();

        cache.putNegative(
                "missing.example.com",
                1, 1,
                3,
                1,
                10
        );

        assertEquals(
                3,
                cache.getNegative(
                        "missing.example.com", 1, 1
                )
        );

        Thread.sleep(1100);

        assertNull(
                cache.getNegative(
                        "missing.example.com", 1, 1
                )
        );
    }

    @Test
    void testHitRatio() {

        DnsCache cache = new DnsCache();

        cache.put(
                "example.com", 1, 1,
                List.of(createRecord(60))
        );

        cache.get("example.com", 1, 1);
        cache.get("missing.com", 1, 1);

        assertEquals(0.5, cache.getHitRatio(), 0.001);
    }

    @Test
    void testResolutionLoopProtection() {

        ResolutionGuard guard = new ResolutionGuard();

        assertTrue(guard.visit("example.com"));
        assertFalse(guard.visit("EXAMPLE.COM"));
    }

    @Test
    void testResolutionDepthProtection() {

        ResolutionGuard guard = new ResolutionGuard(2);

        assertTrue(guard.visit("one.example"));
        assertTrue(guard.visit("two.example"));
        assertFalse(guard.visit("three.example"));
    }
}
