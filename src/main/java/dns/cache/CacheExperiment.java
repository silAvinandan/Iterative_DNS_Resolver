package dns.cache;

import dns.wire.DnsResourceRecord;

import java.util.List;
import java.util.Locale;

public final class CacheExperiment {

    private CacheExperiment() {
    }

    public static void main(String[] args) {

        List<String> queryTrace = List.of(
                "example.com",
                "google.com",
                "example.com",
                "openai.com",
                "google.com",
                "example.com",
                "wikipedia.org",
                "openai.com",
                "example.com",
                "google.com"
        );

        DnsCache coldCache = new DnsCache();
        replay(coldCache, queryTrace);

        DnsCache warmCache = new DnsCache();

        for (String domain : queryTrace) {
            seed(warmCache, domain);
        }

        replay(warmCache, queryTrace);

        System.out.println("DNS Cache Hit-Ratio Experiment");
        System.out.println("--------------------------------");
        System.out.println("Total queries: " + queryTrace.size());

        System.out.printf(
                Locale.ROOT,
                "Cold-cache hit ratio: %.2f%%%n",
                coldCache.getHitRatio() * 100
        );

        System.out.printf(
                Locale.ROOT,
                "Warm-cache hit ratio: %.2f%%%n",
                warmCache.getHitRatio() * 100
        );
    }

    private static void replay(DnsCache cache, List<String> trace) {

        for (String domain : trace) {

            List<DnsResourceRecord> result =
                    cache.get(domain, DnsResourceRecord.TYPE_A,
                            DnsResourceRecord.CLASS_IN);

            if (result == null) {
                seed(cache, domain);
            }
        }
    }

    private static void seed(DnsCache cache, String domain) {

        DnsResourceRecord record = new DnsResourceRecord(
                domain,
                DnsResourceRecord.TYPE_A,
                DnsResourceRecord.CLASS_IN,
                300,
                new byte[]{93, (byte) 184, (byte) 216, 34}
        );

        cache.put(
                domain,
                DnsResourceRecord.TYPE_A,
                DnsResourceRecord.CLASS_IN,
                List.of(record)
        );
    }
}