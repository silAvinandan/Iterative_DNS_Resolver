
package dns.cache;

import dns.wire.DnsResourceRecord;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class DnsCache {

    private static final int RCODE_NOERROR = 0;
    private static final int RCODE_NXDOMAIN = 3;

    private final Map<String, CacheEntry> positiveCache =
            new HashMap<>();

    private final Map<String, NegativeEntry> negativeCache =
            new HashMap<>();

    private long hits = 0;
    private long misses = 0;

    private long queryHits = 0;
    private long queryMisses = 0;

    private record CacheEntry(
            List<DnsResourceRecord> records,
            long expiresAt
    ) {}

    private record NegativeEntry(
            int responseCode,
            long expiresAt
    ) {}

    private String normalizeName(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Invalid DNS name");
        }

        String normalized = name.trim().toLowerCase(Locale.ROOT);

        if (normalized.endsWith(".")) {
            normalized = normalized.substring(
                    0, normalized.length() - 1
            );
        }

        return normalized;
    }

    private String makeKey(
            String name, int type, int recordClass) {

        return normalizeName(name)
                + "|" + type
                + "|" + recordClass;
    }

    private String makeNxDomainKey(
            String name, int recordClass) {

        return normalizeName(name)
                + "|*|" + recordClass;
    }

    private long expirationTime(long ttl) {
        long now = System.currentTimeMillis();

        if (ttl > (Long.MAX_VALUE - now) / 1000) {
            return Long.MAX_VALUE;
        }

        return now + ttl * 1000;
    }

    public synchronized void put(
            String name,
            int type,
            int recordClass,
            List<DnsResourceRecord> records) {

        if (records == null || records.isEmpty()) {
            return;
        }

        long minimumTtl = Long.MAX_VALUE;

        for (DnsResourceRecord record : records) {

            if (record == null
                    || !normalizeName(record.getName())
                    .equals(normalizeName(name))
                    || record.getType() != type
                    || record.getRecordClass() != recordClass) {

                throw new IllegalArgumentException(
                        "Records do not match the cache key"
                );
            }

            minimumTtl = Math.min(
                    minimumTtl, record.getTtl()
            );
        }

        if (minimumTtl <= 0) {
            return;
        }

        String key = makeKey(name, type, recordClass);

        positiveCache.put(
                key,
                new CacheEntry(
                        List.copyOf(records),
                        expirationTime(minimumTtl)
                )
        );

        negativeCache.remove(key);
        negativeCache.remove(
                makeNxDomainKey(name, recordClass)
        );
    }

    public synchronized List<DnsResourceRecord> get(
            String name,
            int type,
            int recordClass) {

        String key = makeKey(name, type, recordClass);

        CacheEntry entry = positiveCache.get(key);

        if (entry == null) {
            misses++;
            return null;
        }

        if (System.currentTimeMillis() >= entry.expiresAt()) {
            positiveCache.remove(key);
            misses++;
            return null;
        }

        hits++;
        return entry.records();
    }

    public synchronized void putNegative(
            String name,
            int type,
            int recordClass,
            int responseCode,
            long soaTtl,
            long soaMinimum) {

        if (responseCode != RCODE_NOERROR
                && responseCode != RCODE_NXDOMAIN) {
            throw new IllegalArgumentException(
                    "Only NOERROR and NXDOMAIN can be cached"
            );
        }

        long negativeTtl = Math.min(soaTtl, soaMinimum);

        if (negativeTtl <= 0) {
            return;
        }

        String key;

        if (responseCode == RCODE_NXDOMAIN) {
            key = makeNxDomainKey(name, recordClass);
        } else {
            key = makeKey(name, type, recordClass);
        }

        negativeCache.put(
                key,
                new NegativeEntry(
                        responseCode,
                        expirationTime(negativeTtl)
                )
        );

        if (responseCode == RCODE_NXDOMAIN) {
            positiveCache.keySet().removeIf(
                    existingKey -> existingKey.startsWith(
                            normalizeName(name) + "|"
                    )
                    && existingKey.endsWith("|" + recordClass)
            );
        } else {
            positiveCache.remove(key);
        }
    }

    public synchronized Integer getNegative(
            String name,
            int type,
            int recordClass) {

        String nxDomainKey =
                makeNxDomainKey(name, recordClass);

        NegativeEntry entry = negativeCache.get(nxDomainKey);

        if (entry == null) {
            entry = negativeCache.get(
                    makeKey(name, type, recordClass)
            );
        }

        if (entry == null) {
            misses++;
            return null;
        }

        if (System.currentTimeMillis() >= entry.expiresAt()) {
            negativeCache.remove(nxDomainKey);
            negativeCache.remove(
                    makeKey(name, type, recordClass)
            );
            misses++;
            return null;
        }

        hits++;
        return entry.responseCode();
    }

    public synchronized void removeExpired() {

        long now = System.currentTimeMillis();

        positiveCache.entrySet().removeIf(
                entry -> now >= entry.getValue().expiresAt()
        );

        negativeCache.entrySet().removeIf(
                entry -> now >= entry.getValue().expiresAt()
        );
    }

    public synchronized double getHitRatio() {

        long total = hits + misses;

        if (total == 0) {
            return 0.0;
        }

        return (double) hits / total;
    }

    public synchronized void recordQueryHit() {
        queryHits++;
    }

    public synchronized void recordQueryMiss() {
        queryMisses++;
    }

    public synchronized double getQueryHitRatio() {
        long total = queryHits + queryMisses;
        return total == 0 ? 0.0 : (double) queryHits / total;
    }
    public synchronized int positiveCacheSize() {
        removeExpired();
        return positiveCache.size();
    }

    public synchronized int negativeCacheSize() {
        removeExpired();
        return negativeCache.size();
    }
}
