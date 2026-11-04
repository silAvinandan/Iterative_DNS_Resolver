package dns.transport;

/** Tunable knobs for the transport layer. Immutable. */
public final class TransportConfig {
    /** Per-attempt wait for a UDP reply (first round). */
    public final int timeoutMs;
    /** Extra rounds over the server list after the first one (0 = try each server once). */
    public final int retries;
    /** If true, the timeout doubles after every full round over the server list. */
    public final boolean exponentialBackoff;

    public TransportConfig(int timeoutMs, int retries, boolean exponentialBackoff) {
        if (timeoutMs <= 0) throw new IllegalArgumentException("timeoutMs must be > 0");
        if (retries < 0) throw new IllegalArgumentException("retries must be >= 0");
        this.timeoutMs = timeoutMs;
        this.retries = retries;
        this.exponentialBackoff = exponentialBackoff;
    }

    public static TransportConfig defaults() {
        return new TransportConfig(2000, 2, true);
    }
}
