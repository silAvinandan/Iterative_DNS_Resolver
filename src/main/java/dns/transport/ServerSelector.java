package dns.transport;

import java.net.InetSocketAddress;
import java.util.*;

/**
 * Orders candidate servers: lowest smoothed RTT first, with a heavy penalty per
 * recent failure. Unknown servers score 0, so they get tried (explored) first.
 */
public final class ServerSelector {
    private static final double FAIL_PENALTY_MS = 5000;
    private static final double ALPHA = 0.3; // EWMA weight of the newest sample

    private final Map<InetSocketAddress, Double> srtt = new HashMap<>();
    private final Map<InetSocketAddress, Integer> fails = new HashMap<>();

    public synchronized List<InetSocketAddress> order(Collection<InetSocketAddress> candidates) {
        List<InetSocketAddress> list = new ArrayList<>(candidates);
        list.sort(Comparator.comparingDouble(this::score)); // stable: ties keep input order
        return list;
    }

    private double score(InetSocketAddress s) {
        return srtt.getOrDefault(s, 0.0) + fails.getOrDefault(s, 0) * FAIL_PENALTY_MS;
    }

    public synchronized void recordSuccess(InetSocketAddress s, double rttMs) {
        Double old = srtt.get(s);
        srtt.put(s, old == null ? rttMs : (1 - ALPHA) * old + ALPHA * rttMs);
        fails.remove(s);
    }

    public synchronized void recordFailure(InetSocketAddress s) {
        fails.merge(s, 1, Integer::sum);
    }
}
