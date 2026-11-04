
package dns.cache;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class ResolutionGuard {

    private static final int DEFAULT_MAX_DEPTH = 16;

    private final int maxDepth;
    private final Set<String> visitedNames = new HashSet<>();

    public ResolutionGuard() {
        this(DEFAULT_MAX_DEPTH);
    }

    public ResolutionGuard(int maxDepth) {

        if (maxDepth <= 0) {
            throw new IllegalArgumentException(
                    "Maximum depth must be positive"
            );
        }

        this.maxDepth = maxDepth;
    }

    public boolean visit(String domainName) {

        if (domainName == null || domainName.isBlank()) {
            throw new IllegalArgumentException(
                    "Domain name cannot be empty"
            );
        }

        String normalized = domainName.trim()
                .toLowerCase(Locale.ROOT);

        if (normalized.endsWith(".")) {
            normalized = normalized.substring(
                    0, normalized.length() - 1
            );
        }

        // Reject a repeated domain name (CNAME loop).
        if (visitedNames.contains(normalized)) {
            return false;
        }

        // Reject resolution beyond the configured depth.
        if (visitedNames.size() >= maxDepth) {
            return false;
        }

        visitedNames.add(normalized);
        return true;
    }

    public int getVisitedCount() {
        return visitedNames.size();
    }

    public void reset() {
        visitedNames.clear();
    }

    public int getMaxDepth() {
        return maxDepth;
    }
}
