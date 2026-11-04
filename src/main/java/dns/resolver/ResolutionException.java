package dns.resolver;

import java.io.IOException;
import java.util.List;

/** Failure that keeps the path and counters gathered so far, for debugging and experiments. */
final class ResolutionException extends IOException {
    private static final long serialVersionUID = 1L;
    final transient List<String> path;
    final transient Resolution.Stats stats;

    ResolutionException(String msg, Throwable cause, List<String> path, Resolution.Stats stats) {
        super(msg, cause);
        this.path = List.copyOf(path);
        this.stats = stats;
    }
}
