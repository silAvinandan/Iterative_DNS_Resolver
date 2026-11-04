package dns.resolver;

import dns.cache.DnsCache;
import dns.transport.DnsTransport;
import dns.transport.ServerSelector;
import dns.transport.TransportConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public final class Main {

    private static final String USAGE =
            "Usage: Main <domain> [type] [options]\n"
            + "  --interactive    Run multiple queries with shared cache\n"
            + "  --stats          Print resolution and cache statistics\n"
            + "  --timeout-ms N   UDP timeout (default 2000)\n"
            + "  --retries N      Extra retry rounds (default 2)\n"
            + "  --no-backoff     Disable exponential timeout backoff";

    public static void main(String[] args) {

        boolean stats = false;
        boolean interactive = false;

        int timeoutMs = TransportConfig.defaults().timeoutMs;
        int retries = TransportConfig.defaults().retries;
        boolean backoff = TransportConfig.defaults().exponentialBackoff;

        List<String> positional = new ArrayList<>();

        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--stats" -> stats = true;
                    case "--interactive" -> interactive = true;
                    case "--no-backoff" -> backoff = false;
                    case "--timeout-ms" -> {
                        if (++i >= args.length) {
                            throw new IllegalArgumentException();
                        }
                        timeoutMs = Integer.parseInt(args[i]);
                    }
                    case "--retries" -> {
                        if (++i >= args.length) {
                            throw new IllegalArgumentException();
                        }
                        retries = Integer.parseInt(args[i]);
                    }
                    default -> positional.add(args[i]);
                }
            }
        } catch (RuntimeException e) {
            System.err.println("Invalid option value.\n" + USAGE);
            return;
        }

        if (interactive && !positional.isEmpty()) {
            System.err.println(
                    "Do not provide a domain with --interactive."
            );
            return;
        }

        if (!interactive && positional.isEmpty()) {
            System.err.println(USAGE);
            return;
        }

        TransportConfig config;

        try {
            config = new TransportConfig(
                    timeoutMs, retries, backoff
            );
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            return;
        }

        DnsTransport transport = new DnsTransport(
                config, new ServerSelector()
        );

        DnsCache cache = new DnsCache();

        IterativeResolver resolver = new IterativeResolver(
                new TransportAdapter(
                        transport, config, new BWireCodec()
                ),
                cache
        );

        if (interactive) {
            runInteractive(resolver, cache, transport, stats);
            return;
        }

        String name = positional.get(0);
        int type;

        try {
            type = positional.size() > 1
                    ? DnsWire.typeCode(positional.get(1))
                    : DnsWire.A;
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            return;
        }

        runQuery(resolver, cache, transport, name, type, stats);
    }

    private static void runInteractive(
            IterativeResolver resolver,
            DnsCache cache,
            DnsTransport transport,
            boolean stats) {

        System.out.println("Iterative DNS Resolver");
        System.out.println("Enter: domain [A|AAAA|NS|CNAME|MX|TXT|SOA]");
        System.out.println("Enter exit to quit.\n");

        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                System.out.print("> ");

                if (!scanner.hasNextLine()) {
                    break;
                }

                String line = scanner.nextLine().trim();

                if (line.equalsIgnoreCase("exit")) {
                    break;
                }

                if (line.isEmpty()) {
                    continue;
                }

                String[] parts = line.split("\\s+");

                if (parts.length > 2) {
                    System.out.println(
                            "Usage: domain [record-type]"
                    );
                    continue;
                }

                int type;

                try {
                    type = parts.length == 2
                            ? DnsWire.typeCode(parts[1])
                            : DnsWire.A;
                } catch (IllegalArgumentException e) {
                    System.out.println(e.getMessage());
                    continue;
                }

                runQuery(
                        resolver, cache, transport,
                        parts[0], type, stats
                );

                System.out.println();
            }
        }

        printCacheStats(cache);
        System.out.println("Resolver stopped.");
    }

    private static void runQuery(
            IterativeResolver resolver,
            DnsCache cache,
            DnsTransport transport,
            String name,
            int type,
            boolean stats) {

        String qname;

        try {
            qname = DnsWire.absolute(name);
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid domain: " + e.getMessage());
            return;
        }

        System.out.println(
                "Query: " + qname + " " + DnsWire.typeName(type)
        );

        try {
            Resolution result = resolver.resolve(name, type);

            System.out.println(
                    "RCODE: " + result.rcode
                            + (result.rcode == 0 ? " (NOERROR)"
                            : result.rcode == 3 ? " (NXDOMAIN)" : "")
            );

            System.out.println("Resolution path:");
            result.path.forEach(System.out::println);

            System.out.println(
                    "Delegation chain: "
                            + String.join(" > ", result.delegations)
            );

            System.out.println("Answer:");

            if (result.answers.isEmpty()) {
                System.out.println("(no answer records)");
                result.authority.forEach(
                        record -> System.out.println("authority: " + record)
                );
            } else {
                result.answers.forEach(System.out::println);
            }

            if (stats) {
                System.out.println(
                        statsLine(
                                qname, type, "OK", result.rcode,
                                result.stats, transport,
                                result.delegations
                        )
                );
                printCacheStats(cache);
            }

        } catch (ResolutionException e) {
            System.out.println("Resolution path:");
            e.path.forEach(System.out::println);
            System.out.println("FAILED: " + e.getMessage());

            if (stats) {
                System.out.println(
                        statsLine(
                                qname, type, "FAILED", -1,
                                e.stats, transport, List.of()
                        )
                );
                printCacheStats(cache);
            }
        }
    }

    private static void printCacheStats(DnsCache cache) {
        System.out.printf(
                "Cache hit ratio: %.2f%%%n",
                cache.getQueryHitRatio() * 100
        );

        System.out.println(
                "Positive cache entries: " + cache.positiveCacheSize()
        );

        System.out.println(
                "Negative cache entries: " + cache.negativeCacheSize()
        );
    }

    private static String statsLine(
            String name,
            int type,
            String status,
            int rcode,
            Resolution.Stats s,
            DnsTransport transport,
            List<String> chain) {

        return "STATS name=" + name
                + " type=" + DnsWire.typeName(type)
                + " status=" + status
                + " rcode=" + rcode
                + " upstream_queries=" + s.upstreamQueries()
                + " packets_sent=" + s.packetsSent()
                + " failed_queries=" + s.failedQueries()
                + " timeouts=" + s.timeouts()
                + " unusable=" + s.unusableResponses()
                + " elapsed_ms=" + s.elapsedMs()
                + " udp_sent=" + transport.udpSent()
                + " tcp_sent=" + transport.tcpSent()
                + " transport_timeouts=" + transport.timeouts()
                + " chain=" + String.join(">", chain);
    }
}
