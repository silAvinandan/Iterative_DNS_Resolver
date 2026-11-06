package dns.resolver;

import dns.cache.DnsCache;
import dns.transport.DnsTransport;
import dns.transport.ServerSelector;
import dns.transport.TransportConfig;

public final class DnsServerMain {

    private DnsServerMain() {}

    public static void main(String[] args) {
        int port = 5353;

        try {
            if (args.length > 1) {
                throw new IllegalArgumentException(
                        "Usage: DnsServerMain [port]"
                );
            }

            if (args.length == 1) {
                port = Integer.parseInt(args[0]);
            }

            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Port must be 1-65535");
            }

            TransportConfig config = TransportConfig.defaults();

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

            DnsServer server = new DnsServer(resolver, port);

            Runtime.getRuntime().addShutdownHook(
                    new Thread(server::close, "dns-server-shutdown")
            );

            server.start();
            server.await();

        } catch (NumberFormatException e) {
            System.err.println("Invalid port number.");
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
        } catch (Exception e) {
            System.err.println("Could not start DNS server: "
                    + e.getMessage());
        }
    }
}