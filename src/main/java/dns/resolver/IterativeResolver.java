package dns.resolver;

import dns.cache.DnsCache;
import dns.wire.DnsResourceRecord;
import dns.wire.DnsRdataCodec;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class IterativeResolver {

    private static final int MAX_HOPS = 32;

    private static final List<String> ROOTS = List.of(
            "198.41.0.4", "170.247.170.2", "192.33.4.12",
            "199.7.91.13", "192.203.230.10", "192.5.5.241",
            "192.112.36.4", "198.97.190.53", "192.36.148.17",
            "192.58.128.30", "193.0.14.129", "199.7.83.42",
            "202.12.27.33"
    );

    private final Transport transport;
    private final DnsCache cache;

    IterativeResolver(Transport transport) {
        this(transport, new DnsCache());
    }

    IterativeResolver(Transport transport, DnsCache cache) {
        if (transport == null || cache == null) {
            throw new IllegalArgumentException(
                    "Transport and cache cannot be null"
            );
        }

        this.transport = transport;
        this.cache = cache;
    }

    DnsCache getCache() {
        return cache;
    }

    private static final class Context {
        final List<String> path = new ArrayList<>();
        final Set<String> active = new HashSet<>();
        final List<String> delegations = new ArrayList<>();

        int queries;
        int packets;
        int failed;
        int timeouts;
        int unusable;

        Resolution.Stats stats(long startNanos) {
            return new Resolution.Stats(
                    queries,
                    packets,
                    failed,
                    timeouts,
                    unusable,
                    (System.nanoTime() - startNanos) / 1_000_000
            );
        }
    }

    private record Reply(
            DnsWire.Message message,
            String server,
            DnsWire.Record delegation
    ) {}

    // ---------------------------------------------------------------
    // Entry point

    Resolution resolve(String input, int type)
            throws ResolutionException {

        Context ctx = new Context();
        long start = System.nanoTime();

        try {
            DnsWire.Message message = resolveInternal(
                    DnsWire.absolute(input),
                    type,
                    0,
                    ctx
            );

            return new Resolution(
                    message,
                    ctx.path,
                    ctx.delegations,
                    ctx.stats(start)
            );

        } catch (IOException | IllegalArgumentException e) {
            throw new ResolutionException(
                    e.getMessage(),
                    e,
                    ctx.path,
                    ctx.stats(start)
            );
        }
    }

    // ---------------------------------------------------------------
    // Iterative resolution

    private DnsWire.Message resolveInternal(
            String qname,
            int qtype,
            int depth,
            Context ctx
    ) throws IOException {

        if (depth > MAX_HOPS) {
            throw new IOException(
                    "Maximum CNAME/delegation depth exceeded"
            );
        }

        try {
            DnsWire.encodeName(qname);
        } catch (IllegalArgumentException e) {
            throw new IOException(
                    "Invalid DNS name " + qname + ": " + e.getMessage()
            );
        }

        String key = qname.toLowerCase(Locale.ROOT) + "/" + qtype;

        if (!ctx.active.add(key)) {
            throw new IOException(
                    "Resolution loop detected at " + key
            );
        }

        try {
            // Check negative and positive cache before contacting DNS servers.
            DnsWire.Message cached = checkCache(qname, qtype);

            if (cached != null) {
                ctx.path.add(
                        "CACHE HIT: " + qname + " "
                                + DnsWire.typeName(qtype)
                );
                return cached;
            }

            ctx.path.add(
                    "CACHE MISS: " + qname + " "
                            + DnsWire.typeName(qtype)
            );

            List<String> servers = new ArrayList<>(ROOTS);
            String zone = ".";

            if (depth == 0) {
                ctx.delegations.add(zone);
            }

            Set<String> visited = new HashSet<>();

            for (int hop = 0; hop < MAX_HOPS; hop++) {

                Reply reply = askCandidates(
                        servers,
                        qname,
                        qtype,
                        zone,
                        ctx
                );

                DnsWire.Message response = reply.message();

                // Final answer or authoritative NXDOMAIN.
                if (response.rcode == 3
                        || hasRequestedAnswer(response, qname, qtype)) {

                    if (response.rcode == 3) {
                        storeNegative(qname, qtype, response);
                    }

                    DnsWire.Message combined = followCnames(
                            response,
                            qname,
                            qtype,
                            depth,
                            ctx
                    );

                    if (combined.rcode == 0) {
storePositive(qname, qtype, combined);
}

                    return combined;
                }

                DnsWire.Record delegation = reply.delegation();

                // Authoritative NODATA response.
                if (delegation == null) {
                    storeNegative(qname, qtype, response);
                    return response;
                }

                String delegated = delegation.name;

                if (depth == 0) {
                    ctx.delegations.add(delegated);
                }

                List<String> next = referralAddresses(
                        response,
                        delegated,
                        zone,
                        ctx
                );

                if (next.isEmpty()) {
                    next = resolveNameServers(
                            response,
                            delegated,
                            depth,
                            ctx
                    );
                }

                if (next.isEmpty()) {
                    throw new IOException(
                            "Referral for " + delegated
                                    + " has no usable glue or resolvable NS address"
                    );
                }

                next.removeIf(ip -> !visited.add(
                        delegated.toLowerCase(Locale.ROOT) + "@" + ip
                ));

                if (next.isEmpty()) {
                    throw new IOException(
                            "Delegation loop detected at " + delegated
                    );
                }

                servers = next;
                zone = delegated;
            }

            throw new IOException(
                    "Maximum delegation hops exceeded for " + qname
            );

        } finally {
            ctx.active.remove(key);
        }
    }

    // ---------------------------------------------------------------
    // Cache integration

    private DnsWire.Message checkCache(
            String qname,
            int qtype
    ) throws IOException {

        Integer negative = cache.getNegative(
                qname,
                qtype,
                DnsWire.IN
        );

        if (negative != null) {
            cache.recordQueryHit();
            DnsWire.Message message = new DnsWire.Message();
            message.rcode = negative;
            message.authoritative = true;
            return message;
        }

        List<DnsResourceRecord> records = cache.get(
                qname,
                qtype,
                DnsWire.IN
        );

        if (records == null || records.isEmpty()) {
            cache.recordQueryMiss();
            return null;
        }

        cache.recordQueryHit();

        DnsWire.Message message = new DnsWire.Message();

        for (DnsResourceRecord record : records) {
            message.answers.add(toWireRecord(record));
        }

        return message;
    }

    private void storePositive(
            String qname,
            int qtype,
            DnsWire.Message message
    ) {
List<DnsResourceRecord> records = new ArrayList<>();

        for (DnsWire.Record record : message.answers) {
if (record.sourceRecord == null) {
                continue;
            }

            if (DnsWire.absolute(record.name).equalsIgnoreCase(DnsWire.absolute(qname))
                    && record.type == qtype
                    && record.sourceRecord.getRecordClass()
                            == DnsWire.IN) {

                records.add(record.sourceRecord);
            }
        }

        if (!records.isEmpty()) {
            cache.put(
                    qname,
                    qtype,
                    DnsWire.IN,
                    records
            );
        }
    }

    private void storeNegative(
            String qname,
            int qtype,
            DnsWire.Message message
    ) {

        if (message.rcode != 0 && message.rcode != 3) {
            return;
        }

        if (message.rcode == 0 && !message.authoritative) {
            return;
        }

        for (DnsWire.Record record : message.authority) {

            if (record.type != DnsWire.SOA
                    || record.sourceRecord == null) {
                continue;
            }

            Object value = record.sourceRecord.getRdataValue();

            if (!(value instanceof DnsRdataCodec.SoaData soa)) {
                continue;
            }

            cache.putNegative(
                    qname,
                    qtype,
                    DnsWire.IN,
                    message.rcode,
                    record.sourceRecord.getTtl(),
                    soa.minimum()
            );

            return;
        }
    }

    private DnsWire.Record toWireRecord(
            DnsResourceRecord record
    ) throws IOException {

        Object value = record.getRdataValue();
        String data;

        try {
            data = switch (record.getType()) {

                case DnsRdataCodec.TYPE_A,
                     DnsRdataCodec.TYPE_AAAA ->
                        InetAddress.getByAddress((byte[]) value)
                                .getHostAddress();

                case DnsRdataCodec.TYPE_NS,
                     DnsRdataCodec.TYPE_CNAME ->
                        (String) value;

                case DnsRdataCodec.TYPE_MX -> {
                    DnsRdataCodec.MxData mx =
                            (DnsRdataCodec.MxData) value;

                    yield mx.preference() + " " + mx.exchange();
                }

                case DnsRdataCodec.TYPE_SOA -> {
                    DnsRdataCodec.SoaData soa =
                            (DnsRdataCodec.SoaData) value;

                    yield soa.mname() + " "
                            + soa.rname() + " "
                            + soa.serial() + " "
                            + soa.refresh() + " "
                            + soa.retry() + " "
                            + soa.expire() + " "
                            + soa.minimum();
                }

                case DnsRdataCodec.TYPE_TXT -> {
                    @SuppressWarnings("unchecked")
                    List<String> strings = (List<String>) value;

                    List<String> quoted = new ArrayList<>();

                    for (String string : strings) {
                        quoted.add("\"" + string + "\"");
                    }

                    yield String.join(" ", quoted);
                }

                default -> throw new IOException(
                        "Unsupported cached record type: "
                                + record.getType()
                );
            };

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(
                    "Could not decode cached record",
                    e
            );
        }

        long rawTtl = record.getTtl();

        int ttl = rawTtl > Integer.MAX_VALUE
                ? 0
                : (int) rawTtl;

        return new DnsWire.Record(
                record.getName(),
                record.getType(),
                ttl,
                data,
                record
        );
    }

    // ---------------------------------------------------------------
    // Name server address resolution

    private List<String> resolveNameServers(
            DnsWire.Message response,
            String delegated,
            int depth,
            Context ctx
    ) {

        List<String> addresses = new ArrayList<>();

        for (DnsWire.Record ns : response.authority) {

            if (ns.type != DnsWire.NS
                    || !ns.name.equalsIgnoreCase(delegated)) {
                continue;
            }

            try {
                DnsWire.Message nsA = resolveInternal(
                        ns.data,
                        DnsWire.A,
                        depth + 1,
                        ctx
                );

                for (DnsWire.Record a : nsA.answers) {
                    if (a.type == DnsWire.A
                            && !addresses.contains(a.data)) {
                        addresses.add(a.data);
                    }
                }

            } catch (IOException e) {
                ctx.path.add(
                        "   could not resolve NS " + ns.data
                                + ": " + e.getMessage()
                );
            }

            if (!addresses.isEmpty()) {
                break;
            }
        }

        return addresses;
    }

    // ---------------------------------------------------------------
    // Candidate server selection

    private Reply askCandidates(
            List<String> candidates,
            String qname,
            int qtype,
            String zone,
            Context ctx
    ) throws IOException {

        List<String> remaining = new ArrayList<>(candidates);
        IOException last = null;

        while (!remaining.isEmpty()) {

            Transport.TransportReply tr;

            ctx.queries++;

            try {
                tr = transport.query(
                        List.copyOf(remaining),
                        qname,
                        qtype
                );

            } catch (TransportFailure e) {

                ctx.packets += e.packetsSent;
                last = e;

                if (e.badServer != null) {
                    ctx.unusable++;

                    ctx.path.add(
                            "   server " + e.badServer
                                    + " unusable: " + e.getMessage()
                    );

                    remaining.remove(e.badServer);
                    continue;
                }

                ctx.failed++;

                if (isTimeout(e)) {
                    ctx.timeouts++;
                }

                ctx.path.add(
                        "   no server answered for " + qname
                                + ": " + e.getMessage()
                );

                break;

            } catch (IOException e) {

                last = e;
                ctx.failed++;

                if (isTimeout(e)) {
                    ctx.timeouts++;
                }

                ctx.path.add(
                        "   no server answered for " + qname
                                + ": " + e.getMessage()
                );

                break;
            }

            ctx.packets += tr.packetsSent();

            DnsWire.Message message = tr.message();
            String ip = tr.server();

            ctx.path.add(
                    "-> " + ip
                            + " queried for " + qname
                            + " " + DnsWire.typeName(qtype)
                            + " [rcode=" + message.rcode + "]"
                            + (tr.usedTcp()
                                    ? " [TCP fallback]"
                                    : tr.packetsSent() > 1
                                            ? " [" + tr.packetsSent()
                                                    + " packets sent]"
                                            : "")
            );

            String problem = null;
            DnsWire.Record delegation = null;

            if (message.rcode == 3) {

                if (!message.authoritative) {
                    problem = "NXDOMAIN without AA";
                }

            } else if (message.rcode != 0) {

                problem = "RCODE " + message.rcode;

            } else if (!hasRequestedAnswer(
                    message, qname, qtype)) {

                delegation = bestDelegation(
                        message.authority,
                        qname
                );

                if (delegation != null) {

                    if (!DnsWire.isSubdomain(
                            delegation.name, zone)
                            || delegation.name.equalsIgnoreCase(zone)) {

                        problem = "referral to "
                                + delegation.name
                                + " does not descend from " + zone;
                    }

                } else if (!message.authoritative) {

                    problem = "lame: no answer, no referral, AA=0";
                }
            }

            if (problem == null) {
                return new Reply(message, ip, delegation);
            }

            ctx.unusable++;

            last = new IOException(
                    "server " + ip + " unusable: " + problem
            );

            ctx.path.add(
                    "   server " + ip + " unusable: " + problem
            );

            if (!remaining.remove(ip)) {
                remaining.remove(0);
            }
        }

        throw new IOException(
                "All candidate name servers failed for " + qname,
                last
        );
    }

    private static boolean isTimeout(Throwable e) {

        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof SocketTimeoutException) {
                return true;
            }
        }

        return false;
    }

    // ---------------------------------------------------------------
    // CNAME handling

    private boolean hasRequestedAnswer(
            DnsWire.Message message,
            String name,
            int type
    ) {

        for (DnsWire.Record record : message.answers) {

            if (DnsWire.absolute(record.name).equalsIgnoreCase(DnsWire.absolute(name))
                    && (record.type == type
                            || record.type == DnsWire.CNAME)) {
                return true;
            }
        }

        return false;
    }

    private DnsWire.Message followCnames(
            DnsWire.Message initial,
            String qname,
            int qtype,
            int depth,
            Context ctx
    ) throws IOException {

        DnsWire.Message combined = initial.copy();

        // A CNAME query asks for the alias record itself.
        if (qtype == DnsWire.CNAME) {
            return combined;
        }

        String current = qname;

        Set<String> seen = new HashSet<>();
        seen.add(current.toLowerCase(Locale.ROOT));

        int links = 0;

        while (true) {

            DnsWire.Record link = findCname(combined, current);

            if (link == null) {
                break;
            }

            current = DnsWire.absolute(link.data);

            if (!seen.add(current.toLowerCase(Locale.ROOT))) {
                throw new IOException("CNAME loop at " + current);
            }

            if (++links > MAX_HOPS) {
                throw new IOException(
                        "CNAME chain exceeds " + MAX_HOPS + " links"
                );
            }
        }

        if (hasType(combined, current, qtype)
                || combined.rcode != 0) {
            return combined;
        }

        DnsWire.Message target = resolveInternal(
                current,
                qtype,
                depth + 1,
                ctx
        );

        for (DnsWire.Record record : target.answers) {
            if (!combined.answers.contains(record)) {
                combined.answers.add(record);
            }
        }

        combined.rcode = target.rcode;
        combined.authority = new ArrayList<>(target.authority);
        combined.authoritative = target.authoritative;

        return combined;
    }

    private DnsWire.Record findCname(
            DnsWire.Message message,
            String name
    ) {

        for (DnsWire.Record record : message.answers) {

            if (record.type == DnsWire.CNAME
                    && DnsWire.absolute(record.name).equalsIgnoreCase(DnsWire.absolute(name))) {
                return record;
            }
        }

        return null;
    }

    private boolean hasType(
            DnsWire.Message message,
            String name,
            int type
    ) {

        for (DnsWire.Record record : message.answers) {

            if (record.type == type
                    && DnsWire.absolute(record.name).equalsIgnoreCase(DnsWire.absolute(name))) {
                return true;
            }
        }

        return false;
    }

    // ---------------------------------------------------------------
    // Referrals and glue

    private DnsWire.Record bestDelegation(
            List<DnsWire.Record> authority,
            String qname
    ) {

        DnsWire.Record best = null;

        for (DnsWire.Record record : authority) {

            if (record.type == DnsWire.NS
                    && DnsWire.isSubdomain(qname, record.name)
                    && (best == null
                            || record.name.length() > best.name.length())) {

                best = record;
            }
        }

        return best;
    }

    private List<String> referralAddresses(
            DnsWire.Message message,
            String delegatedZone,
            String respondingZone,
            Context ctx
    ) {

        Set<String> nsNames = new HashSet<>();

        for (DnsWire.Record record : message.authority) {

            if (record.type == DnsWire.NS
                    && record.name.equalsIgnoreCase(delegatedZone)) {

                nsNames.add(record.data.toLowerCase(Locale.ROOT));
            }
        }

        Set<String> ipv4 = new LinkedHashSet<>();
        Set<String> ipv6 = new LinkedHashSet<>();

        for (DnsWire.Record record : message.additional) {

            if (!nsNames.contains(
                    record.name.toLowerCase(Locale.ROOT))) {
                continue;
            }

            if (record.type != DnsWire.A
                    && record.type != DnsWire.AAAA) {
                continue;
            }

            if (!DnsWire.isSubdomain(
                    record.name, respondingZone)) {

                ctx.path.add(
                        "   ignored out-of-bailiwick glue "
                                + record.name + " -> " + record.data
                                + " (server zone " + respondingZone + ")"
                );

                continue;
            }

            if (record.type == DnsWire.A) {
                ipv4.add(record.data);
            } else {
                ipv6.add(record.data);
            }
        }

        List<String> result = new ArrayList<>(ipv4);
        result.addAll(ipv6);

        return result;
    }
}
