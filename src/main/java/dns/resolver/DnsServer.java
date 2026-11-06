package dns.resolver;

import dns.wire.DnsHeader;
import dns.wire.DnsQuestion;
import dns.wire.DnsResourceRecord;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

final class DnsServer implements AutoCloseable {

    private static final int UDP_LIMIT = 512;

    private final IterativeResolver resolver;
    private final DatagramSocket udpSocket;
    private final ServerSocket tcpServer;
    private final ExecutorService workers =
            Executors.newFixedThreadPool(12);
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final CountDownLatch stopped = new CountDownLatch(1);

    DnsServer(IterativeResolver resolver, int port) throws IOException {
        if (resolver == null) {
            throw new IllegalArgumentException("Resolver cannot be null");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Invalid port: " + port);
        }

        this.resolver = resolver;
        this.udpSocket = new DatagramSocket(port);

        try {
            this.tcpServer = new ServerSocket(port);
        } catch (IOException e) {
            udpSocket.close();
            throw e;
        }
    }

    void start() {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("DNS server already started");
        }

        Thread udpThread = new Thread(this::udpLoop, "dns-udp-listener");
        Thread tcpThread = new Thread(this::tcpLoop, "dns-tcp-listener");

        udpThread.setDaemon(true);
        tcpThread.setDaemon(true);

        udpThread.start();
        tcpThread.start();

        System.out.println("DNS server listening on UDP and TCP port "
                + tcpServer.getLocalPort());
    }

    void await() throws InterruptedException {
        stopped.await();
    }

    private void udpLoop() {
        while (running.get()) {
            try {
                byte[] buffer = new byte[4096];
                DatagramPacket request =
                        new DatagramPacket(buffer, buffer.length);

                udpSocket.receive(request);
                System.out.println("[UDP] Received " + request.getLength() + " bytes");

                byte[] query = new byte[request.getLength()];
                System.arraycopy(
                        request.getData(),
                        request.getOffset(),
                        query,
                        0,
                        request.getLength()
                );

                InetAddress address = request.getAddress();
                int port = request.getPort();

                workers.submit(() -> {
                    byte[] response = process(query, false);
                    if (response == null || !running.get()) {
                        return;
                    }

                    try {
                        DatagramPacket reply = new DatagramPacket(
                                response, response.length, address, port
                        );
                        udpSocket.send(reply);
                    } catch (IOException e) {
                        if (running.get()) {
                            System.err.println("UDP response failed: "
                                    + e.getMessage());
                        }
                    }
                });

            } catch (SocketException e) {
                if (running.get()) {
                    System.err.println("UDP listener error: " + e.getMessage());
                }
                break;
            } catch (IOException e) {
                if (running.get()) {
                    System.err.println("UDP receive error: " + e.getMessage());
                }
            }
        }
    }

    private void tcpLoop() {
        while (running.get()) {
            try {
                Socket socket = tcpServer.accept();
                workers.submit(() -> handleTcp(socket));
            } catch (SocketException e) {
                if (running.get()) {
                    System.err.println("TCP listener error: " + e.getMessage());
                }
                break;
            } catch (IOException e) {
                if (running.get()) {
                    System.err.println("TCP accept error: " + e.getMessage());
                }
            }
        }
    }

    private void handleTcp(Socket socket) {
        try (socket;
             DataInputStream input =
                     new DataInputStream(socket.getInputStream());
             DataOutputStream output =
                     new DataOutputStream(socket.getOutputStream())) {

            socket.setSoTimeout(10000);

            int length = input.readUnsignedShort();
            if (length < DnsHeader.HEADER_LENGTH) {
                return;
            }

            byte[] query = new byte[length];
            input.readFully(query);
            System.out.println("[TCP] Received " + length + " bytes");

            byte[] response = process(query, true);
            if (response == null || response.length > 65535) {
                return;
            }

            output.writeShort(response.length);
            output.write(response);
            output.flush();

        } catch (IOException e) {
            System.err.println("TCP client error: " + e.getMessage());
        }
    }

    private byte[] process(byte[] packet, boolean tcp) {
        if (packet == null || packet.length < DnsHeader.HEADER_LENGTH) {
            return null;
        }

        DnsHeader header;

        try {
            header = DnsHeader.fromBytes(packet);
        } catch (IllegalArgumentException e) {
            return null;
        }

        int queryFlags = header.getFlags();
        DnsQuestion question = null;
        int rcode = 0;

        if ((queryFlags & 0x8000) != 0
                || (queryFlags & 0x7800) != 0
                || header.getQdCount() != 1) {
            return buildResponse(header, queryFlags, null, 1,
                    null, false);
        }

        try {
            DnsQuestion.Decoded decoded =
                    DnsQuestion.decode(packet, DnsHeader.HEADER_LENGTH);

            question = decoded.question();

            if (decoded.nextOffset() > packet.length) {
                return buildResponse(header, queryFlags, null, 1,
                        null, false);
            }

            if (question.getQclass() != DnsQuestion.CLASS_IN) {
                return buildResponse(header, queryFlags, question, 5,
                        null, false);
            }

            if (!supportedType(question.getQtype())) {
                return buildResponse(header, queryFlags, question, 4,
                        null, false);
            }

            System.out.println("[DNS] Starting resolution");
            Resolution result = resolver.resolve(
                    question.getQname(),
                    question.getQtype()
            );

            rcode = result.rcode;

            byte[] response = buildResponse(
                    header, queryFlags, question, rcode, result, false
            );

            if (!tcp && response.length > UDP_LIMIT) {
                return buildResponse(
                        header, queryFlags, question, rcode, null, true
                );
            }

            return response;

        } catch (IllegalArgumentException e) {
            return buildResponse(header, queryFlags, question, 1,
                    null, false);
        } catch (ResolutionException e) {
            System.err.println("Resolution failed: " + e.getMessage());
            return buildResponse(header, queryFlags, question, 2,
                    null, false);
        } catch (RuntimeException e) {
            System.err.println("DNS request failed: " + e.getMessage());
            return buildResponse(header, queryFlags, question, 2,
                    null, false);
        }
    }

    private static boolean supportedType(int type) {
        return type == DnsWire.A
                || type == DnsWire.AAAA
                || type == DnsWire.NS
                || type == DnsWire.CNAME
                || type == DnsWire.MX
                || type == DnsWire.TXT
                || type == DnsWire.SOA;
    }

    private static byte[] buildResponse(
            DnsHeader requestHeader,
            int requestFlags,
            DnsQuestion question,
            int rcode,
            Resolution result,
            boolean truncated) {

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        // Reserve the 12-byte header so compression offsets are absolute.
        output.writeBytes(new byte[DnsHeader.HEADER_LENGTH]);

        Map<String, Integer> compression = new HashMap<>();

        int questionCount = 0;
        int answerCount = 0;
        int authorityCount = 0;

        try {
            if (question != null) {
                question.encodeTo(output, compression);
                questionCount = 1;
            }

            if (result != null && !truncated) {
                for (DnsWire.Record record : result.answers) {
                    if (record.sourceRecord != null) {
                        record.sourceRecord.encodeTo(output, compression);
                        answerCount++;
                    }
                }

                for (DnsWire.Record record : result.authority) {
                    if (record.sourceRecord != null) {
                        record.sourceRecord.encodeTo(output, compression);
                        authorityCount++;
                    }
                }
            }

            int flags = 0x8000
                    | (requestFlags & 0x7900)
                    | 0x0080
                    | (truncated ? 0x0200 : 0)
                    | (rcode & 0x000F);

            DnsHeader responseHeader = new DnsHeader(
                    requestHeader.getId(),
                    flags,
                    questionCount,
                    answerCount,
                    authorityCount,
                    0
            );

            byte[] body = output.toByteArray();
            byte[] headerBytes = responseHeader.toBytes();
            System.arraycopy(headerBytes, 0, body, 0, headerBytes.length);

            return body;

        } catch (RuntimeException e) {
            // Return SERVFAIL if a response record cannot be encoded.
            DnsHeader failure = new DnsHeader(
                    requestHeader.getId(),
                    0x8082 | (requestFlags & 0x7900),
                    0, 0, 0, 0
            );
            return failure.toBytes();
        }
    }

    @Override
    public void close() {
        if (running.getAndSet(false)) {
            udpSocket.close();

            try {
                tcpServer.close();
            } catch (IOException ignored) {
                // Socket is being shut down.
            }

            workers.shutdownNow();
            stopped.countDown();
        } else {
            udpSocket.close();

            try {
                tcpServer.close();
            } catch (IOException ignored) {
                // Already closed.
            }
        }
    }
}