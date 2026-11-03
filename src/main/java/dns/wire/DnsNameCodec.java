
package dns.wire;

import java.io.ByteArrayOutputStream;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Shared DNS domain-name encoder and decoder.
 *
 * Supports RFC 1035 label encoding and compression pointers.
 */
public final class DnsNameCodec {

    private DnsNameCodec() {
    }

    /**
     * Encodes a domain name into DNS wire format.
     *
     * The output must represent the complete DNS message from offset zero.
     * The compression map must be shared across message sections.
     */
    public static void encode(
            String name,
            ByteArrayOutputStream output,
            Map<String, Integer> compressionMap) {

        if (name == null || output == null ||
                compressionMap == null) {
            throw new IllegalArgumentException(
                    "Arguments cannot be null"
            );
        }

        if (name.equals(".") || name.isEmpty()) {
            output.write(0);
            return;
        }

        if (name.endsWith(".")) {
            name = name.substring(0, name.length() - 1);
        }

        if (name.isEmpty()) {
            output.write(0);
            return;
        }

        String[] labels = name.split("\\.", -1);
        String[] asciiLabels = new String[labels.length];

        int expandedLength = 1;

        for (int i = 0; i < labels.length; i++) {

            if (labels[i].isEmpty()) {
                throw new IllegalArgumentException(
                        "Domain contains an empty label"
                );
            }

            String ascii = IDN.toASCII(
                    labels[i],
                    IDN.USE_STD3_ASCII_RULES
            );

            byte[] bytes = ascii.getBytes(
                    StandardCharsets.US_ASCII
            );

            if (bytes.length == 0 || bytes.length > 63) {
                throw new IllegalArgumentException(
                        "Invalid DNS label length"
                );
            }

            expandedLength += bytes.length + 1;
            asciiLabels[i] = ascii;
        }

        if (expandedLength > 255) {
            throw new IllegalArgumentException(
                    "DNS name exceeds 255 bytes"
            );
        }

        for (int i = 0; i < asciiLabels.length; i++) {

            StringBuilder suffixBuilder = new StringBuilder();

            for (int j = i; j < asciiLabels.length; j++) {
                if (j > i) {
                    suffixBuilder.append('.');
                }
                suffixBuilder.append(asciiLabels[j]);
            }

            String suffix = suffixBuilder.toString();

            String key = suffix.toLowerCase(Locale.ROOT);

            Integer pointer = compressionMap.get(key);

            if (pointer != null &&
                    pointer >= 0 &&
                    pointer < 0x4000) {

                output.write(0xC0 | ((pointer >>> 8) & 0x3F));
                output.write(pointer & 0xFF);
                return;
            }

            int currentOffset = output.size();

            if (currentOffset < 0x4000) {
                compressionMap.putIfAbsent(
                        key, currentOffset
                );
            }

            byte[] labelBytes = asciiLabels[i].getBytes(
                    StandardCharsets.US_ASCII
            );

            output.write(labelBytes.length);
            output.writeBytes(labelBytes);
        }

        output.write(0);
    }

    /**
     * Decodes a domain name, following compression pointers.
     *
     * nextOffset represents the position immediately after the
     * original encoded name, not the final pointer target.
     */
    public static Decoded decode(
            byte[] message,
            int offset) {

        if (message == null) {
            throw new IllegalArgumentException(
                    "Message cannot be null"
            );
        }

        if (offset < 0 || offset >= message.length) {
            throw new IllegalArgumentException(
                    "Invalid DNS name offset"
            );
        }

        StringBuilder name = new StringBuilder();

        Set<Integer> visitedOffsets = new HashSet<>();

        int position = offset;
        int nextOffset = -1;

        int expandedLength = 1;

        while (true) {

            if (position >= message.length) {
                throw new IllegalArgumentException(
                        "Truncated DNS name"
                );
            }

            if (!visitedOffsets.add(position)) {
                throw new IllegalArgumentException(
                        "DNS compression pointer loop detected"
                );
            }

            int length = message[position] & 0xFF;

            // Compression pointer: binary prefix 11.
            if ((length & 0xC0) == 0xC0) {

                if (position + 1 >= message.length) {
                    throw new IllegalArgumentException(
                            "Truncated compression pointer"
                    );
                }

                int pointer = ((length & 0x3F) << 8)
                        | (message[position + 1] & 0xFF);

                // RFC 1035 compression references an earlier name.
                if (pointer >= position) {
                    throw new IllegalArgumentException(
                            "Invalid forward compression pointer"
                    );
                }

                if (pointer >= message.length) {
                    throw new IllegalArgumentException(
                            "Compression pointer outside message"
                    );
                }

                if (nextOffset == -1) {
                    nextOffset = position + 2;
                }

                position = pointer;
                continue;
            }

            // Other extended label types are not supported.
            if ((length & 0xC0) != 0) {
                throw new IllegalArgumentException(
                        "Unsupported DNS label encoding"
                );
            }

            position++;

            // Zero-length label marks the root.
            if (length == 0) {

                if (nextOffset == -1) {
                    nextOffset = position;
                }

                break;
            }

            if (length > 63 ||
                    position + length > message.length) {

                throw new IllegalArgumentException(
                        "Invalid or truncated DNS label"
                );
            }

            expandedLength += length + 1;

            if (expandedLength > 255) {
                throw new IllegalArgumentException(
                        "Expanded DNS name exceeds 255 bytes"
                );
            }

            if (name.length() > 0) {
                name.append('.');
            }

            name.append(new String(
                    message,
                    position,
                    length,
                    StandardCharsets.US_ASCII
            ));

            position += length;
        }

        return new Decoded(name.toString(), nextOffset);
    }

    /**
     * Decoded DNS name and next position in the original message.
     */
    public record Decoded(
            String name,
            int nextOffset) {
    }
}
