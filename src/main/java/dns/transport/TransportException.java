package dns.transport;

import java.io.IOException;

/** Thrown when every candidate server failed on every retry. */
public class TransportException extends IOException {
    public TransportException(String msg, Throwable cause) { super(msg, cause); }
}
