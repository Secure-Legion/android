package org.torproject.onionmasq.errors;

/**
 * An exception raised when a configured bridge line could not be parsed by Arti.
 */
public class BridgelineException extends OnionmasqException {
    public BridgelineException(String message) {
        super(message);
    }
}
