package org.torproject.onionmasq.errors;

/**
 * A generic error setting up or using the Arti Tor client library.
 */
public class ArtiException extends OnionmasqException {
    public ArtiException(String message) {
        super(message);
    }
}
