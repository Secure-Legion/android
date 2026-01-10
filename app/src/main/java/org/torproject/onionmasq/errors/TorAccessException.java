package org.torproject.onionmasq.errors;

/**
 * An error trying to connect to the Tor network.
 *
 * Corresponds to the `TorAccessFailed` arti error kind.
 */
public class TorAccessException extends ArtiException {
    public TorAccessException(String message) {
        super(message);
    }
}
