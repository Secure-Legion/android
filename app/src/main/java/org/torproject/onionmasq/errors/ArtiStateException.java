package org.torproject.onionmasq.errors;

/**
 * An error occurred with something in Arti's state or cache directories.
 *
 * If this happens, it might be a good idea to try wiping the state and cache directories and
 * attempting to run the VPN again.
 */
public class ArtiStateException extends ArtiException {
    public ArtiStateException(String message) {
        super(message);
    }
}
