package org.torproject.onionmasq.errors;

/**
 * The exception (parent) class for most things that can go wrong while using the onionmasq VPN.
 *
 * This should only be used for expected error conditions.
 * Rust panics, being by definition unexpected, are represented with RustPanicException instead
 * (which is a runtime/unchecked exception class).
 */
public class OnionmasqException extends Exception {
    public OnionmasqException(String message) {
        super(message);
    }

}
