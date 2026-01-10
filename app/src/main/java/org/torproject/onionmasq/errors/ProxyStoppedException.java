package org.torproject.onionmasq.errors;

/**
 * The caller tried to do something with the onionmasq proxy (e.g. stop it, or tell it
 * to refresh its circuits), but it was stopped when the command was attempted.
 */
public class ProxyStoppedException extends OnionmasqException {
    public ProxyStoppedException(String message) {
        super(message);
    }
}
