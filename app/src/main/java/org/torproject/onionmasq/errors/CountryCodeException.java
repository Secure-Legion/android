package org.torproject.onionmasq.errors;

/**
 * An invalid 2-letter country code was passed to setCountryCode().
 */
public class CountryCodeException extends OnionmasqException {
    public CountryCodeException(String message) {
        super(message);
    }
}
