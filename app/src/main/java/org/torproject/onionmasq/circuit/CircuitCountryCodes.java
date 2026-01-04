package org.torproject.onionmasq.circuit;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * CircuitCountryCodes is a list whose elements represent the country codes
 * of the hops involved in a Tor circuit
 */
public class CircuitCountryCodes {

    private final List<String> countryCode;
    public CircuitCountryCodes(ArrayList<String> countryCodes) {
        this.countryCode = countryCodes;
    }

    public List<String> getCountryCodes() {
        return countryCode;
    }

    @Override
    public int hashCode() {
        return countryCode != null ? countryCode.hashCode() : 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CircuitCountryCodes that)) return false;

        return Objects.equals(countryCode, that.countryCode);
    }
}
