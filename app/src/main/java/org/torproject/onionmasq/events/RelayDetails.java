package org.torproject.onionmasq.events;

import androidx.annotation.Nullable;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/**
 * Information about a relay inside a connection's circuit.
 */
public class RelayDetails {
    /**
     * The RSA identity of the relay, if it has one.
     */
    @Nullable
    public String rsa_identity;
    /**
     * The Ed25519 identity of the relay, if it has one.
     */
    @Nullable
    public String ed_identity;
    /**
     * A list of IP address:port combinations this relay is reachable at.
     */
    public List<String> addresses;

    /**
     * The country code of the relay, if one is known.
     */
    @Nullable
    public String country_code;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RelayDetails)) return false;

        RelayDetails that = (RelayDetails) o;

        if (!Objects.equals(rsa_identity, that.rsa_identity))
            return false;
        if (!Objects.equals(ed_identity, that.ed_identity))
            return false;
        return (addresses == null && that.addresses == null) ||
                (addresses != null && that.addresses != null &&
                addresses.size() == that.addresses.size() &&
                new HashSet<>(addresses).containsAll(that.addresses));
    }

    @Override
    public int hashCode() {
        int result = rsa_identity != null ? rsa_identity.hashCode() : 0;
        result = 31 * result + (ed_identity != null ? ed_identity.hashCode() : 0);
        result = 31 * result + (addresses != null ? addresses.hashCode() : 0);
        return result;
    }
}
