package org.torproject.onionmasq.circuit;

import androidx.annotation.Nullable;

import org.torproject.onionmasq.events.RelayDetails;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class Circuit {
    private final ArrayList<RelayDetails> relayDetails;
    private final String torDstDomain;

    public Circuit(List<RelayDetails> relayDetails, String torDst) {
        if (relayDetails != null) {
            this.relayDetails = new ArrayList<>(relayDetails);
        } else {
            this.relayDetails = new ArrayList<>();
        }
        this.torDstDomain = getDomainFrom(torDst);
    }

    public ArrayList<RelayDetails> getRelayDetails() {
        return relayDetails;
    }

    public String getDestinationDomain() {
        return torDstDomain;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Circuit)) return false;

        Circuit circuit = (Circuit) o;

        return Objects.equals(torDstDomain, circuit.torDstDomain) &&
                relayDetails.size() == circuit.relayDetails.size() &&
                relayDetails.containsAll(circuit.relayDetails);
    }

    @Override
    public int hashCode() {
        int result = relayDetails.hashCode();
        result = 31 * result + (torDstDomain != null ? torDstDomain.hashCode() : 0);
        return result;
    }

    @Nullable
    private String getDomainFrom(String hostPortTuple) {
        if (hostPortTuple == null) {
            return null;
        }

        int i = hostPortTuple.indexOf(":");
        if (i < 0) {
            return hostPortTuple;
        }

        return hostPortTuple.substring(0, i);
    }
}
