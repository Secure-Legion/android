package org.torproject.onionmasq.events;

import java.util.HashMap;

/**
 * A new directory was downloaded.
 *
 * Currently, this is only used for relay country code information.
 */
public class NewDirectoryEvent extends OnionmasqEvent {
    /**
     * An index of 2-letter country code to number of relays in that country.
     */
    public HashMap<String, Long> relaysByCountry;
}
