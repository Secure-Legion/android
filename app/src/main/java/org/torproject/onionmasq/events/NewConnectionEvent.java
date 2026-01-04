package org.torproject.onionmasq.events;

import java.util.List;

/**
 * Notification about a new connection successfully completing.
 *
 * You should ideally keep a map keyed on (proxySrc, proxyDst) and use it to keep track of
 * open connections -- for example, to track when the connection closes again with a
 * ClosedConnectionEvent.
 */
public class NewConnectionEvent extends OnionmasqEvent {
    /**
     * The source IP:port for the connection, from the Android side.
     */
    public String proxySrc;
    /**
     * The destination IP:port *on the VPN side*, i.e. a fake address the VPN gave out.
     */
    public String proxyDst;
    /**
     * The actual address (IP:port, or hostname:port) we tried to reach over the Tor network.
     */
    public String torDst;
    /**
     * The Android app UID of the app that made the connection.
     */
    public int appId;
    /**
     * A list of relays involved in the connection's circuit.
     */
    public List<RelayDetails> circuit;
}
