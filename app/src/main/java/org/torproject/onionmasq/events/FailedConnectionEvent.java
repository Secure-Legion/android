package org.torproject.onionmasq.events;

/**
 * Notification about a connection event failing.
 *
 * You might also receive a ClosedConnectionEvent after this.
 */
public class FailedConnectionEvent extends OnionmasqEvent {
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
     * What went wrong. This will hopefully become more advanced than a string in later versions.
     */
    public String error;
}
