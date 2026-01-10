package org.torproject.onionmasq.events;

import androidx.annotation.Nullable;

/**
 * Notification about a connection having closed, either cleanly or uncleanly.
 *
 * This may be sent after either a NewConnectionEvent or FailedConnectionEvent, but the consumer
 * should tolerate it not being matched up with either of those.
 */
public class ClosedConnectionEvent extends OnionmasqEvent {
    /**
     * The source IP:port for the connection, from the Android side.
     */
    public String proxySrc;
    /**
     * The destination IP:port *on the VPN side*, i.e. a fake address the VPN gave out.
     */
    public String proxyDst;
    /**
     * If the connection closed normally, this is null. If not, this contains a human-readable
     * error describing what went wrong on the connection.
     */
    @Nullable
    public String error;
}
