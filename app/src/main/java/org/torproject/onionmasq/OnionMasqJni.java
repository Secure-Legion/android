package org.torproject.onionmasq;

import android.content.Context;
import android.os.Build;

import androidx.annotation.WorkerThread;

import org.torproject.onionmasq.errors.CountryCodeException;
import org.torproject.onionmasq.errors.OnionmasqException;
import org.torproject.onionmasq.errors.ProxyStoppedException;
import org.torproject.onionmasq.events.OnionmasqEvent;

public class OnionMasqJni {

    private static final String TAG = OnionMasqJni.class.getSimpleName();

    /**
     * Starts onionmasq to route all packets over the tun interface into the tor network.
     * If you call this method with a ptType, ptPort and bridgeLines, it's up to you
     * to start an unmanaged pluggable transport client beforehand.
     * The method is blocking and should be called from a worker thread.
     * @param filedescriptor the tun interface's filedescriptor
     * @param cacheDir temporary data dir
     * @param dataDir persistent data dir
     * @param ptType transport type of the unmanaged PT (e.g. snowflake, obfs4)
     * @param ptPort port the unmanaged PT client is listening on
     * @param bridgeLines a set of newline-separated bridge lines, or null if bridges are not to be used
     *
     * This function asserts ownership of `filedescriptor`. `filedescriptor` must not be used for
     * any purpose after calling this function.
     * */
    @WorkerThread
    public static native void runProxy(int filedescriptor, String cacheDir, String dataDir,  String ptType,
                                              long ptPort, String bridgeLines) throws OnionmasqException;

    /**
     * Stops the proxy.
     */
    public static native void closeProxy();

    /**
     * Check if the control channel of the onionmasq proxy exists. If so it is indicating onionmasq is running.
     */
    public static native boolean isRunning();

    /**
     * Initializes the logcat logging and the Java environment in Rust.
     * Call this method from the main thread and only once during the app's lifecycle.
     */
    public static native void init() throws OnionmasqException;


    /**
     * Set a path that the proxy should write a .pcap file of all observed traffic to.
     * Should be called only once prior to calling runProxy().
     *
     * FIXME(eta): This shouldn't have such stringent requirements, you should be able to turn it off, etc.
     *
     * @param path Path to write a pcap file to.
     */
    public static native void setPcapPath(String path);

    /**
     * Make traffic appear to come from a given country.
     * Passing null will unset the country code and make traffic come from any country again.
     * Throws an exception if the passed country code is invalid.
     *
     * @param countryCode an ISO 3166-1 alpha-2 country code, such as "IT" for Italy, or null to unset
     */
    public static native void setCountryCode(String countryCode) throws CountryCodeException;

    /**
     * Set the bridge lines to the configuration.
     *
     * @param lines the bridge lines to set.
     */
    public static native void setBridgeLines(String lines);

    /**
     * Set application UIDs that will be excluded from the VPN.
     */
    public static native void setExcludedUids(long[] uids);

    /**
     * Set a turn server config and enable UDP traffic via tor
     *
     * @param host turn server Hostname, IP, or Onion-Address
     * @param port turn server port
     * @param auth shared secret for authentication
     */
    public static native void setTurnServerConfig(String host, long port, String auth);

    /**
     * Informs onionmasq whether a working internet connection is available.
     * @param available
     */
    public static native void setInternetConnectivity(boolean available) throws ProxyStoppedException;

    /**
     * Get the number of bytes received over the network by the tunnel since start or last call to `resetCounters`.
     */
    public static native long getBytesReceived();

    /**
     * Get the number of bytes received by one app from the Tor network since start or last call to `resetCounters`.
     *
     * Note that the returned value does not include Tor network overhead (i.e. the extra bytes incurred by
     * packing the data into cells, etc.) -- it just measures the number of bytes copied from Tor to the app's
     * TCP sockets.
     *
     * @param appId the app ID to get statistics for
     */

    public static native long getBytesReceivedForApp(long appId);

    /**
     * Get the number of bytes sent over the network by the tunnel since start or last call to `resetCounters`.
     */
    public static native long getBytesSent();

    /**
     * Get the number of bytes sent by one app from the Tor network since start or last call to `resetCounters`.
     *
     * Note that the returned value does not include Tor network overhead (i.e. the extra bytes incurred by
     * packing the data into cells, etc.) -- it just measures the number of bytes copied from the app's
     * TCP sockets to Tor.
     *
     * @param appId the app ID to get statistics for
     */
    public static native long getBytesSentForApp(long appId);

    /**
     * Reset the packet counters returned by `getBytesReceived/Sent`, including their `ForApp` counterparts.
     */
    public static native void resetCounters();

    /**
     * Cause a running proxy to refresh all of its circuits; i.e., stop using the current set of circuits
     * for new connections and spawn some new ones instead.
     *
     * @throws ProxyStoppedException if the proxy was not running
     */
    public static native void refreshCircuits() throws ProxyStoppedException;

    /**
     * Does the same thing as `refreshCircuits`, but restricted to one app UID.
     *
     * @param appId the app UID to refresh circuits for
     * @throws ProxyStoppedException if the proxy was not running
     */
    public static native void refreshCircuitsForApp(long appId) throws ProxyStoppedException;

    /**
     * Returns an apps UID from a packets IP source and destination address.
     * This method doesn't block, i.e. no reverse name service lookup is performed.
     * IPv4 address byte array must be 4 bytes long and IPv6 byte array must be 16 bytes long
     * This method can be called from Rust after the Java environment has been initialized ({@link #init()}).
     * @param rawSourceAddress: the raw IP source address in network byte order (the highest order byte of the address is in rawSourceAddress[0]).
     * @param sourcePort: the source IP's port
     * @param rawDestinationAddress: the raw IP destination address in network byte order
     * @param destinationPort: the destination IP's port
     * @return an app's UID or -1 if no UID could be found
     */
    @SuppressWarnings("unused")
    public static int getConnectionOwnerUid(int protocol, byte[] rawSourceAddress, int sourcePort, byte[] rawDestinationAddress, int destinationPort) {
        return OnionMasq.getConnectionOwnerUid(protocol, rawSourceAddress, sourcePort, rawDestinationAddress, destinationPort);
    }

    /**
     * Protect a socket from VPN connections.
     * After protecting, data sent through this socket will go directly to the underlying network,
     * so its traffic will not be forwarded through the VPN. This method is useful if some connections
     * need to be kept outside of VPN.
     * For example, a VPN tunnel should protect itself if its destination is covered by VPN routes.
     * Otherwise its outgoing packets will be sent back to the VPN interface and cause an infinite loop.
     * This method will fail if the Android VPN Service is not prepared ({@link android.net.VpnService#prepare(Context)})
     * or is revoked.
     * The socket is NOT closed by this method.
     * @param socket fd of a socket
     * @return true on success.
     */
    @SuppressWarnings("unused")
    public static boolean protect(int socket) {
        return OnionMasq.protect(socket);
    }

    /**
     * Returns the Android SDK Version number.
     * This method can be called from Rust after the Java environment has been initialized ({@link #init()}).
     * @return Android SDK Version number
     */
    @SuppressWarnings("unused")
    public static int getAndroidAPI() {
        return Build.VERSION.SDK_INT;
    }

    @SuppressWarnings("unused")
    public static void postEvent(String update) {
        // NOTE(eta): we cannot log the `update` directly, since it might contain sensitive
        //            connection information!
        // Log.d(TAG, "postEvent: " + update);
        OnionMasq.handleEvent(OnionmasqEvent.fromJson(update));
    }

    static {
        System.loadLibrary("onionmasq_mobile");
    }
}
