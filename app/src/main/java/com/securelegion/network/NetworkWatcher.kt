package com.securelegion.network

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface

/**
 * Comprehensive network monitoring system that detects:
 * - Network available/lost events
 * - WiFi ↔ Mobile data switches
 * - IPv6-only networks
 * - Screen on/off events
 * - Doze mode changes (Android 6+)
 * - WiFi AP state changes
 * - WiFi P2P changes
 * - Airplane mode changes
 *
 * Implements strategic delays for different event types to allow
 * the network stack to stabilize before triggering Tor rehydration.
 */
class NetworkWatcher(
    private val context: Context,
    private val scope: kotlinx.coroutines.CoroutineScope = GlobalScope,
    private val onNetworkChanged: suspend (NetworkEvent) -> Unit
) {
    companion object {
        private const val TAG = "NetworkWatcher"

        // Undocumented WiFi AP intent
        private const val WIFI_AP_STATE_CHANGED_ACTION = "android.net.wifi.WIFI_AP_STATE_CHANGED"
    }

    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    private val handler = Handler(Looper.getMainLooper())

    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var broadcastReceiver: BroadcastReceiver? = null
    private var isRegistered = false

    // Track current network state
    private var hasNetworkConnection = false
    private var isWifiConnected = false
    private var isIpv6Only = false

    /**
     * Network event types with context information
     */
    sealed class NetworkEvent {
        data class Available(
            val hasInternet: Boolean,
            val isWifi: Boolean,
            val isIpv6Only: Boolean
        ) : NetworkEvent()

        object Lost : NetworkEvent()

        data class CapabilitiesChanged(
            val hasInternet: Boolean,
            val isWifi: Boolean,
            val isIpv6Only: Boolean
        ) : NetworkEvent()

        object ScreenOn : NetworkEvent()
        object ScreenOff : NetworkEvent()
        object DozeModeChanged : NetworkEvent()
        object WifiApStateChanged : NetworkEvent()
        object WifiP2pChanged : NetworkEvent()

        data class AirplaneModeChanged(
            val isEnabled: Boolean,
            val hasInternet: Boolean
        ) : NetworkEvent()
    }

    /**
     * Start comprehensive network monitoring
     */
    fun start() {
        if (isRegistered) {
            Log.d(TAG, "Network watcher already running")
            return
        }

        // Register NetworkCallback for real-time network events
        registerNetworkCallback()

        // Register BroadcastReceiver for system events
        registerBroadcastReceiver()

        // Check initial network state
        updateNetworkState()

        isRegistered = true
        Log.i(TAG, "Network watcher started")
    }

    /**
     * Stop all network monitoring
     */
    fun stop() {
        if (!isRegistered) {
            return
        }

        // Unregister NetworkCallback
        try {
            networkCallback?.let { connectivityManager.unregisterNetworkCallback(it) }
            networkCallback = null
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister network callback", e)
        }

        // Unregister BroadcastReceiver
        try {
            broadcastReceiver?.let { context.unregisterReceiver(it) }
            broadcastReceiver = null
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister broadcast receiver", e)
        }

        // Cancel pending callbacks
        handler.removeCallbacksAndMessages(null)

        isRegistered = false
        Log.d(TAG, "Network watcher stopped")
    }

    /**
     * Get current network status
     */
    fun getCurrentStatus(): NetworkEvent.Available {
        updateNetworkState()
        return NetworkEvent.Available(hasNetworkConnection, isWifiConnected, isIpv6Only)
    }

    private fun registerNetworkCallback() {
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i(TAG, "Network available")
                updateNetworkState()
                triggerEvent(NetworkEvent.Available(hasNetworkConnection, isWifiConnected, isIpv6Only))
            }

            override fun onLost(network: Network) {
                Log.w(TAG, "Network lost")
                hasNetworkConnection = false
                isWifiConnected = false
                isIpv6Only = false
                triggerEvent(NetworkEvent.Lost)
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                Log.i(TAG, "Network capabilities changed")
                updateNetworkState()
                triggerEvent(NetworkEvent.CapabilitiesChanged(hasNetworkConnection, isWifiConnected, isIpv6Only))
            }
        }

        try {
            connectivityManager.registerDefaultNetworkCallback(networkCallback!!)
            Log.d(TAG, "NetworkCallback registered")
        } catch (e: SecurityException) {
            Log.e(TAG, "Failed to register network callback - missing permission", e)
            // Fall back to basic wifi detection
            fallbackToWifiManager()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register network callback", e)
        }
    }

    private fun registerBroadcastReceiver() {
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_AIRPLANE_MODE_CHANGED)
            addAction(WIFI_AP_STATE_CHANGED_ACTION)
            addAction(android.net.wifi.p2p.WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)

            // Doze mode (Android 6+)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                addAction(android.os.PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
            }
        }

        broadcastReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                val action = intent?.action ?: return
                Log.i(TAG, "Received broadcast: $action")

                when (action) {
                    Intent.ACTION_SCREEN_ON -> {
                        // Delay 1 minute to allow network stack to settle
                        scheduleDelayedEvent(NetworkEvent.ScreenOn, 60_000)
                    }

                    Intent.ACTION_SCREEN_OFF -> {
                        // Delay 1 minute to allow network stack to settle
                        scheduleDelayedEvent(NetworkEvent.ScreenOff, 60_000)
                    }

                    android.os.PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                            // Delay 1 minute to allow network stack to settle
                            scheduleDelayedEvent(NetworkEvent.DozeModeChanged, 60_000)
                        }
                    }

                    WIFI_AP_STATE_CHANGED_ACTION -> {
                        // Delay 5 seconds to allow AP address to become visible
                        scheduleDelayedEvent(NetworkEvent.WifiApStateChanged, 5_000)
                    }

                    android.net.wifi.p2p.WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION -> {
                        // Delay 5 seconds to allow P2P address to become visible
                        scheduleDelayedEvent(NetworkEvent.WifiP2pChanged, 5_000)
                    }

                    Intent.ACTION_AIRPLANE_MODE_CHANGED -> {
                        val isEnabled = intent.getBooleanExtra("state", false)
                        Log.i(TAG, "Airplane mode: ${if (isEnabled) "ON" else "OFF"}")

                        // Delay 2 seconds to let network stabilize
                        handler.postDelayed({
                            updateNetworkState()
                            triggerEvent(NetworkEvent.AirplaneModeChanged(isEnabled, hasNetworkConnection))
                        }, 2_000)
                    }
                }
            }
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(broadcastReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                context.registerReceiver(broadcastReceiver, filter)
            }
            Log.d(TAG, "BroadcastReceiver registered")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register broadcast receiver", e)
        }
    }

    /**
     * Schedule a delayed event trigger
     */
    private fun scheduleDelayedEvent(event: NetworkEvent, delayMs: Long) {
        handler.postDelayed({
            updateNetworkState()
            triggerEvent(event)
        }, delayMs)
    }

    /**
     * Update internal network state by querying system
     */
    private fun updateNetworkState() {
        try {
            val activeNetwork = connectivityManager.activeNetwork
            val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)

            hasNetworkConnection = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
            isWifiConnected = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true

            // Check if network is IPv6-only
            isIpv6Only = if (hasNetworkConnection) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    isActiveNetworkIpv6Only(activeNetwork)
                } else {
                    areAllAvailableNetworksIpv6Only()
                }
            } else {
                false
            }

            Log.d(TAG, "Network state: connected=$hasNetworkConnection, wifi=$isWifiConnected, ipv6Only=$isIpv6Only")
        } catch (e: SecurityException) {
            Log.w(TAG, "Security exception checking network state - using fallback", e)
            fallbackToWifiManager()
        } catch (e: Exception) {
            Log.e(TAG, "Error updating network state", e)
        }
    }

    /**
     * Check if the active network is IPv6-only (Android 6+)
     */
    private fun isActiveNetworkIpv6Only(network: Network?): Boolean {
        if (network == null) return false

        try {
            val linkProps = connectivityManager.getLinkProperties(network) ?: return false

            var hasIpv6Unicast = false
            for (linkAddress in linkProps.linkAddresses) {
                val addr = linkAddress.address
                if (addr is Inet4Address) return false
                if (!addr.isMulticastAddress) hasIpv6Unicast = true
            }

            return hasIpv6Unicast
        } catch (e: Exception) {
            Log.w(TAG, "Error checking IPv6-only status", e)
            return false
        }
    }

    /**
     * Check if all available networks are IPv6-only (fallback for Android < 6)
     */
    private fun areAllAvailableNetworksIpv6Only(): Boolean {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return false

            var hasIpv6Unicast = false
            for (iface in interfaces.toList()) {
                if (iface.isLoopback || !iface.isUp) continue

                for (addr in iface.inetAddresses.toList()) {
                    if (addr is Inet4Address) return false
                    if (!addr.isMulticastAddress) hasIpv6Unicast = true
                }
            }

            return hasIpv6Unicast
        } catch (e: Exception) {
            Log.w(TAG, "Error checking IPv6-only status (fallback)", e)
            return false
        }
    }

    /**
     * Fallback to WifiManager when ConnectivityManager is unavailable
     */
    private fun fallbackToWifiManager() {
        Log.w(TAG, "Using WifiManager fallback for network detection")

        // Conservative: assume NO internet unless WiFi proves otherwise.
        // Previous optimistic default (true) caused false gate opens, rebind attempts,
        // and retry storms when ConnectivityManager threw SecurityException.
        isIpv6Only = false

        // Try to detect WiFi connection — only claim internet if WiFi is active
        isWifiConnected = try {
            val wifiInfo = wifiManager?.connectionInfo
            wifiInfo != null && wifiInfo.ipAddress != 0
        } catch (e: Exception) {
            Log.w(TAG, "Error checking WiFi state", e)
            false
        }
        hasNetworkConnection = isWifiConnected
    }

    /**
     * Trigger the network event callback
     */
    private fun triggerEvent(event: NetworkEvent) {
        Log.d(TAG, "Triggering event: ${event.javaClass.simpleName}")
        scope.launch(Dispatchers.Main) {
            try {
                onNetworkChanged(event)
            } catch (e: Exception) {
                Log.e(TAG, "Error in network event callback", e)
            }
        }
    }
}
