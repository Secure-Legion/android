package com.securelegion.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import com.securelegion.MainActivity
import com.securelegion.R
import org.torproject.onionmasq.ISocketProtect
import org.torproject.onionmasq.OnionMasq
import org.torproject.onionmasq.errors.OnionmasqException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VPN Service that routes all device traffic through Tor using OnionMasq.
 *
 * This service uses Android's VpnService API with systemExempted foreground service type
 * to avoid battery/wake lock restrictions. When enabled, all network traffic from the
 * device goes through the Tor network for maximum privacy.
 */
class TorVpnService : VpnService(), ISocketProtect {

    companion object {
        private const val TAG = "TorVpnService"
        const val ACTION_START_VPN = "com.securelegion.START_TOR_VPN"
        const val ACTION_STOP_VPN = "com.securelegion.STOP_TOR_VPN"

        // Use same channel AND same ID as TorService for unified notification
        private const val NOTIFICATION_CHANNEL_ID = "tor_service_channel"
        private const val NOTIFICATION_ID = 1001 // Same ID as TorService - they share one notification

        @Volatile
        private var running = AtomicBoolean(false)

        fun isRunning(): Boolean = running.get()
    }

    private val executor = Executors.newSingleThreadExecutor()
    private val binder = TorVpnServiceBinder(this)

    private var vpnInterface: ParcelFileDescriptor? = null
    private var bandwidthUpdateThread: Thread? = null

    inner class TorVpnServiceBinder(private val socketProtect: ISocketProtect) : Binder(), ISocketProtect {
        override fun protect(socket: Int): Boolean {
            return socketProtect.protect(socket)
        }
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "TorVpnService created")

        // Initialize OnionMasq
        try {
            OnionMasq.init(applicationContext)
            OnionMasq.bindVPNService(TorVpnService::class.java)
        } catch (e: OnionmasqException) {
            Log.e(TAG, "Failed to initialize OnionMasq", e)
        }

        // No need to create channel - using TorService's channel
    }

    override fun onBind(intent: Intent?): IBinder {
        return binder
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ""
        Log.d(TAG, "onStartCommand: $action")

        when (action) {
            ACTION_START_VPN, "android.net.VpnService" -> {
                // Start foreground immediately (required for systemExempted)
                val notification = createNotification("Starting Tor VPN...")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    startForeground(
                        NOTIFICATION_ID,
                        notification,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
                    )
                } else {
                    startForeground(NOTIFICATION_ID, notification)
                }

                executor.execute {
                    establishVpn()
                }
            }
            ACTION_STOP_VPN -> {
                executor.execute {
                    stopVpn()
                }
            }
        }

        return START_STICKY
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked by user")
        executor.execute {
            stopVpn()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "TorVpnService destroyed")
        running.set(false)
        executor.shutdown()
    }

    private fun establishVpn() {
        try {
            Log.i(TAG, "Establishing VPN connection...")

            // Stop if already running
            if (OnionMasq.isRunning()) {
                Log.w(TAG, "OnionMasq already running, stopping first...")
                OnionMasq.stop()
            }

            // Build VPN profile
            val builder = Builder()
                .setSession("SecureLegion Tor VPN")
                .addAddress("169.254.42.1", 16) // IPv4 local address
                .addAddress("fc00::", 7) // IPv6 local address
                .addRoute("0.0.0.0", 0) // Route all IPv4
                .addRoute("::", 0) // Route all IPv6
                .addDnsServer("169.254.42.53") // Local DNS
                .addDnsServer("fe80::53") // Local IPv6 DNS
                .allowFamily(OsConstants.AF_INET)
                .allowFamily(OsConstants.AF_INET6)
                .setMtu(1500)

            // CRITICAL: Exclude SecureLegion from VPN routing
            // SecureLegion uses its own Tor instance (port 9050)
            // Routing it through OnionMasq VPN breaks messaging
            try {
                val myUid = android.os.Process.myUid()
                builder.addDisallowedApplication(packageName)
                Log.i(TAG, "Excluded SecureLegion (UID $myUid) from VPN routing")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to exclude SecureLegion from VPN", e)
            }

            // Make non-metered if supported
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            // Establish VPN tunnel
            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return
            }

            Log.i(TAG, "VPN interface established, starting OnionMasq...")

            // Start OnionMasq in background thread
            running.set(true)

            // Immediately broadcast that VPN is active (before OnionMasq fully starts)
            broadcastVpnStats(0, 0, true)

            Thread {
                try {
                    val fd = vpnInterface!!.detachFd()
                    Log.d(TAG, "Starting OnionMasq with fd=$fd")

                    // Start OnionMasq proxy (this blocks until stopped)
                    OnionMasq.start(fd, null) // null = no bridges, direct Tor

                    Log.i(TAG, "OnionMasq stopped normally")
                } catch (e: OnionmasqException) {
                    Log.e(TAG, "OnionMasq error", e)
                } catch (e: Exception) {
                    Log.e(TAG, "Unexpected error", e)
                } finally {
                    running.set(false)
                    stopSelf()
                }
            }.start()

            // Start bandwidth tracking (will broadcast stats to TorService)
            startBandwidthTracking()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN", e)
            running.set(false)
            stopSelf()
        }
    }

    private fun stopVpn() {
        Log.i(TAG, "Stopping Tor VPN...")
        running.set(false)

        // Stop bandwidth tracking
        bandwidthUpdateThread?.interrupt()
        try {
            bandwidthUpdateThread?.join(1000) // Wait up to 1 second for clean exit
        } catch (e: InterruptedException) {
            Log.w(TAG, "Bandwidth thread didn't stop cleanly")
        }
        bandwidthUpdateThread = null

        try {
            OnionMasq.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping OnionMasq", e)
        }

        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }

        OnionMasq.unbindVPNService()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun protect(socket: Int): Boolean {
        val result = super.protect(socket)
        if (!result) {
            Log.w(TAG, "Failed to protect socket $socket")
        }
        return result
    }

    private fun startBandwidthTracking() {
        // Stop any existing thread first
        bandwidthUpdateThread?.interrupt()

        bandwidthUpdateThread = Thread {
            try {
                // Give OnionMasq a moment to fully start before querying stats
                Thread.sleep(5000)

                while (running.get() && !Thread.currentThread().isInterrupted) {
                    try {
                        // Only query if OnionMasq is actually running
                        if (OnionMasq.isRunning()) {
                            val bytesReceived = OnionMasq.getBytesReceived()
                            val bytesSent = OnionMasq.getBytesSent()

                            // Broadcast stats to TorService instead of showing separate notification
                            broadcastVpnStats(bytesReceived, bytesSent, true)
                        }
                    } catch (e: Exception) {
                        // Don't crash on errors, just log and continue
                        Log.e(TAG, "Error updating bandwidth stats", e)
                    }

                    Thread.sleep(5000) // Update every 5 seconds - gives TorService time to update too
                }
            } catch (e: InterruptedException) {
                Log.d(TAG, "Bandwidth tracking stopped (interrupted)")
            } finally {
                Log.d(TAG, "Bandwidth tracking thread exited cleanly")
                // Notify TorService that VPN is no longer active
                broadcastVpnStats(0, 0, false)
            }
        }
        bandwidthUpdateThread?.start()
        Log.i(TAG, "Bandwidth tracking started")
    }

    private fun broadcastVpnStats(bytesRx: Long, bytesTx: Long, active: Boolean) {
        Log.d(TAG, "Broadcasting VPN stats: active=$active, rx=$bytesRx, tx=$bytesTx")
        val intent = Intent(TorService.ACTION_VPN_BANDWIDTH_UPDATE).apply {
            setPackage(packageName) // Explicit package for Android 8.0+ broadcast restrictions
            putExtra(TorService.EXTRA_VPN_RX_BYTES, bytesRx)
            putExtra(TorService.EXTRA_VPN_TX_BYTES, bytesTx)
            putExtra(TorService.EXTRA_VPN_ACTIVE, active)
        }
        sendBroadcast(intent)
        Log.d(TAG, "Broadcast sent to package: $packageName")
    }

    private fun createNotification(message: String): Notification {
        // Use TorService's notification - it will be updated with combined stats
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }

        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("Tor VPN")
            .setContentText(message)
            .setSmallIcon(R.drawable.ic_notification_logo)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setSilent(true)
            .build()
    }
}
