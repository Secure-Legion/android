package com.securelegion.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log
import com.securelegion.LinkedMessengerActivity
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LinkedProfileCredentialStore
import com.securelegion.crypto.RustBridge
import com.securelegion.utils.SessionManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

/** Owns Arti for a seedless linked installation; never starts the primary TorService. */
internal class LinkedDeviceService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var started = false
    private var startup: Job? = null
    private var rosterRuntime: DeviceRosterRuntime? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (KeyManager.getInstance(this).isInitialized() ||
            LinkedProfileCredentialStore(this).activeProfile() == null) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        val notifications = getSystemService(NotificationManager::class.java)
        notifications.createNotificationChannel(NotificationChannel(CHANNEL,
            "Linked device connection", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0,
            Intent(this, LinkedMessengerActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(this, CHANNEL)
            .setSmallIcon(com.securelegion.R.mipmap.ic_launcher_secure)
            .setContentTitle("Secure Legion linked device")
            .setContentText("Connecting secure device sync")
            .setContentIntent(open)
            .setOngoing(true).build()
        startForeground(NOTIFICATION_ID, notification)
        if (!started) {
            started = true
            startup = scope.launch {
                try {
                    DeviceEnrollmentCandidateRuntime.stopAndJoin()
                    check(RustBridge.initializeTor() == "Arti bootstrapped")
                    val runtime = DeviceRosterRuntime(this@LinkedDeviceService)
                    rosterRuntime = runtime
                    runtime.start(scope, directArti = true)
                    notifications.notify(NOTIFICATION_ID,
                        Notification.Builder(this@LinkedDeviceService, CHANNEL)
                            .setSmallIcon(com.securelegion.R.mipmap.ic_launcher_secure)
                            .setContentTitle("Secure Legion linked device")
                            .setContentText("Secure device sync active")
                            .setContentIntent(open)
                            .setOngoing(true).build())
                } catch (e: Exception) {
                    Log.e(TAG, "Linked device network failed", e)
                    stopSelf()
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        runBlocking(Dispatchers.IO) {
            startup?.cancelAndJoin()
            rosterRuntime?.stopAndJoin()
            scope.cancel()
            runCatching { RustBridge.shutdownArti() }
        }
        super.onDestroy()
    }

    private companion object {
        const val CHANNEL = "linked_device_sync"
        const val NOTIFICATION_ID = 2084
        const val TAG = "LinkedDeviceService"
    }
}
