package com.securelegion.services

import android.content.Context
import android.os.Build
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.sync.DeviceRosterExchange
import com.securelegion.sync.DeviceRosterAuthority
import com.securelegion.utils.SessionManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Own-device A4/A5 loop. It never enters the legacy contact message parser. */
internal class DeviceRosterRuntime(private val context: Context) {
    private var job: Job? = null

    fun start(scope: CoroutineScope) {
        if (job?.isActive == true) return
        job = scope.launch(Dispatchers.IO) {
            while (isActive) {
                if (!SessionManager.isUnlocked(context) ||
                    TorService.getCurrentTorState() != TorService.TorState.RUNNING) {
                    delay(2_000)
                    continue
                }
                try { runAuthorizedSession() }
                catch (e: Exception) { Log.w(TAG, "Device roster runtime unavailable: ${e.message}") }
                delay(5_000)
            }
        }
    }

    fun stop() { job?.cancel(); job = null }

    private suspend fun runAuthorizedSession() {
        val keyManager = KeyManager.getInstance(context)
        if (!keyManager.isInitialized()) return
        val account = keyManager.getSigningPublicKey()
        if (account.size != 32) return
        // A completed primary profile needs an independent installation identity
        // and an account-signed initial roster before it can receive device frames.
        val identity = LocalDeviceIdentity.loadOrCreate(context)
        try {
            val database = SecureLegionDatabase.getInstance(context, keyManager.getDatabasePassphrase())
            val roster = DeviceRosterStore(database)
            if (roster.fetchSignedRoster(account) == null) {
                val model = Build.MODEL.orEmpty().filter { it.code >= 32 && it.code !in 127..159 }
                    .trim().take(64).ifBlank { "Android" }
                DeviceRosterAuthority(roster).ensurePrimaryRoster(keyManager, identity, model)
            }
            if (!roster.isLocalAuthorized(account, identity.deviceId, 0x02)) return
            val exchange = DeviceRosterExchange(database, roster)
            val onion = identity.withTorServiceSeed { RustBridge.createDeviceOnionService(it) }
            check(onion == identity.onionAddress)
            check(RustBridge.startDeviceOnionListener())
            var nextSendMs = 0L
            try {
                while (kotlin.coroutines.coroutineContext.isActive &&
                    SessionManager.isUnlocked(context) &&
                    TorService.getCurrentTorState() == TorService.TorState.RUNNING &&
                    roster.isLocalAuthorized(account, identity.deviceId, 0x02)) {
                    val frame = RustBridge.pollDeviceOnionFrame()
                    if (frame != null) {
                        try {
                            when (frame[0].toInt() and 0xff) {
                                0xA4 -> exchange.acceptUpdate(frame, account, identity)?.let { reply ->
                                    // A removed endpoint may acknowledge the public
                                    // revocation before this listener shuts down.
                                    if (SessionManager.isUnlocked(context)) {
                                        RustBridge.sendDeviceOnionFrame(reply.onion, reply.wire)
                                    }
                                }
                                0xA5 -> exchange.acceptAcknowledgment(frame, account)
                                // Enrollment and Noise traffic remain closed until their
                                // authenticated state machines are connected here.
                            }
                        } catch (e: Exception) { Log.w(TAG, "Device roster frame rejected: ${e.message}") }
                    }
                    val now = System.currentTimeMillis()
                    if (now >= nextSendMs && TorService.getTransportGate()?.isOpenNow() == true) {
                        for (pending in exchange.pendingNotifications(account, now)) {
                            if (!SessionManager.isUnlocked(context) ||
                                !roster.isLocalAuthorized(account, identity.deviceId, 0x02)) break
                            try { RustBridge.sendDeviceOnionFrame(pending.onion, pending.wire) }
                            catch (e: Exception) { Log.w(TAG, "Roster notice send failed: ${e.message}") }
                            exchange.recordAttempt(account, pending, now)
                        }
                        nextSendMs = now + 10_000L
                    }
                    delay(250)
                }
            } finally { RustBridge.stopDeviceOnionListener() }
        } finally { identity.close() }
    }

    private companion object { const val TAG = "DeviceRosterRuntime" }
}
