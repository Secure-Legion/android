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
import com.securelegion.sync.DeviceEnrollmentReceiptVerifier
import com.securelegion.sync.DeviceEnrollmentOwnerCoordinator
import com.securelegion.sync.DeviceEnrollmentWire
import com.securelegion.sync.DeviceSyncWireRoute
import com.securelegion.sync.DeviceSyncFrameV2
import com.securelegion.sync.DeviceSyncHelloWire
import com.securelegion.sync.DeviceSyncPushWire
import com.securelegion.sync.DeviceSyncTorPolicy
import com.securelegion.sync.DeviceSyncAccountSettingsReceiver
import com.securelegion.database.DeviceSyncChunkStore
import com.securelegion.database.DeviceSyncOutboxStore
import com.securelegion.sync.DeviceSyncAccountSettingsPublisher
import com.securelegion.sync.DeviceSyncOutboundWire
import com.securelegion.sync.DeviceSyncContactReceiver
import com.securelegion.sync.DeviceSyncContactPublisher
import com.securelegion.sync.DeviceSyncLiveMessageReceiver
import com.securelegion.sync.DeviceSyncLiveReceiptReceiver
import com.securelegion.sync.DeviceSyncMediaFiles
import com.securelegion.sync.DeviceSyncLivePublisher
import androidx.sqlite.db.SimpleSQLiteQuery
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

    fun stop() { job?.cancel(); job = null; DeviceEnrollmentOwnerCoordinator.cancel() }

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
            val syncHost = DeviceSyncFsHost(account, identity, roster)
            val settingsReceiver = DeviceSyncAccountSettingsReceiver(database, roster)
            val contactReceiver = DeviceSyncContactReceiver(database, roster)
            val messageReceiver = DeviceSyncLiveMessageReceiver(database, roster,
                keyManager::encryptDeviceSyncContent,
                DeviceSyncMediaFiles(context, keyManager)::store)
            val receiptReceiver = DeviceSyncLiveReceiptReceiver(database, roster)
            val contactPublisher = DeviceSyncContactPublisher(database, roster)
            val livePublisher = DeviceSyncLivePublisher(context, database, roster, keyManager)
            val settingsPublisher = DeviceSyncAccountSettingsPublisher(database, roster)
            val outbox = DeviceSyncOutboxStore(database, roster)
            val peerCapabilities = HashMap<String, Set<String>>()
            val lastHelloMs = HashMap<String, Long>()
            val receiptVerifier = DeviceEnrollmentReceiptVerifier(roster)
            val onion = identity.withTorServiceSeed { RustBridge.createDeviceOnionService(it) }
            check(onion == identity.onionAddress)
            check(RustBridge.startDeviceOnionListener())
            var nextSendMs = 0L
            try {
                runCatching { settingsPublisher.capturePrimary(context, keyManager) }
                    .onFailure { Log.w(TAG, "Account setting capture deferred: ${it.message}") }
                var settingsMaterialized = runCatching {
                    settingsReceiver.materializePrimary(context, keyManager)
                }.onFailure {
                    Log.w(TAG, "Account settings materialization deferred: ${it.message}")
                }.isSuccess
                while (kotlin.coroutines.coroutineContext.isActive &&
                    SessionManager.isUnlocked(context) &&
                    TorService.getCurrentTorState() == TorService.TorState.RUNNING &&
                    roster.isLocalAuthorized(account, identity.deviceId, 0x02)) {
                    val frame = RustBridge.pollDeviceOnionFrame()
                    if (frame != null && frame.isNotEmpty()) {
                        try {
                            when (frame[0].toInt() and 0xff) {
                                0xA3 -> {
                                    val enrollment = DeviceEnrollmentWire.decodeFrame(frame)
                                    if (enrollment.type == "committed") {
                                        if (receiptVerifier.verifyAndComplete(frame))
                                            DeviceEnrollmentOwnerCoordinator.committed(enrollment.transcriptId)
                                    } else DeviceEnrollmentOwnerCoordinator.receive(context, frame)
                                }
                                0xA4 -> exchange.acceptUpdate(frame, account, identity)?.let { reply ->
                                    peerCapabilities.clear()
                                    lastHelloMs.clear()
                                    // A removed endpoint may acknowledge the public
                                    // revocation before this listener shuts down.
                                    if (SessionManager.isUnlocked(context)) {
                                        RustBridge.sendDeviceOnionFrame(reply.onion, reply.wire)
                                    }
                                }
                                0xA5 -> exchange.acceptAcknowledgment(frame, account)
                                0xB6, 0xB7 -> {
                                    val peerId = DeviceSyncWireRoute.peerId(frame,
                                        identity.deviceId, account)
                                    val outcome = syncHost.receive(peerId, frame)
                                    try {
                                        val peer = roster.authorizedPeer(account, peerId, 0x02)
                                            ?: throw IllegalStateException("Sync peer was revoked")
                                        for (reply in outcome.outgoing) {
                                            if (!SessionManager.isUnlocked(context) ||
                                                !roster.isLocalAuthorized(account, identity.deviceId, 0x02) ||
                                                roster.authorizedPeer(account, peerId, 0x02)?.onion != peer.onion)
                                                break
                                            RustBridge.sendDeviceOnionFrame(peer.onion, reply)
                                        }
                                        outcome.message?.let { plaintext ->
                                            val inner = DeviceSyncFrameV2.decode(plaintext, peerId,
                                                identity.deviceId, frame)
                                            when (inner.kind) {
                                                DeviceSyncFrameV2.Kind.HELLO,
                                                DeviceSyncFrameV2.Kind.HELLO_ACK -> {
                                                    val hello = DeviceSyncHelloWire.parse(inner.payload)
                                                    peerCapabilities[peerId] = hello.capabilities
                                                    // Android advertises only the Tor skip policy until
                                                    // its transactional topic importers are live.
                                                    syncHost.noteCapabilities(peerId, hello.capabilities,
                                                        setOf("tor_metadata_only_v1"))
                                                    if (inner.kind == DeviceSyncFrameV2.Kind.HELLO) {
                                                        sendSyncApplication(syncHost, roster, account,
                                                            identity.deviceId, peerId, peer.onion,
                                                            DeviceSyncFrameV2.Kind.HELLO_ACK,
                                                            DeviceSyncHelloWire.payload(
                                                                setOf("tor_metadata_only_v1"),
                                                                cursorSnapshot(database, peerId)))
                                                    }
                                                }
                                                DeviceSyncFrameV2.Kind.PUSH -> {
                                                    val topic = inner.payload.optString("topic")
                                                    if (topic == "contacts") {
                                                        val part = DeviceSyncPushWire.parse(inner,
                                                            liveNegotiated = false)
                                                        if (contactReceiver.receive(account,
                                                                identity.deviceId, part) ==
                                                            DeviceSyncChunkStore.Result.COMMITTED) {
                                                            sendSyncApplication(syncHost, roster, account,
                                                                identity.deviceId, peerId, peer.onion,
                                                                DeviceSyncFrameV2.Kind.PULL_RESPONSE,
                                                                DeviceSyncPushWire.settled(part))
                                                        }
                                                    } else if (topic == "settings") {
                                                        settingsPublisher.capturePrimary(context,
                                                            keyManager)
                                                        val part = DeviceSyncPushWire.parse(inner,
                                                            liveNegotiated = false)
                                                        if (settingsReceiver.receive(account,
                                                                identity.deviceId, part) ==
                                                            DeviceSyncChunkStore.Result.COMMITTED) {
                                                            sendSyncApplication(syncHost, roster, account,
                                                                identity.deviceId, peerId, peer.onion,
                                                                DeviceSyncFrameV2.Kind.PULL_RESPONSE,
                                                                DeviceSyncPushWire.settled(part))
                                                            settingsReceiver.materializePrimary(
                                                                context, keyManager)
                                                        }
                                                    } else if (topic == "messages" &&
                                                        syncHost.liveNegotiated(peerId)) {
                                                        val part = DeviceSyncPushWire.parse(inner,
                                                            liveNegotiated = true)
                                                        if (messageReceiver.receive(account,
                                                                identity.deviceId, part, true) ==
                                                            DeviceSyncChunkStore.Result.COMMITTED) {
                                                            sendSyncApplication(syncHost, roster, account,
                                                                identity.deviceId, peerId, peer.onion,
                                                                DeviceSyncFrameV2.Kind.PULL_RESPONSE,
                                                                DeviceSyncPushWire.settled(part))
                                                        }
                                                    } else if (topic == "receipts" &&
                                                        syncHost.liveNegotiated(peerId)) {
                                                        val part = DeviceSyncPushWire.parse(inner,
                                                            liveNegotiated = true)
                                                        if (receiptReceiver.receive(account,
                                                                identity.deviceId, part, true) ==
                                                            DeviceSyncChunkStore.Result.COMMITTED) {
                                                            sendSyncApplication(syncHost, roster, account,
                                                                identity.deviceId, peerId, peer.onion,
                                                                DeviceSyncFrameV2.Kind.PULL_RESPONSE,
                                                                DeviceSyncPushWire.settled(part))
                                                        }
                                                    } else if (topic !in DeviceSyncTorPolicy.metadataTopics &&
                                                        topic in setOf("messages", "receipts", "groups") &&
                                                        peerCapabilities.containsKey(peerId)) {
                                                        val policyAware = peerCapabilities[peerId]
                                                            ?.contains("tor_metadata_only_v1") == true
                                                        val response = if (policyAware)
                                                            DeviceSyncPushWire.transportSkipped(inner.payload)
                                                        else DeviceSyncPushWire.legacySettled(inner.payload)
                                                        sendSyncApplication(syncHost, roster, account,
                                                            identity.deviceId, peerId, peer.onion,
                                                            DeviceSyncFrameV2.Kind.PULL_RESPONSE, response)
                                                    }
                                                }
                                                DeviceSyncFrameV2.Kind.PULL_RESPONSE ->
                                                    outbox.consumeAuthenticatedResponse(account,
                                                        identity.deviceId, inner,
                                                        DeviceSyncOutboxStore.Transport.TOR,
                                                        syncHost.liveNegotiated(peerId))
                                                else -> Unit
                                            }
                                        }
                                    } finally {
                                        // Topic data remains unacknowledged until its transactional
                                        // importer is wired. Clear decrypted application bytes.
                                        outcome.message?.fill(0)
                                    }
                                }
                            }
                        } catch (e: Exception) { Log.w(TAG, "Device roster frame rejected: ${e.message}") }
                    }
                    val now = System.currentTimeMillis()
                    if (TorService.getTransportGate()?.isOpenNow() == true &&
                        (now >= nextSendMs || DeviceSyncAccountSettingsPublisher.consumeWake())) {
                        for (pending in exchange.pendingNotifications(account, now)) {
                            if (!SessionManager.isUnlocked(context) ||
                                !roster.isLocalAuthorized(account, identity.deviceId, 0x02)) break
                            try { RustBridge.sendDeviceOnionFrame(pending.onion, pending.wire) }
                            catch (e: Exception) { Log.w(TAG, "Roster notice send failed: ${e.message}") }
                            exchange.recordAttempt(account, pending, now)
                        }
                        if (roster.fetchSignedRoster(account) != null) {
                            for (grant in roster.pendingEnrollmentGrants(account, now)) {
                                if (!SessionManager.isUnlocked(context) ||
                                    !roster.isLocalAuthorized(account, identity.deviceId, 0x02)) break
                                val candidate = roster.authorizedPeer(account, grant.candidateDeviceId, 0x02)
                                    ?: continue
                                try { RustBridge.sendDeviceOnionFrame(candidate.onion, grant.wireFrame) }
                                catch (e: Exception) { Log.w(TAG, "Grant retry failed: ${e.message}") }
                            }
                        }
                        nextSendMs = now + 10_000L
                        runCatching {
                            settingsPublisher.capturePrimary(context, keyManager, now)
                        }.onFailure { Log.w(TAG, "Account setting capture deferred: ${it.message}") }
                        if (!settingsMaterialized) {
                            settingsMaterialized = runCatching {
                                settingsReceiver.materializePrimary(context, keyManager)
                            }.isSuccess
                        }
                        for (applied in contactReceiver.drainPending(account,
                                identity.deviceId, now)) {
                            val peer = roster.authorizedPeer(account, applied.peerDeviceId, 0x02)
                                ?: continue
                            runCatching {
                                sendSyncApplication(syncHost, roster, account,
                                    identity.deviceId, peer.deviceId, peer.onion,
                                    DeviceSyncFrameV2.Kind.PULL_RESPONSE,
                                    DeviceSyncPushWire.settled(applied))
                            }
                        }
                        for (applied in messageReceiver.drainPending(account,
                                identity.deviceId, { syncHost.liveNegotiated(it) }, now)) {
                            val peer = roster.authorizedPeer(account, applied.peerDeviceId, 0x02)
                                ?: continue
                            runCatching {
                                sendSyncApplication(syncHost, roster, account,
                                    identity.deviceId, peer.deviceId, peer.onion,
                                    DeviceSyncFrameV2.Kind.PULL_RESPONSE,
                                    DeviceSyncPushWire.settled(applied.eventId,
                                        applied.digestHex, "messages", applied.objectId,
                                        applied.eventTimeMs))
                            }
                        }
                        for (applied in receiptReceiver.drainPending(account,
                                identity.deviceId, { syncHost.liveNegotiated(it) }, now)) {
                            val peer = roster.authorizedPeer(account, applied.peerDeviceId, 0x02)
                                ?: continue
                            runCatching {
                                sendSyncApplication(syncHost, roster, account,
                                    identity.deviceId, peer.deviceId, peer.onion,
                                    DeviceSyncFrameV2.Kind.PULL_RESPONSE,
                                    DeviceSyncPushWire.settled(applied.eventId,
                                        applied.digestHex, "receipts", applied.objectId,
                                        applied.eventTimeMs))
                            }
                        }
                        for (device in roster.listAuthorizedDevices(account)) {
                            if (device.isSelf || device.capabilities and 0x02 == 0 ||
                                device.expiresAtMs <= now) continue
                            try {
                                val peer = roster.authorizedPeer(account, device.deviceId, 0x02)
                                    ?: continue
                                val control = syncHost.ensure(peer.deviceId, now)
                                control.outgoing.forEach {
                                    RustBridge.sendDeviceOnionFrame(peer.onion, it)
                                }
                                if (control.ready && now - (lastHelloMs[peer.deviceId] ?: 0L) >= 30_000L) {
                                    if (sendSyncApplication(syncHost, roster, account,
                                            identity.deviceId, peer.deviceId, peer.onion,
                                            DeviceSyncFrameV2.Kind.HELLO,
                                            DeviceSyncHelloWire.payload(
                                                setOf("tor_metadata_only_v1"),
                                                cursorSnapshot(database, peer.deviceId)))) {
                                        lastHelloMs[peer.deviceId] = now
                                    }
                                }
                                if (control.ready && peerCapabilities[peer.deviceId]
                                        ?.contains("durable_history_v2") == true) {
                                    contactPublisher.prepareBatch(account, identity.deviceId,
                                        peer.deviceId, now)
                                    if (syncHost.liveNegotiated(peer.deviceId)) {
                                        livePublisher.prepareBatch(account, identity.deviceId,
                                            peer.deviceId, now)
                                    }
                                    if (settingsMaterialized && peerCapabilities[peer.deviceId]
                                            ?.contains("account_profile_v1") == true) {
                                        settingsPublisher.enqueueForPeer(account, identity.deviceId,
                                            peer.deviceId, now)
                                    }
                                    for (event in outbox.dueTor(account, identity.deviceId,
                                            peer.deviceId, now,
                                            liveNegotiated = syncHost.liveNegotiated(peer.deviceId))) {
                                        try {
                                            for (payload in DeviceSyncOutboundWire.payloads(event)) {
                                                if (!sendSyncApplication(syncHost, roster, account,
                                                        identity.deviceId, peer.deviceId, peer.onion,
                                                        DeviceSyncFrameV2.Kind.PUSH, payload)) break
                                            }
                                        } finally {
                                            outbox.recordTorAttempt(account, identity.deviceId,
                                                event, now,
                                                liveNegotiated = syncHost.liveNegotiated(peer.deviceId))
                                        }
                                    }
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "Sync peer retry deferred: ${e.message}")
                            }
                        }
                    }
                    delay(250)
                }
            } finally {
                syncHost.close()
                RustBridge.stopDeviceOnionListener()
                DeviceEnrollmentOwnerCoordinator.cancel()
            }
        } finally { identity.close() }
    }

    private fun cursorSnapshot(database: SecureLegionDatabase,
                               peerDeviceId: String): Map<String, Pair<Long, Long>> {
        require(peerDeviceId.length == 43)
        return database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT topic,pushed_seq,received_seq FROM device_sync_cursors " +
                "WHERE peer_device_id=?", arrayOf(peerDeviceId)
        )).use { cursor ->
            buildMap {
                while (cursor.moveToNext()) put(cursor.getString(0),
                    cursor.getLong(1) to cursor.getLong(2))
            }
        }
    }

    private fun sendSyncApplication(host: DeviceSyncFsHost, roster: DeviceRosterStore,
                                    account: ByteArray, localId: String, peerId: String,
                                    onion: String, kind: DeviceSyncFrameV2.Kind,
                                    payload: org.json.JSONObject): Boolean {
        if (!SessionManager.isUnlocked(context) ||
            !roster.isLocalAuthorized(account, localId, 0x02) ||
            roster.authorizedPeer(account, peerId, 0x02)?.onion != onion) return false
        val plaintext = DeviceSyncFrameV2.encode(kind, localId, peerId, payload)
        try {
            val sealed = host.seal(peerId, plaintext)
            if (!sealed.ready || sealed.outgoing.isEmpty()) return false
            for (wire in sealed.outgoing) {
                if (!SessionManager.isUnlocked(context) ||
                    !roster.isLocalAuthorized(account, localId, 0x02) ||
                    roster.authorizedPeer(account, peerId, 0x02)?.onion != onion) return false
                if (!RustBridge.sendDeviceOnionFrame(onion, wire)) return false
            }
            return true
        } finally { plaintext.fill(0) }
    }

    private companion object { const val TAG = "DeviceRosterRuntime" }
}
