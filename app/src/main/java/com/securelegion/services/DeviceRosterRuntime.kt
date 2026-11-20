package com.securelegion.services

import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LinkedProfileCredentialStore
import com.securelegion.crypto.LinkedProfileContentCrypto
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DelegatedGroupReceiver
import com.securelegion.database.DelegatedGroupProofExchange
import com.securelegion.database.DelegatedGroupRootApproval
import com.securelegion.database.DelegatedGroupDeliveryStore
import com.securelegion.database.DelegatedGroupMessageOutbox
import com.securelegion.database.LinkedChatStore
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
import com.securelegion.database.DeviceTransportSessionStore
import com.securelegion.sync.DeviceSyncAccountSettingsPublisher
import com.securelegion.sync.DeviceSyncOutboundWire
import com.securelegion.sync.DeviceSyncContactReceiver
import com.securelegion.sync.DeviceSyncContactPublisher
import com.securelegion.sync.DeviceSyncGroupReceiver
import com.securelegion.sync.DeviceSyncGroupLinkPublisher
import com.securelegion.sync.DeviceSyncLiveMessageReceiver
import com.securelegion.sync.DeviceSyncLiveReceiptReceiver
import com.securelegion.sync.DeviceSyncMediaFiles
import com.securelegion.sync.DeviceSyncLivePublisher
import com.securelegion.sync.DeviceTransportFrame
import com.securelegion.sync.DeviceGroupFrame
import com.securelegion.sync.DeviceChatPayloadStore
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.utils.SessionManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** Own-device A4/A5 loop. It never enters the legacy contact message parser. */
internal class DeviceRosterRuntime(private val context: Context) {
    private var job: Job? = null
    private var directArti = false
    private var nextProofScanMs = 0L
    private var nextAccountAckScanMs = 0L
    private var proofScanCursor = ""
    private val proofDue = java.util.concurrent.ConcurrentHashMap<String, Long>()

    fun start(scope: CoroutineScope, directArti: Boolean = false) {
        if (job?.isActive == true) return
        this.directArti = directArti
        job = scope.launch(Dispatchers.IO) {
            while (isActive) {
                if (!SessionManager.isUnlocked(context) ||
                    !networkReady()) {
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

    suspend fun stopAndJoin() {
        val current = job.also { job = null }
        current?.cancelAndJoin()
        DeviceEnrollmentOwnerCoordinator.cancel()
    }

    private suspend fun runAuthorizedSession() {
        val keyManager = KeyManager.getInstance(context)
        val primary = keyManager.isInitialized()
        val linkedStore = if (primary) null else LinkedProfileCredentialStore(context)
        val linkedProfile = linkedStore?.activeProfile()
        if (!primary && linkedProfile == null) return
        val account = if (primary) keyManager.getSigningPublicKey()
            else linkedProfile!!.accountEd
        if (account.size != 32) return
        // A completed primary profile needs an independent installation identity
        // and an account-signed initial roster before it can receive device frames.
        val identity = if (primary) LocalDeviceIdentity.loadOrCreate(context)
            else LocalDeviceIdentity.loadExisting(context)
        val linkedCrypto = if (primary) null else LinkedProfileContentCrypto(context)
        val localCapabilities = setOf(
            "tor_metadata_only_v1", "contact_roster_v1", "durable_history_v2",
            "account_profile_v1", "group_links_v1", DeviceSyncTorPolicy.LIVE_CAPABILITY)
        try {
            val databaseKey = if (primary) keyManager.getDatabasePassphrase()
                else linkedStore!!.activeDatabaseKey()
                    ?: throw IllegalStateException("Linked profile database unavailable")
            val database = try { SecureLegionDatabase.getInstance(context, databaseKey) }
                finally { databaseKey.fill(0) }
            val roster = DeviceRosterStore(database)
            if (roster.fetchSignedRoster(account) == null) {
                if (!primary) throw IllegalStateException("Linked roster unavailable")
                val model = Build.MODEL.orEmpty().filter { it.code >= 32 && it.code !in 127..159 }
                    .trim().take(64).ifBlank { "Android" }
                DeviceRosterAuthority(roster).ensurePrimaryRoster(keyManager, identity, model)
            }
            if (!roster.isLocalAuthorized(account, identity.deviceId, 0x02)) {
                if (roster.isLocalAuthorized(account, identity.deviceId, 0x04))
                    runGroupOnlySession(database, roster, account, identity)
                return
            }
            val exchange = DeviceRosterExchange(database, roster)
            val syncHost = DeviceSyncFsHost(account, identity, roster)
            val settingsReceiver = DeviceSyncAccountSettingsReceiver(database, roster)
            val mediaFiles = if (primary) DeviceSyncMediaFiles(context, keyManager)
                else DeviceSyncMediaFiles(context, linkedCrypto!!::encryptImage,
                    linkedCrypto::encryptVoice)
            val linkedChat = if (primary) null else LinkedChatStore(database, roster,
                linkedCrypto!!::encryptText, mediaFiles).also { it.ensureSchema() }
            val contactReceiver = DeviceSyncContactReceiver(database, roster, linkedChat)
            val messageReceiver = DeviceSyncLiveMessageReceiver(database, roster,
                if (primary) keyManager::encryptDeviceSyncContent else linkedCrypto!!::encryptText,
                mediaFiles::store, linkedChat)
            val receiptReceiver = DeviceSyncLiveReceiptReceiver(database, roster,
                linkedChat)
            val groupReceiver = DeviceSyncGroupReceiver(database, roster)
            val delegatedReceiver = DelegatedGroupReceiver(database)
            val delegatedDelivery = DelegatedGroupDeliveryStore(database)
            val delegatedMessages = DelegatedGroupMessageOutbox(database)
            val contactPublisher = DeviceSyncContactPublisher(database, roster,
                linked = !primary)
            val livePublisher = if (primary)
                DeviceSyncLivePublisher(context, database, roster, keyManager)
                else DeviceSyncLivePublisher(context, database, roster,
                    linkedCrypto!!::decryptText, linkedCrypto::decryptImage,
                    linkedCrypto::decryptVoice, linked = true,
                    linkedStore = linkedChat)
            val settingsPublisher = DeviceSyncAccountSettingsPublisher(database, roster)
            val groupPublisher = DeviceSyncGroupLinkPublisher(database, roster)
            val outbox = DeviceSyncOutboxStore(database, roster)
            val transport = DeviceTransportSessionStore(database, roster)
            val chatPayloads = DeviceChatPayloadStore(
                if (primary) keyManager::encryptDeviceSyncContent else linkedCrypto!!::encryptText,
                mediaFiles::storeRaw, linkedChat)
            val peerCapabilities = HashMap<String, Set<String>>()
            val lastHelloMs = HashMap<String, Long>()
            val lastGroupPrepareMs = HashMap<String, Long>()
            val receiptVerifier = DeviceEnrollmentReceiptVerifier(roster)
            val onion = identity.withTorServiceSeed { RustBridge.createDeviceOnionService(it) }
            check(onion == identity.onionAddress)
            check(RustBridge.startDeviceOnionListener())
            val controlJob = SupervisorJob(kotlin.coroutines.coroutineContext[Job])
            val contactJob = SupervisorJob(kotlin.coroutines.coroutineContext[Job])
            val controlQueue = DeviceSyncControlQueue(
                CoroutineScope(controlJob + Dispatchers.IO), account, identity.deviceId,
                valid = { peerId ->
                    SessionManager.isUnlocked(context) && networkReady() &&
                        runCatching {
                            if (primary) keyManager.isInitialized() &&
                                keyManager.getSigningPublicKey().contentEquals(account)
                            else linkedStore?.activeProfile()?.accountEd?.contentEquals(account) == true
                        }.getOrDefault(false) &&
                        roster.isLocalAuthorized(account, identity.deviceId, 0x02) &&
                        roster.authorizedPeer(account, peerId, 0x02) != null
                },
                send = { peerId, wire ->
                    val peer = roster.authorizedPeer(account, peerId, 0x02)
                    peer != null && RustBridge.sendDeviceOnionFrame(peer.onion, wire)
                },
                onFailure = { peerId, error ->
                    Log.w(TAG, "Sync control send deferred for ${peerId.take(8)}: ${error?.message ?: "authorization or transport"}")
                })
            val contactQueue = ContactRosterSendQueue(
                CoroutineScope(contactJob + Dispatchers.IO),
                valid = { item ->
                    SessionManager.isUnlocked(context) && networkReady() &&
                        runCatching { keyManager.isInitialized() &&
                            keyManager.getSigningPublicKey().contentEquals(account) }
                            .getOrDefault(false) &&
                        exchange.canSendBootstrap(account, identity.deviceId, item)
                },
                send = { item -> RustBridge.sendContactRosterFrame(item.onion, item.wire) })
            fun queueControl(peer: DeviceRosterStore.PeerKeys, outgoing: List<ByteArray>) {
                if (outgoing.isEmpty()) return
                val generation = syncHost.generation(peer.deviceId)
                if (!controlQueue.enqueue(peer.deviceId, outgoing) {
                        syncHost.generation(peer.deviceId) == generation &&
                            roster.authorizedPeer(account, peer.deviceId, 0x02)?.let {
                                it.onion == peer.onion &&
                                    it.signingKey.contentEquals(peer.signingKey) &&
                                    it.encryptionKey.contentEquals(peer.encryptionKey)
                            } == true
                    }) Log.w(TAG, "Sync control queue full or invalid for ${peer.deviceId.take(8)}")
            }
            var nextSendMs = 0L
            var reconnectBootstrap = true
            var nextSourceCheckMs = 0L
            var lastSourceSequence = sourceSequence(database)
            try {
                if (primary) runCatching { settingsPublisher.capturePrimary(context, keyManager) }
                    .onFailure { Log.w(TAG, "Account setting capture deferred: ${it.message}") }
                var settingsMaterialized = if (primary) runCatching {
                    settingsReceiver.materializePrimary(context, keyManager)
                }.onFailure {
                    Log.w(TAG, "Account settings materialization deferred: ${it.message}")
                }.isSuccess else false
                while (kotlin.coroutines.coroutineContext.isActive &&
                    SessionManager.isUnlocked(context) &&
                    networkReady() &&
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
                                    if (SessionManager.isUnlocked(context) &&
                                        exchange.canSendReply(account, identity.deviceId, reply)) {
                                        RustBridge.sendDeviceOnionFrame(reply.onion, reply.wire)
                                    }
                                }
                                0xA5 -> exchange.acceptAcknowledgment(frame, account)
                                DeviceGroupFrame.TYPE -> handleGroupFrame(frame, account,
                                    identity, roster, delegatedReceiver, delegatedDelivery,
                                    database)
                                0xC0 -> {
                                    val incoming = DeviceTransportFrame.parse(frame)
                                    require(incoming.recipientAccount.contentEquals(account) &&
                                        incoming.recipientDeviceId == identity.deviceId)
                                    val peer = roster.authorizedPeer(incoming.senderAccount,
                                        incoming.senderDeviceId, 0x01)
                                        ?: throw IllegalArgumentException("Unknown C0 sender")
                                    val reply = when (incoming.kind) {
                                        DeviceTransportFrame.Kind.SESSION_REQUEST ->
                                            transport.acceptRequest(incoming, identity)
                                        DeviceTransportFrame.Kind.PREKEY -> {
                                            transport.acceptPrekey(incoming, identity)
                                            // The queued first DATA is ready now; do not wait for
                                            // the periodic transport sweep before sealing it.
                                            nextSendMs = 0L
                                            null
                                        }
                                        DeviceTransportFrame.Kind.DATA -> {
                                            var changedContactId: Long? = null
                                            val ack = transport.acceptData(incoming, identity,
                                                { db, logicalId, plaintext ->
                                                    val accountReady = chatPayloads.apply(db,
                                                        incoming.senderAccount, logicalId, plaintext)
                                                    if (primary) {
                                                        val accountEd = android.util.Base64.encodeToString(
                                                            incoming.senderAccount,
                                                            android.util.Base64.NO_WRAP)
                                                        changedContactId = db.query(SimpleSQLiteQuery(
                                                            "SELECT id FROM contacts WHERE publicKeyBase64=? " +
                                                                "AND isBlocked=0 LIMIT 1",
                                                            arrayOf(accountEd)
                                                        )).use { if (it.moveToFirst()) it.getLong(0) else null }
                                                    }
                                                    accountReady
                                                })
                                            // acceptData returns only after the payload and ACK commit.
                                            changedContactId?.let { contactId ->
                                                runCatching {
                                                    context.sendBroadcast(Intent(
                                                        "com.securelegion.MESSAGE_RECEIVED").apply {
                                                        setPackage(context.packageName)
                                                        putExtra("CONTACT_ID", contactId)
                                                    })
                                                }.onFailure {
                                                    Log.w(TAG, "C0 chat refresh deferred: ${it.message}")
                                                }
                                            }
                                            ack
                                        }
                                        DeviceTransportFrame.Kind.DEVICE_STORAGE_ACK,
                                        DeviceTransportFrame.Kind.ACCOUNT_STORAGE_ACK -> {
                                            transport.acceptAcknowledgment(incoming, identity)
                                            Log.i(TAG, "C0 ACK committed kind=${incoming.kind} " +
                                                "job=${incoming.jobId.take(4).joinToString("") {
                                                    "%02x".format(it.toInt() and 255)
                                                }}")
                                            null
                                        }
                                        else -> throw IllegalArgumentException("Unsupported C0 kind")
                                    }
                                    if (reply != null && SessionManager.isUnlocked(context) &&
                                        roster.authorizedPeer(incoming.senderAccount,
                                            incoming.senderDeviceId, 0x01)?.onion == peer.onion) {
                                        RustBridge.sendDeviceOnionFrame(peer.onion, reply)
                                    }
                                }
                                0xB6, 0xB7 -> {
                                    val peerId = DeviceSyncWireRoute.peerId(frame,
                                        identity.deviceId, account)
                                    val outcome = syncHost.receive(peerId, frame)
                                    try {
                                        val peer = roster.authorizedPeer(account, peerId, 0x02)
                                            ?: throw IllegalStateException("Sync peer was revoked")
                                        queueControl(peer, outcome.outgoing)
                                        outcome.message?.let { plaintext ->
                                            val inner = DeviceSyncFrameV2.decode(plaintext, peerId,
                                                identity.deviceId, frame)
                                            when (inner.kind) {
                                                DeviceSyncFrameV2.Kind.HELLO,
                                                DeviceSyncFrameV2.Kind.HELLO_ACK -> {
                                                    val hello = DeviceSyncHelloWire.parse(inner.payload)
                                                    peerCapabilities[peerId] = hello.capabilities
                                                    syncHost.noteCapabilities(peerId, hello.capabilities,
                                                        localCapabilities)
                                                    if (inner.kind == DeviceSyncFrameV2.Kind.HELLO) {
                                                        sendSyncApplication(syncHost, roster, account,
                                                            identity.deviceId, peerId, peer.onion,
                                                            DeviceSyncFrameV2.Kind.HELLO_ACK,
                                                            DeviceSyncHelloWire.payload(
                                                                localCapabilities,
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
                                                        if (primary) settingsPublisher.capturePrimary(context,
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
                                                            if (primary) settingsReceiver.materializePrimary(
                                                                context, keyManager)
                                                        }
                                                    } else if (topic == "group_links" &&
                                                        peerCapabilities[peerId]
                                                            ?.contains("group_links_v1") == true) {
                                                        val part = DeviceSyncPushWire.parse(inner,
                                                            liveNegotiated = false)
                                                        if (groupReceiver.receive(account,
                                                                identity.deviceId, part) ==
                                                            DeviceSyncChunkStore.Result.COMMITTED) {
                                                            sendSyncApplication(syncHost, roster, account,
                                                                identity.deviceId, peerId, peer.onion,
                                                                DeviceSyncFrameV2.Kind.PULL_RESPONSE,
                                                                DeviceSyncPushWire.settled(part))
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
                                        // Clear decrypted application bytes after the
                                        // authenticated topic importer returns.
                                        outcome.message?.fill(0)
                                    }
                                }
                            }
                        } catch (e: Exception) { Log.w(TAG, "Device roster frame rejected: ${e.message}") }
                    }
                    val now = System.currentTimeMillis()
                    var localChangeWake = false
                    if (now >= nextSourceCheckMs) {
                        nextSourceCheckMs = now + 1_000L
                        val sequence = sourceSequence(database)
                        if (sequence != lastSourceSequence) {
                            localChangeWake = true
                            lastSourceSequence = sequence
                        }
                    }
                    if ((directArti || TorService.getTransportGate()?.isOpenNow() == true) &&
                        (now >= nextSendMs || localChangeWake ||
                            DeviceSyncAccountSettingsPublisher.consumeWake())) {
                        if (primary) {
                            for (item in exchange.contactBootstraps(account, now,
                                    reconnect = reconnectBootstrap)) {
                                if (!SessionManager.isUnlocked(context)) break
                                if (!contactQueue.enqueue(item))
                                    Log.w(TAG, "Contact roster control queue full")
                            }
                            reconnectBootstrap = false
                        }
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
                        pumpGroup(account, identity, roster, delegatedMessages,
                            delegatedDelivery, database, now)
                        if (roster.isLocalAuthorized(account, identity.deviceId, 0x01, now)) {
                            repeat(3) {
                                if (transport.nextDataWire(account, identity,
                                        draftOnly = true) == null) return@repeat
                            }
                            for (pending in transport.dueSends(identity, now)) {
                                if (!SessionManager.isUnlocked(context) ||
                                    !roster.isLocalAuthorized(account, identity.deviceId,
                                        0x01, now)) break
                                val frame = DeviceTransportFrame.parse(pending.wire)
                                if (!frame.senderAccount.contentEquals(account) ||
                                    roster.authorizedPeer(frame.recipientAccount,
                                        pending.peerId, 0x01, now)?.onion != pending.onion) continue
                                val sent = runCatching {
                                    RustBridge.sendDeviceOnionFrame(pending.onion, pending.wire)
                                }.onFailure { Log.w(TAG, "C0 send deferred: ${it.message}") }
                                    .getOrDefault(false)
                                Log.d(TAG, "C0 dispatch kind=${frame.kind} counter=${frame.counter} " +
                                    "job=${frame.jobId.take(4).joinToString("") {
                                        "%02x".format(it.toInt() and 255)
                                    }} send_returned=$sent")
                                transport.recordSendAttempt(pending.wire, now)
                            }
                        }
                        if (primary) runCatching {
                            settingsPublisher.capturePrimary(context, keyManager, now)
                        }.onFailure { Log.w(TAG, "Account setting capture deferred: ${it.message}") }
                        if (primary && !settingsMaterialized) {
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
                                queueControl(peer, control.outgoing)
                                if (control.ready && now - (lastHelloMs[peer.deviceId] ?: 0L) >= 30_000L) {
                                    if (sendSyncApplication(syncHost, roster, account,
                                            identity.deviceId, peer.deviceId, peer.onion,
                                            DeviceSyncFrameV2.Kind.HELLO,
                                            DeviceSyncHelloWire.payload(
                                                localCapabilities,
                                                cursorSnapshot(database, peer.deviceId)))) {
                                        lastHelloMs[peer.deviceId] = now
                                    }
                                }
                                if (control.ready && peerCapabilities[peer.deviceId]
                                        ?.contains("durable_history_v2") == true) {
                                    contactPublisher.prepareBatch(account, identity.deviceId,
                                        peer.deviceId, now,
                                        peerCapabilities[peer.deviceId]
                                            ?.contains("contact_roster_v1") == true)
                                    if (syncHost.liveNegotiated(peer.deviceId)) {
                                        livePublisher.prepareBatch(account, identity.deviceId,
                                            peer.deviceId, now)
                                    }
                                    if (settingsMaterialized && peerCapabilities[peer.deviceId]
                                            ?.contains("account_profile_v1") == true) {
                                        settingsPublisher.enqueueForPeer(account, identity.deviceId,
                                            peer.deviceId, now)
                                    }
                                    if (peerCapabilities[peer.deviceId]
                                            ?.contains("group_links_v1") == true &&
                                        now - (lastGroupPrepareMs[peer.deviceId] ?: 0L) >= 60_000L &&
                                        roster.isLocalAuthorized(account, identity.deviceId, 0x06, now) &&
                                        roster.isAuthorized(account, peer.deviceId, 0x06, now)) {
                                        groupPublisher.prepare(account, identity.deviceId,
                                            peer.deviceId, now)
                                        lastGroupPrepareMs[peer.deviceId] = now
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
                withContext(NonCancellable) { controlJob.cancelAndJoin() }
                withContext(NonCancellable) { contactJob.cancelAndJoin() }
                syncHost.close()
                RustBridge.stopDeviceOnionListener()
                DeviceEnrollmentOwnerCoordinator.cancel()
            }
        } finally { linkedCrypto?.close(); identity.close() }
    }

    private suspend fun runGroupOnlySession(database: SecureLegionDatabase,
                                            roster: DeviceRosterStore,
                                            account: ByteArray,
                                            identity: LocalDeviceIdentity) {
        val receiver = DelegatedGroupReceiver(database)
        val delivery = DelegatedGroupDeliveryStore(database)
        val messages = DelegatedGroupMessageOutbox(database)
        val onion = identity.withTorServiceSeed { RustBridge.createDeviceOnionService(it) }
        check(onion == identity.onionAddress && RustBridge.startDeviceOnionListener())
        try {
            var nextSendMs = 0L
            var lastSequence = sourceSequence(database)
            while (kotlin.coroutines.coroutineContext.isActive &&
                SessionManager.isUnlocked(context) && networkReady() &&
                roster.isLocalAuthorized(account, identity.deviceId, 0x04)) {
                val frame = RustBridge.pollDeviceOnionFrame()
                if (frame != null && frame.isNotEmpty() &&
                    frame[0].toInt() and 255 == DeviceGroupFrame.TYPE)
                    try { handleGroupFrame(frame, account, identity, roster,
                        receiver, delivery, database) }
                    catch (error: Exception) {
                        Log.w(TAG, "Group frame rejected: ${error.message}")
                    }
                val now = System.currentTimeMillis()
                val sequence = sourceSequence(database)
                val changed = sequence != lastSequence
                lastSequence = sequence
                if ((now >= nextSendMs || changed) && (directArti ||
                        TorService.getTransportGate()?.isOpenNow() == true)) {
                    pumpGroup(account, identity, roster, messages, delivery,
                        database, now)
                    nextSendMs = now + 10_000L
                }
                delay(250)
            }
        } finally { RustBridge.stopDeviceOnionListener() }
    }

    private fun handleGroupFrame(wire: ByteArray, account: ByteArray,
                                 identity: LocalDeviceIdentity,
                                 roster: DeviceRosterStore,
                                 receiver: DelegatedGroupReceiver,
                                 delivery: DelegatedGroupDeliveryStore,
                                 database: SecureLegionDatabase) {
        val incoming = DeviceGroupFrame.parse(wire)
        if (incoming.kind == DeviceGroupFrame.Kind.PROOF_REQUEST) {
            DelegatedGroupProofExchange(database).respond(incoming, account,
                identity)?.let { (onion, reply) ->
                if (SessionManager.isUnlocked(context) &&
                    roster.isLocalAuthorized(account, identity.deviceId, 0x04))
                    RustBridge.sendDeviceOnionFrame(onion, reply)
            }
            return
        }
        if (incoming.isAcknowledgment) {
            if (delivery.acknowledge(wire, account, identity))
                context.sendBroadcast(Intent("com.securelegion.NEW_GROUP_MESSAGE").apply {
                    setPackage(context.packageName)
                    putExtra("GROUP_ID", incoming.groupId.joinToString("") {
                        "%02x".format(it.toInt() and 255)
                    })
                })
            return
        }
        require(incoming.kind == DeviceGroupFrame.Kind.DATA ||
            incoming.kind == DeviceGroupFrame.Kind.REINVITATION ||
            incoming.kind == DeviceGroupFrame.Kind.PROOF_RESPONSE)
        val result = receiver.receive(wire, account, identity)
        if (result.complete && !result.duplicate)
            context.sendBroadcast(Intent("com.securelegion.NEW_GROUP_MESSAGE").apply {
                setPackage(context.packageName)
                putExtra("GROUP_ID", incoming.groupId.joinToString("") {
                    "%02x".format(it.toInt() and 255)
                })
            })
        result.ack?.let { ack ->
            if (SessionManager.isUnlocked(context) &&
                roster.isLocalAuthorized(account, identity.deviceId, 0x04)) {
                val onion = receiver.replyEndpoint(incoming, account, identity)
                RustBridge.sendDeviceOnionFrame(onion, ack)
            }
        }
    }

    private fun pumpGroup(account: ByteArray, identity: LocalDeviceIdentity,
                          roster: DeviceRosterStore,
                          messages: DelegatedGroupMessageOutbox,
                          delivery: DelegatedGroupDeliveryStore,
                          database: SecureLegionDatabase,
                          nowMs: Long) {
        if (!roster.isLocalAuthorized(account, identity.deviceId, 0x04, nowMs)) return
        if (nowMs >= nextAccountAckScanMs) {
            nextAccountAckScanMs = nowMs + 10_000L
            try {
                val catchup = com.securelegion.database.DelegatedGroupAccountAck(database)
                for (ack in catchup.due(account, identity, nowMs)) {
                    if (!SessionManager.isUnlocked(context) ||
                        !roster.isLocalAuthorized(account, identity.deviceId, 0x06)) break
                    if (RustBridge.sendDeviceOnionFrame(ack.onion, ack.wire))
                        catchup.markSent(ack.id, nowMs)
                }
            } catch (error: Exception) {
                Log.w(TAG, "Group account ACK deferred: ${error.message}")
            }
        }
        for (intent in messages.due(account, identity.deviceId, nowMs).take(4))
            try { messages.convert(intent.id, account, identity, nowMs) }
            catch (error: Exception) {
                Log.w(TAG, "Group intent deferred: ${error.message}")
            }
        try { delivery.prepare(account, identity, nowMs) }
        catch (error: Exception) {
            Log.w(TAG, "Group delivery preparation deferred: ${error.message}")
        }
        val due = try { delivery.due(account, identity, nowMs) }
            catch (error: Exception) {
                Log.w(TAG, "Group delivery lookup deferred: ${error.message}")
                emptyList()
            }
        for (pending in due) {
            if (!SessionManager.isUnlocked(context) ||
                !roster.isLocalAuthorized(account, identity.deviceId, 0x04)) break
            var sent = true
            for (wire in pending.wires) {
                if (!RustBridge.sendDeviceOnionFrame(pending.onion, wire)) {
                    sent = false
                    break
                }
            }
            delivery.defer(pending.id, if (sent) nowMs else nowMs + 10_000L)
        }
        if (nowMs >= nextProofScanMs) {
            nextProofScanMs = nowMs + 10_000L
            pumpProofRequests(database, account, identity, nowMs)
        }
    }

    private fun pumpProofRequests(database: SecureLegionDatabase,
                                  account: ByteArray,
                                  identity: LocalDeviceIdentity,
                                  nowMs: Long) {
        val groups = ArrayList<String>()
        database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT group_id FROM delegated_group_states WHERE group_id>? " +
                "ORDER BY group_id LIMIT 2", arrayOf(proofScanCursor))).use { cursor ->
            while (cursor.moveToNext()) groups.add(cursor.getString(0))
        }
        if (groups.isEmpty()) {
            proofScanCursor = ""
            return
        }
        proofScanCursor = groups.last()
        val exchange = DelegatedGroupProofExchange(database)
        val states = com.securelegion.database.DelegatedGroupStateStore(database)
        for (group in groups) {
            val missing = try { states.missingHistoryAuthority(group, account, nowMs) }
                catch (error: Exception) {
                    Log.w(TAG, "Group proof scan deferred: ${error.message}")
                    continue
                }
            for ((encodedRoot, hashes) in missing) {
                val root = android.util.Base64.decode(encodedRoot,
                    android.util.Base64.DEFAULT)
                if (root.contentEquals(account)) {
                    try {
                        DelegatedGroupRootApproval(database).approveMissing(group,
                            account, identity, KeyManager.getInstance(context), nowMs)
                    } catch (error: Exception) {
                        Log.w(TAG, "Primary group approval deferred: ${error.message}")
                    }
                    continue
                }
                val key = "$group:$encodedRoot"
                if ((proofDue[key] ?: 0L) > nowMs) continue
                try {
                    val requests = exchange.request(group, root, hashes,
                        account, identity, nowMs)
                    for ((onion, wire) in requests)
                        RustBridge.sendDeviceOnionFrame(onion, wire)
                    if (requests.isNotEmpty()) {
                        if (proofDue.size >= 256)
                            proofDue.keys.firstOrNull()?.let(proofDue::remove)
                        proofDue[key] = nowMs + 30_000L
                    }
                } catch (error: Exception) {
                    Log.w(TAG, "Group proof request deferred: ${error.message}")
                }
            }
        }
        if (proofDue.size > 256) proofDue.entries.removeIf { it.value <= nowMs }
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

    private fun sourceSequence(database: SecureLegionDatabase): Long =
        database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
            "SELECT COALESCE(MAX(seq),0) FROM device_sync_source_changes"
        )).use { cursor -> check(cursor.moveToFirst()); cursor.getLong(0) }

    private fun networkReady(): Boolean = directArti ||
        TorService.getCurrentTorState() == TorService.TorState.RUNNING

    private fun sendSyncApplication(host: DeviceSyncFsHost, roster: DeviceRosterStore,
                                    account: ByteArray, localId: String, peerId: String,
                                    onion: String, kind: DeviceSyncFrameV2.Kind,
                                    payload: org.json.JSONObject): Boolean {
        val capability = if (payload.optString("topic") == "group_links" ||
            payload.optString("topic") == "groups") 0x06 else 0x02
        if (!SessionManager.isUnlocked(context) ||
            !roster.isLocalAuthorized(account, localId, capability) ||
            roster.authorizedPeer(account, peerId, capability)?.onion != onion) return false
        val plaintext = DeviceSyncFrameV2.encode(kind, localId, peerId, payload)
        try {
            val sealed = host.seal(peerId, plaintext)
            if (!sealed.ready || sealed.outgoing.isEmpty()) return false
            for (wire in sealed.outgoing) {
                if (!SessionManager.isUnlocked(context) ||
                    !roster.isLocalAuthorized(account, localId, capability) ||
                    roster.authorizedPeer(account, peerId, capability)?.onion != onion) return false
                if (!RustBridge.sendDeviceOnionFrame(onion, wire)) return false
            }
            return true
        } finally { plaintext.fill(0) }
    }

    private companion object { const val TAG = "DeviceRosterRuntime" }
}
