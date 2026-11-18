package com.securelegion.services

import android.content.Context
import android.os.Build
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LinkedProfileCredentialStore
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.sync.DeviceEnrollmentCandidateCheckpoint
import com.securelegion.sync.DeviceEnrollmentCandidateCommitter
import com.securelegion.sync.DeviceEnrollmentCandidateSession
import com.securelegion.sync.DeviceEnrollmentWire
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Candidate-only A3 listener. It never opens the ordinary direct-message parser. */
internal object DeviceEnrollmentCandidateRuntime {
    enum class Phase { IDLE, STARTING_TOR, SHOW_QR, COMPARE, WAITING_FOR_GRANT,
                       COMPLETE, FAILED }
    data class State(val phase: Phase, val qr: String = "", val code: String = "",
                     val detail: String = "")

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutable = MutableStateFlow(State(Phase.IDLE))
    val state: StateFlow<State> = mutable
    private var job: Job? = null
    private var session: DeviceEnrollmentCandidateSession? = null
    private var identity: LocalDeviceIdentity? = null
    private var checkpointState: DeviceEnrollmentCandidateCheckpoint.State? = null
    private var context: Context? = null

    @Synchronized
    fun start(appContext: Context) {
        if (job?.isActive == true) return
        require(!KeyManager.getInstance(appContext).isInitialized())
        context = appContext.applicationContext
        mutable.value = State(Phase.STARTING_TOR, detail = "Connecting Tor")
        job = scope.launch { run(appContext.applicationContext) }
    }

    private suspend fun run(appContext: Context) {
        val checkpoint = DeviceEnrollmentCandidateCheckpoint(appContext)
        var listenerStarted = false
        try {
            val localIdentity = LocalDeviceIdentity.loadOrCreate(appContext)
            synchronized(this) { identity = localIdentity }
            val committer = DeviceEnrollmentCandidateCommitter(appContext)
            val recovered = committer.recoverCommitted(localIdentity)
            if (recovered == null) {
                val saved = checkpoint.load()
                if (saved == null) {
                    val pendingKey = LinkedProfileCredentialStore(appContext).pendingDatabaseKey()
                    if (pendingKey != null) {
                        pendingKey.fill(0)
                        error("A linked profile grant is pending. Reopen this app to recover it before starting a new link.")
                    }
                }
                val exchange = if (saved == null) {
                    DeviceEnrollmentCandidateSession.create(localIdentity, deviceName()).also {
                        val ephemeral = it.checkpointEphemeral()
                        try {
                            checkpoint.save(DeviceEnrollmentCandidateCheckpoint.State(it.qrPayload, ephemeral))
                        } finally { ephemeral.fill(0) }
                    }
                } else {
                    try { DeviceEnrollmentCandidateSession.restore(localIdentity,
                        saved.qr, saved.ephemeral) }
                    finally { saved.ephemeral.fill(0) }
                }
                synchronized(this) {
                    session = exchange
                    checkpointState = checkpoint.load()
                }
                val savedState = synchronized(this) { checkpointState }
                if (savedState?.offer != null) {
                    exchange.acceptOffer(savedState.offer)
                    if (savedState.localApproved) exchange.approveComparison()
                    savedState.ownerApproval?.let(exchange::acceptOwnerApproval)
                }
            }
            check(RustBridge.initializeTor() == "Arti bootstrapped")
            val onion = localIdentity.withTorServiceSeed { RustBridge.createDeviceOnionService(it) }
            check(onion == localIdentity.onionAddress)
            check(RustBridge.startDeviceOnionListener())
            listenerStarted = true
            val exchange = synchronized(this) { session }
            mutable.value = if (exchange == null) State(Phase.COMPLETE)
                else if (synchronized(this) { checkpointState?.offer } == null)
                    State(Phase.SHOW_QR, exchange.qrPayload)
                else State(Phase.COMPARE, exchange.qrPayload, exchange.comparisonCode)
            var nextRetry = 0L
            while (kotlin.coroutines.coroutineContext.isActive) {
                val frame = RustBridge.pollDeviceOnionFrame()
                if (frame != null && frame.isNotEmpty() && frame[0].toInt() and 255 == 0xA3)
                    try { receive(appContext, checkpoint, frame) }
                    catch (e: Exception) { Log.w(TAG, "Rejected candidate frame: ${e.message}") }
                val now = System.currentTimeMillis()
                if (now >= nextRetry) {
                    retry(appContext)
                    nextRetry = now + 10_000
                }
                delay(250)
            }
        } catch (e: Exception) {
            mutable.value = State(Phase.FAILED, detail = e.message ?: "Linking failed")
            Log.e(TAG, "Candidate runtime failed", e)
        } finally {
            if (listenerStarted) RustBridge.stopDeviceOnionListener()
            runCatching { RustBridge.shutdownArti() }
            synchronized(this) {
                session?.close(); session = null
                identity?.close(); identity = null
                checkpointState?.ephemeral?.fill(0); checkpointState = null
                context = null
            }
        }
    }

    @Synchronized
    fun approve(): State {
        require(mutable.value.phase == Phase.COMPARE)
        val exchange = session ?: throw IllegalStateException("Candidate session unavailable")
        val saved = checkpointState ?: throw IllegalStateException("Candidate checkpoint unavailable")
        val onion = exchange.ownerOnion ?: throw IllegalStateException("Owner not verified")
        val wire = exchange.approveComparison()
        val next = saved.copy(localApproved = true)
        DeviceEnrollmentCandidateCheckpoint(context!!).save(next)
        checkpointState = next
        runCatching { RustBridge.sendDeviceOnionFrame(onion, wire) }
        return State(Phase.WAITING_FOR_GRANT, exchange.qrPayload,
            exchange.comparisonCode, "Waiting for the signed grant").also { mutable.value = it }
    }

    @Synchronized
    private fun receive(appContext: Context, checkpoint: DeviceEnrollmentCandidateCheckpoint,
                        wire: ByteArray) {
        val exchange = session ?: return
        val saved = checkpointState ?: return
        val frame = DeviceEnrollmentWire.decodeFrame(wire)
        when (frame.type) {
            "offer" -> {
                val proof = exchange.acceptOffer(wire)
                if (saved.offer == null) {
                    val next = saved.copy(offer = wire.copyOf())
                    checkpoint.save(next); checkpointState = next
                }
                val onion = exchange.ownerOnion ?: error("Missing owner onion")
                runCatching { RustBridge.sendDeviceOnionFrame(onion, proof) }
                if (mutable.value.phase != Phase.WAITING_FOR_GRANT)
                    mutable.value = State(Phase.COMPARE, exchange.qrPayload, exchange.comparisonCode)
            }
            "owner_approval" -> {
                exchange.acceptOwnerApproval(wire)
                if (saved.ownerApproval == null) {
                    val next = saved.copy(ownerApproval = wire.copyOf())
                    checkpoint.save(next); checkpointState = next
                }
            }
            "grant" -> {
                val grant = exchange.acceptGrant(wire)
                val local = identity ?: error("Installation identity unavailable")
                val committer = DeviceEnrollmentCandidateCommitter(appContext)
                committer.commit(exchange, grant, local)
                exchange.close(); session = null
                checkpoint.discard()
                checkpointState?.ephemeral?.fill(0); checkpointState = null
                committer.pendingReceipt(local)?.let {
                    runCatching { RustBridge.sendDeviceOnionFrame(it.ownerOnion, it.wire) }
                }
                mutable.value = State(Phase.COMPLETE, detail = "Device authorized")
            }
            else -> throw IllegalArgumentException("Unexpected candidate frame")
        }
    }

    @Synchronized
    private fun retry(appContext: Context) {
        val local = identity ?: return
        val exchange = session
        if (exchange != null) {
            val saved = checkpointState ?: return
            val offer = saved.offer ?: return
            val onion = exchange.ownerOnion ?: return
            runCatching { RustBridge.sendDeviceOnionFrame(onion, exchange.acceptOffer(offer)) }
            if (saved.localApproved) runCatching {
                RustBridge.sendDeviceOnionFrame(onion, exchange.approveComparison())
            }
        } else DeviceEnrollmentCandidateCommitter(appContext).pendingReceipt(local)?.let {
            runCatching { RustBridge.sendDeviceOnionFrame(it.ownerOnion, it.wire) }
        }
    }

    @Synchronized
    fun stop() { job?.cancel(); job = null }

    @Synchronized
    fun discard(appContext: Context) {
        val credentials = LinkedProfileCredentialStore(appContext)
        check(credentials.activeProfile() == null) { "An authorized profile cannot be discarded here" }
        val pendingKey = credentials.pendingDatabaseKey()
        if (pendingKey != null) {
            pendingKey.fill(0)
            error("A linked profile grant is pending; do not discard this enrollment")
        }
        stop()
        DeviceEnrollmentCandidateCheckpoint(appContext).discard()
        mutable.value = State(Phase.IDLE)
    }

    private fun deviceName() = Build.MODEL.orEmpty()
        .filter { it.code >= 32 && it.code !in 127..159 }
        .trim().take(64).ifBlank { "Android" }

    private const val TAG = "DeviceCandidateRuntime"
}
