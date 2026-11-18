package com.securelegion.sync

import android.content.Context
import android.os.Build
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.services.TorService
import com.securelegion.utils.SessionManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** One unlocked owner A3 exchange. A committed grant outbox survives this object. */
internal object DeviceEnrollmentOwnerCoordinator {
    data class State(val phase: Phase, val candidateName: String = "",
                     val comparisonCode: String = "", val detail: String = "")
    enum class Phase { IDLE, WAITING_FOR_PROOF, COMPARE, WAITING_FOR_CANDIDATE,
                       GRANT_COMMITTED, COMPLETE, FAILED }

    private val mutable = MutableStateFlow(State(Phase.IDLE))
    val state: StateFlow<State> = mutable
    private var active: DeviceEnrollmentOwnerSession? = null
    private var approvedWire: ByteArray? = null

    @Synchronized
    fun start(context: Context, qr: String): State {
        requireReady(context)
        require(active == null) { "An enrollment is already in progress" }
        val keys = KeyManager.getInstance(context)
        val model = deviceName()
        val identity = LocalDeviceIdentity.loadExisting(context)
        try {
            val session = DeviceEnrollmentOwnerSession.create(qr, keys, identity, model)
            try {
                val database = SecureLegionDatabase.getInstance(context,
                    keys.getDatabasePassphrase())
                val roster = DeviceRosterStore(database)
                val account = keys.getSigningPublicKey()
                val signed = roster.fetchSignedRoster(account)
                    ?: throw IllegalStateException("Signed owner roster unavailable")
                require(roster.isLocalAuthorized(account, identity.deviceId, 0x07) &&
                    signed.isNotEmpty())
                require(RustBridge.sendDeviceOnionFrame(session.candidateOnion,
                    session.encodedOffer())) { "Offer transport unavailable" }
                active = session
                return State(Phase.WAITING_FOR_PROOF, session.candidateName).also {
                    mutable.value = it
                }
            } catch (e: Exception) { session.close(); throw e }
        } finally { identity.close() }
    }

    /** Called only with A3 frames from the isolated device-onion listener. */
    @Synchronized
    fun receive(context: Context, wire: ByteArray) {
        requireReady(context)
        val session = active ?: return
        val frame = DeviceEnrollmentWire.decodeFrame(wire)
        require(frame.transcriptId == session.transcriptId)
        if (mutable.value.phase == Phase.GRANT_COMMITTED) return
        when (frame.type) {
            "candidate_proof" -> {
                session.acceptCandidateProof(wire)
                mutable.value = State(Phase.COMPARE, session.candidateName,
                    session.comparisonCode)
            }
            "candidate_approval" -> {
                session.acceptCandidateApproval(wire)
                if (approvedWire != null) commitGrant(context, session)
                else mutable.value = State(Phase.COMPARE, session.candidateName,
                    session.comparisonCode, "Candidate approved; confirm the matching code")
            }
            else -> throw IllegalArgumentException("Unexpected enrollment frame")
        }
    }

    @Synchronized
    fun approve(context: Context): State {
        requireReady(context)
        val session = active ?: throw IllegalStateException("No enrollment in progress")
        require(mutable.value.phase == Phase.COMPARE ||
            mutable.value.phase == Phase.WAITING_FOR_CANDIDATE)
        val wire = approvedWire ?: session.approveComparison().also { approvedWire = it }
        require(RustBridge.sendDeviceOnionFrame(session.candidateOnion, wire)) {
            "Approval transport unavailable"
        }
        if (session.canIssueGrant) commitGrant(context, session)
        else mutable.value = State(Phase.WAITING_FOR_CANDIDATE, session.candidateName,
            session.comparisonCode)
        return mutable.value
    }

    private fun commitGrant(context: Context, session: DeviceEnrollmentOwnerSession) {
        if (mutable.value.phase == Phase.GRANT_COMMITTED) return
        val keys = KeyManager.getInstance(context)
        val identity = LocalDeviceIdentity.loadExisting(context)
        try {
            val database = SecureLegionDatabase.getInstance(context,
                keys.getDatabasePassphrase())
            val roster = DeviceRosterStore(database)
            val grant = DeviceRosterAuthority(roster).authorizeEnrollment(
                keys, identity, session, deviceName(), keys.getUsername()?.take(64)
                    ?.ifBlank { "Secure Legion" } ?: "Secure Legion")
            // The signed roster and exact grant are durable before this write.
            runCatching { RustBridge.sendDeviceOnionFrame(session.candidateOnion, grant.exactGrant) }
            mutable.value = State(Phase.GRANT_COMMITTED, session.candidateName,
                session.comparisonCode, "Waiting for the candidate to commit")
        } finally { identity.close() }
    }

    @Synchronized
    fun committed(transcriptId: String) {
        val session = active ?: return
        if (session.transcriptId != transcriptId) return
        val name = session.candidateName
        clearSession()
        mutable.value = State(Phase.COMPLETE, name)
    }

    @Synchronized
    fun cancel() { clearSession(); mutable.value = State(Phase.IDLE) }

    private fun clearSession() {
        active?.close(); active = null
        approvedWire?.fill(0); approvedWire = null
    }

    private fun requireReady(context: Context) {
        check(SessionManager.isUnlocked(context) &&
            KeyManager.getInstance(context).isInitialized() &&
            TorService.getCurrentTorState() == TorService.TorState.RUNNING &&
            TorService.getTransportGate()?.isOpenNow() == true) {
            "Unlock the primary account and connect Tor first"
        }
    }

    private fun deviceName() = Build.MODEL.orEmpty()
        .filter { it.code >= 32 && it.code !in 127..159 }
        .trim().take(64).ifBlank { "Android" }
}
