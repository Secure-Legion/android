package com.securelegion.services

import android.util.Base64
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.sync.DeviceSyncFrameV2
import com.securelegion.sync.DeviceSyncTorPolicy
import org.json.JSONObject
import java.io.Closeable

/** Roster-checked host for the memory-only portable Noise engine. */
class DeviceSyncFsHost(
    private val accountEd: ByteArray,
    private val identity: LocalDeviceIdentity,
    private val roster: DeviceRosterStore
) : Closeable {
    data class Outcome(val ready: Boolean, val becameReady: Boolean,
                       val outgoing: List<ByteArray>, val message: ByteArray?)

    private var handle = 0L
    private var closed = false
    private val peerKeys = HashMap<String, Pair<ByteArray, ByteArray>>()
    private val livePeers = HashSet<String>()
    private val legacyPeers = HashSet<String>()

    init { require(accountEd.size == 32) }

    @Synchronized
    fun ensure(peerId: String, nowMs: Long = System.currentTimeMillis()): Outcome =
        call(peerId, "ensure", null, null, nowMs)

    @Synchronized
    fun receive(peerId: String, wire: ByteArray,
                nowMs: Long = System.currentTimeMillis()): Outcome {
        require(wire.size in 5..512 * 1024 && wire[0].toInt() and 0xff in 0xB6..0xB7)
        return call(peerId, "receive", wire, null, nowMs)
    }

    @Synchronized
    fun seal(peerId: String, applicationPlaintext: ByteArray,
             nowMs: Long = System.currentTimeMillis()): Outcome {
        validateTorPlaintext(applicationPlaintext, peerId, inbound = false)
        return call(peerId, "seal", null, applicationPlaintext, nowMs)
    }

    /** Call only after an authenticated HELLO/HELLO_ACK and local feature readiness. */
    @Synchronized
    fun noteCapabilities(peerId: String, peerCapabilities: Set<String>,
                         localCapabilities: Set<String>, nowMs: Long = System.currentTimeMillis()) {
        check(!closed)
        require(roster.isLocalAuthorized(accountEd, identity.deviceId, 0x02, nowMs) &&
            roster.isAuthorized(accountEd, peerId, 0x02, nowMs))
        if (DeviceSyncTorPolicy.LIVE_CAPABILITY in peerCapabilities &&
            DeviceSyncTorPolicy.LIVE_CAPABILITY in localCapabilities) livePeers.add(peerId)
        else livePeers.remove(peerId)
        if ("tor_metadata_only_v1" !in peerCapabilities) legacyPeers.add(peerId)
        else legacyPeers.remove(peerId)
    }

    @Synchronized
    fun liveNegotiated(peerId: String, nowMs: Long = System.currentTimeMillis()): Boolean =
        peerId in livePeers &&
            roster.isLocalAuthorized(accountEd, identity.deviceId, 0x02, nowMs) &&
            roster.isAuthorized(accountEd, peerId, 0x02, nowMs)

    @Synchronized
    private fun call(peerId: String, operation: String, wire: ByteArray?,
                     message: ByteArray?, nowMs: Long): Outcome {
        check(!closed)
        require(peerId.length == 43 && peerId != identity.deviceId)
        require(nowMs in 1..9_007_199_254_740_991L)
        if (!roster.isLocalAuthorized(accountEd, identity.deviceId, 0x02, nowMs)) {
            reset()
            throw IllegalStateException("Local device is not authorized")
        }
        val peer = roster.authorizedPeer(accountEd, peerId, 0x02, nowMs)
            ?: run { forget(peerId, nowMs); throw IllegalStateException("Peer is not authorized") }
        val old = peerKeys[peerId]
        if (old != null && (!old.first.contentEquals(peer.signingKey) ||
                    !old.second.contentEquals(peer.encryptionKey))) reset()
        if (peerKeys[peerId] == null) {
            peerKeys[peerId] = peer.signingKey.copyOf() to peer.encryptionKey.copyOf()
        }
        if (handle == 0L) {
            handle = identity.withSyncKeys { ed, x -> RustBridge.syncFsNew(accountEd, ed, x) }
            check(handle > 0)
        }
        val request = JSONObject().apply {
            put("op", operation)
            put("peer", JSONObject().put("id", peerId)
                .put("ed", Base64.encodeToString(peer.signingKey, Base64.NO_WRAP))
                .put("x", Base64.encodeToString(peer.encryptionKey, Base64.NO_WRAP)))
            put("now", nowMs)
            put("wire", wire?.let { Base64.encodeToString(it, Base64.NO_WRAP) } ?: JSONObject.NULL)
            put("message", message?.let { Base64.encodeToString(it, Base64.NO_WRAP) } ?: JSONObject.NULL)
        }
        val response = JSONObject(RustBridge.syncFsCall(handle,
            request.toString().toByteArray(Charsets.UTF_8)).toString(Charsets.UTF_8))
        val outgoingJson = response.getJSONArray("outgoing")
        require(outgoingJson.length() <= 8)
        val outgoing = (0 until outgoingJson.length()).map { index ->
            val bytes = Base64.decode(outgoingJson.getString(index), Base64.DEFAULT)
            require(bytes.size in 5..512 * 1024 && bytes[0].toInt() and 0xff in 0xB6..0xB7)
            bytes
        }
        val plaintext = if (response.isNull("message")) null else
            Base64.decode(response.getString("message"), Base64.DEFAULT).also {
                validateTorPlaintext(it, peerId, inbound = true)
                if (operation == "receive" && wire != null) {
                    DeviceSyncFrameV2.decode(it, peerId, identity.deviceId, wire, nowMs)
                }
            }
        // A revocation during Noise work invalidates the result before dispatch or send.
        if (!roster.isLocalAuthorized(accountEd, identity.deviceId, 0x02, nowMs) ||
            roster.authorizedPeer(accountEd, peerId, 0x02, nowMs)?.let {
                it.signingKey.contentEquals(peer.signingKey) &&
                    it.encryptionKey.contentEquals(peer.encryptionKey)
            } != true) {
            reset()
            throw IllegalStateException("Device authorization changed")
        }
        return Outcome(response.getBoolean("ready"), response.getBoolean("became_ready"),
            outgoing, plaintext)
    }

    @Synchronized
    fun forget(peerId: String, nowMs: Long = System.currentTimeMillis()) {
        livePeers.remove(peerId)
        legacyPeers.remove(peerId)
        val keys = peerKeys.remove(peerId) ?: return
        if (handle == 0L) return
        val request = JSONObject().put("op", "forget")
            .put("peer", JSONObject().put("id", peerId)
                .put("ed", Base64.encodeToString(keys.first, Base64.NO_WRAP))
                .put("x", Base64.encodeToString(keys.second, Base64.NO_WRAP)))
            .put("now", nowMs).put("wire", JSONObject.NULL).put("message", JSONObject.NULL)
        try { RustBridge.syncFsCall(handle, request.toString().toByteArray(Charsets.UTF_8)) }
        catch (_: Exception) { reset() }
        finally { keys.first.fill(0); keys.second.fill(0) }
    }

    private fun reset() {
        if (handle != 0L) RustBridge.syncFsFree(handle)
        handle = 0L
        peerKeys.values.forEach { (ed, x) -> ed.fill(0); x.fill(0) }
        peerKeys.clear()
        livePeers.clear()
        legacyPeers.clear()
    }

    /** iOS build 48's PULL_REQUEST can carry group message actions. Block it here. */
    private fun validateTorPlaintext(bytes: ByteArray, peerId: String, inbound: Boolean) {
        require(bytes.size in 2..384 * 1024)
        val kind = bytes[0].toInt() and 0xff
        require(kind in setOf(0xB0, 0xB1, 0xB2, 0xB4, 0xB5))
        val frame = JSONObject(bytes.copyOfRange(1, bytes.size).toString(Charsets.UTF_8))
        val payload = frame.optJSONObject("payload")
            ?: throw IllegalArgumentException("Missing Tor sync payload")
        val frameKind = DeviceSyncFrameV2.Kind.fromWire(kind)
            ?: throw IllegalArgumentException("Unknown Tor sync frame")
        require(if (inbound) DeviceSyncTorPolicy.allowsInbound(frameKind, payload,
            livePeer = peerId in livePeers) else DeviceSyncTorPolicy.allows(frameKind, payload,
            livePeer = peerId in livePeers, legacyPeer = peerId in legacyPeers))
    }

    @Synchronized
    override fun close() {
        if (!closed) { reset(); closed = true }
    }
}
