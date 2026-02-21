package com.securelegion.services

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.CrdtOpLog
import com.securelegion.database.entities.Group
import com.securelegion.database.entities.GroupPeer
import com.securelegion.database.entities.PendingGroupDelivery
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * CRDT Group Manager — singleton orchestrator for all CRDT group operations.
 *
 * All group mutations (create, invite, message, etc.) go through this class.
 * It bridges Kotlin (Room/SQLCipher persistence) with Rust (in-memory CRDT state via JNI).
 *
 * Pattern: Kotlin persists raw op bytes in CrdtOpLog; Rust owns the derived state.
 * On startup, ops are loaded from DB and replayed via crdtLoadGroup to rebuild state.
 */
class CrdtGroupManager private constructor(private val context: Context) {

    companion object {
        private const val TAG = "CrdtGroupManager"

        @Volatile
        private var INSTANCE: CrdtGroupManager? = null

        fun getInstance(context: Context): CrdtGroupManager {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: CrdtGroupManager(context.applicationContext).also {
                    INSTANCE = it
                }
            }
        }
    }

    private val keyManager = KeyManager.getInstance(context)
    private val secureRandom = SecureRandom()

    /** Bounded concurrency for outbound Tor sends — matches Rust SEND_SEMAPHORE(6). */
    private val broadcastSemaphore = Semaphore(6)

    /** Track which groups are currently loaded in Rust memory. */
    private val loadedGroups = mutableSetOf<String>()

    /** Long-lived scope for background tasks (pending delivery retry, etc.) */
    private val managerScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    init {
        startPendingDeliveryRetryLoop()
    }

    // ==================== Routing Resolution ====================

    data class PeerRouting(val onion: String, val displayName: String)

    /**
     * Resolve a group member's onion address. Checks Contact table first (friend = authoritative),
     * falls back to GroupPeer table (routing-only, non-friend).
     *
     * @return PeerRouting with onion + display name, or null if completely unknown
     */
    suspend fun resolveRouting(db: SecureLegionDatabase, pubkeyHex: String, groupId: String): PeerRouting? {
        // 1. Contact table (friend) — authoritative source
        val pubkeyB64 = Base64.encodeToString(hexToBytes(pubkeyHex), Base64.NO_WRAP)
        val contact = db.contactDao().getContactByPublicKey(pubkeyB64)
        if (contact?.messagingOnion != null && contact.messagingOnion.isNotEmpty()) {
            return PeerRouting(contact.messagingOnion.trim().lowercase(), contact.displayName ?: "unknown")
        }
        // 2. GroupPeer table (routing-only, non-friend member)
        val peer = db.groupPeerDao().getByGroupAndPubkey(groupId, pubkeyHex)
        if (peer != null && peer.messagingOnion.isNotEmpty()) {
            return PeerRouting(peer.messagingOnion, peer.displayName)
        }
        return null
    }

    /**
     * Resolve onion address by X25519 public key. Used for SYNC_REQUEST reply routing.
     * Tries Contact first, falls back to GroupPeer.
     */
    suspend fun resolveOnionByX25519(x25519B64: String, groupIdHex: String): String? {
        val db = getDatabase()
        // 1. Contact table
        val contact = db.contactDao().getContactByX25519PublicKey(x25519B64)
        if (contact?.messagingOnion != null && contact.messagingOnion.isNotEmpty()) {
            return contact.messagingOnion.trim().lowercase()
        }
        // 2. GroupPeer table (convert B64 to hex for lookup)
        try {
            val x25519Bytes = Base64.decode(x25519B64, Base64.NO_WRAP)
            val x25519Hex = bytesToHex(x25519Bytes)
            val peer = db.groupPeerDao().getByGroupAndX25519(groupIdHex, x25519Hex)
            if (peer != null && peer.messagingOnion.isNotEmpty()) {
                return peer.messagingOnion
            }
        } catch (_: Exception) { }
        return null
    }

    // ==================== Pending Delivery Queue ====================

    /**
     * Queue an op that couldn't be delivered because routing is missing.
     * Persisted to DB so it survives app restart.
     */
    private suspend fun queuePendingDelivery(groupId: String, pubkeyHex: String, wireType: Byte, payload: ByteArray) {
        val db = getDatabase()
        val delivery = PendingGroupDelivery(
            groupId = groupId,
            targetPubkeyHex = pubkeyHex,
            wireType = wireType.toInt() and 0xFF,
            payload = payload,
            nextRetryAt = System.currentTimeMillis() + 30_000L,
            createdAt = System.currentTimeMillis()
        )
        db.pendingGroupDeliveryDao().insert(delivery)
        Log.w(TAG, "PENDING_DELIVERY: queued op for ${pubkeyHex.take(8)} in group ${groupId.take(16)}")
    }

    /**
     * Flush all pending deliveries for a member once their routing is known.
     * Called when a ROUTING_UPDATE (0x35) provides a previously-missing onion.
     */
    suspend fun flushPendingDelivery(groupId: String, pubkeyHex: String, onion: String) {
        val db = getDatabase()
        val pending = db.pendingGroupDeliveryDao().getForTarget(groupId, pubkeyHex)
        if (pending.isEmpty()) return
        Log.i(TAG, "FLUSH_PENDING: ${pending.size} deliveries to ${pubkeyHex.take(8)} via $onion")
        for (delivery in pending) {
            try {
                val success = RustBridge.sendMessageBlob(onion, delivery.payload, delivery.wireType.toByte())
                if (success) {
                    db.pendingGroupDeliveryDao().deleteById(delivery.id)
                    Log.d(TAG, "FLUSH_PENDING: delivered id=${delivery.id}")
                } else {
                    Log.w(TAG, "FLUSH_PENDING: sendMessageBlob returned false for id=${delivery.id}")
                }
            } catch (e: Exception) {
                Log.e(TAG, "FLUSH_PENDING: failed for id=${delivery.id}", e)
            }
        }
    }

    /**
     * Background retry loop for pending deliveries. Runs every 60s.
     * Retries entries past their nextRetryAt with exponential backoff.
     */
    private fun startPendingDeliveryRetryLoop() {
        managerScope.launch {
            while (isActive) {
                delay(60_000L)
                try {
                    val db = getDatabase()
                    // Purge stale entries (>1 hour old or 20+ attempts)
                    db.pendingGroupDeliveryDao().purgeStale(System.currentTimeMillis() - 3_600_000L)

                    val due = db.pendingGroupDeliveryDao().getDueForRetry(System.currentTimeMillis())
                    if (due.isEmpty()) continue
                    Log.i(TAG, "PENDING_RETRY: ${due.size} deliveries due for retry")
                    for (delivery in due) {
                        val routing = resolveRouting(db, delivery.targetPubkeyHex, delivery.groupId)
                        if (routing != null) {
                            try {
                                val success = RustBridge.sendMessageBlob(routing.onion, delivery.payload, delivery.wireType.toByte())
                                if (success) {
                                    db.pendingGroupDeliveryDao().deleteById(delivery.id)
                                    Log.d(TAG, "PENDING_RETRY: delivered id=${delivery.id} to ${routing.displayName}")
                                    continue
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "PENDING_RETRY: send failed for id=${delivery.id}", e)
                            }
                        }
                        // Exponential backoff: 30s, 60s, 120s, 240s... capped at 15 min
                        val newCount = delivery.attemptCount + 1
                        val backoff = (30_000L * (1L shl minOf(newCount, 6))).coerceAtMost(900_000L)
                        db.pendingGroupDeliveryDao().updateRetry(delivery.id, newCount, System.currentTimeMillis() + backoff)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "PENDING_RETRY: sweep error", e)
                }
            }
        }
    }

    private fun getDatabase(): SecureLegionDatabase {
        val dbPassphrase = keyManager.getDatabasePassphrase()
        return SecureLegionDatabase.getInstance(context, dbPassphrase)
    }

    // ==================== Wire Format Helpers ====================

    /**
     * Pack ops into length-prefixed format for Rust: [4-byte BE u32 len][op bytes]...
     */
    fun packOps(ops: List<CrdtOpLog>): ByteArray {
        val buf = ByteArrayOutputStream()
        for (op in ops) {
            val len = op.opBytes.size
            buf.write(byteArrayOf(
                (len shr 24 and 0xFF).toByte(),
                (len shr 16 and 0xFF).toByte(),
                (len shr 8 and 0xFF).toByte(),
                (len and 0xFF).toByte()
            ))
            buf.write(op.opBytes)
        }
        return buf.toByteArray()
    }

    /**
     * Pack a single op's raw bytes into length-prefixed format.
     */
    fun packSingleOp(opBytes: ByteArray): ByteArray {
        val buf = ByteArrayOutputStream()
        val len = opBytes.size
        buf.write(byteArrayOf(
            (len shr 24 and 0xFF).toByte(),
            (len shr 16 and 0xFF).toByte(),
            (len shr 8 and 0xFF).toByte(),
            (len and 0xFF).toByte()
        ))
        buf.write(opBytes)
        return buf.toByteArray()
    }

    // ==================== Tor Broadcast ====================

    /**
     * Broadcast a CRDT op to all accepted group members via Tor (0x30 wire type).
     *
     * Wire format sent by RustBridge.sendMessageBlob:
     *   [0x30][ourX25519:32][groupId:32][packedOps]
     * The X25519 pubkey is prepended automatically by the Rust sendMessageBlob implementation.
     *
     * CRDT ops are NOT per-member X25519 encrypted because:
     * - Op envelopes are Ed25519-signed (integrity + authorship)
     * - Message content is XChaCha20 group-secret encrypted (confidentiality)
     * - Tor .onion provides transport encryption
     *
     * @param groupId hex string (64 chars)
     * @param opBytes raw serialized op bytes (single op)
     */
    suspend fun broadcastOpToGroup(groupId: String, opBytes: ByteArray) {
        val db = getDatabase()
        val members = queryMembers(groupId).filter { it.accepted && !it.removed }
        val localPubkeyHex = bytesToHex(keyManager.getSigningPublicKey())

        // Build payload: [groupId:32][packedOps]
        val groupIdBytes = hexToBytes(groupId)
        val packed = packSingleOp(opBytes)
        val payload = groupIdBytes + packed

        // Resolve onion addresses via Contact → GroupPeer fallback (see resolveRouting())
        data class SendTarget(val onion: String, val displayName: String, val deviceIdHex: String, val pubkeyHex: String)
        val targets = mutableListOf<SendTarget>()
        val unreachable = mutableListOf<Pair<String, String>>() // (pubkeyHex, deviceIdHex) — missing routing
        for (member in members) {
            if (member.pubkeyHex == localPubkeyHex) continue
            val routing = resolveRouting(db, member.pubkeyHex, groupId)
            if (routing == null) {
                Log.w(TAG, "PENDING_ROUTING: no onion for member ${member.deviceIdHex.take(8)} — queueing (not dropping)")
                unreachable.add(Pair(member.pubkeyHex, member.deviceIdHex))
                continue
            }
            targets.add(SendTarget(routing.onion, routing.displayName, member.deviceIdHex, member.pubkeyHex))
        }

        // Queue pending deliveries for unreachable members (DB-backed, survives restart)
        for ((pubkeyHex, _) in unreachable) {
            queuePendingDelivery(groupId, pubkeyHex, 0x30.toByte(), payload)
        }

        // Send concurrently, bounded by semaphore (matches Rust SEND_SEMAPHORE cap of 6)
        data class SendResult(val success: Boolean, val pubkeyHex: String)
        val results = coroutineScope {
            targets.map { target ->
                async(Dispatchers.IO) {
                    broadcastSemaphore.withPermit {
                        try {
                            val success = RustBridge.sendMessageBlob(target.onion, payload, 0x30.toByte())
                            if (success) {
                                Log.d(TAG, "CRDT op sent to ${target.displayName}")
                            } else {
                                Log.w(TAG, "sendMessageBlob returned false for ${target.displayName}")
                            }
                            SendResult(success, target.pubkeyHex)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to send CRDT op to ${target.deviceIdHex.take(8)}", e)
                            SendResult(false, target.pubkeyHex)
                        }
                    }
                }
            }.awaitAll()
        }

        val sent = results.count { it.success }
        val failed = results.count { !it.success }
        Log.i(TAG, "Broadcast op to group ${groupId.take(16)}: sent=$sent failed=$failed unreachable=${unreachable.size}")

        // Queue failed sends for retry (Tor flakiness is common)
        for (result in results) {
            if (!result.success) {
                queuePendingDelivery(groupId, result.pubkeyHex, 0x30.toByte(), payload)
            }
        }

        // Self-healing: request routing for unreachable members from any successful target
        if (unreachable.isNotEmpty() && targets.isNotEmpty()) {
            val reachableOnion = targets.first().onion
            for ((pubkeyHex, deviceIdHex) in unreachable) {
                try {
                    sendRoutingRequest(groupId, pubkeyHex, reachableOnion)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to request routing for ${deviceIdHex.take(8)}", e)
                }
            }
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    /**
     * Send a raw payload to all accepted group members with a given wire type.
     * Used by both broadcastOpToGroup (0x30) and requestSyncToAllPeers (0x32).
     */
    private suspend fun broadcastRaw(groupId: String, wireType: Byte, payload: ByteArray) {
        val db = getDatabase()
        val members = queryMembers(groupId).filter { it.accepted && !it.removed }
        val localPubkeyHex = bytesToHex(keyManager.getSigningPublicKey())

        // Resolve targets via Contact → GroupPeer fallback
        data class RawTarget(val onion: String, val deviceIdHex: String)
        val targets = mutableListOf<RawTarget>()
        for (member in members) {
            if (member.pubkeyHex == localPubkeyHex) continue
            val routing = resolveRouting(db, member.pubkeyHex, groupId)
            if (routing == null) {
                Log.w(TAG, "broadcastRaw: no routing for ${member.deviceIdHex.take(8)} — skipping (sync protocol)")
                continue
            }
            targets.add(RawTarget(routing.onion, member.deviceIdHex))
        }

        // Send concurrently, bounded by semaphore
        val results = coroutineScope {
            targets.map { target ->
                async(Dispatchers.IO) {
                    broadcastSemaphore.withPermit {
                        try {
                            RustBridge.sendMessageBlob(target.onion, payload, wireType)
                        } catch (e: Exception) {
                            Log.e(TAG, "broadcastRaw 0x${"%02x".format(wireType)} failed for ${target.deviceIdHex.take(8)}", e)
                            false
                        }
                    }
                }
            }.awaitAll()
        }

        val sent = results.count { it }
        val failed = results.count { !it }

        // Collect unreachable members for self-healing
        val unreachableRaw = mutableListOf<String>()
        for (member in members) {
            if (member.pubkeyHex == localPubkeyHex) continue
            val routing = resolveRouting(db, member.pubkeyHex, groupId)
            if (routing == null) unreachableRaw.add(member.pubkeyHex)
        }

        Log.i(TAG, "broadcastRaw 0x${"%02x".format(wireType)} group=${groupId.take(16)}: sent=$sent failed=$failed unreachable=${unreachableRaw.size}")

        // Self-healing: request routing for unreachable members
        if (unreachableRaw.isNotEmpty() && targets.isNotEmpty()) {
            val reachableOnion = targets.first().onion
            for (pubkeyHex in unreachableRaw) {
                try {
                    sendRoutingRequest(groupId, pubkeyHex, reachableOnion)
                } catch (e: Exception) {
                    Log.e(TAG, "broadcastRaw: routing request failed for ${pubkeyHex.take(8)}", e)
                }
            }
        }
    }

    // ==================== Invite Bundle ====================

    /**
     * Send ALL ops for a group to a specific recipient (invitee).
     * Used when inviting: the invitee needs GroupCreate + all prior ops to bootstrap.
     *
     * @param groupId hex (64 chars)
     * @param recipientPubkeyHex Ed25519 public key of the invitee (64 hex chars)
     */
    private suspend fun sendInviteBundleToInvitee(groupId: String, recipientPubkeyHex: String) {
        val db = getDatabase()
        val ops = db.crdtOpLogDao().getOpsForGroup(groupId)
        if (ops.isEmpty()) {
            Log.w(TAG, "sendInviteBundle: no ops for group $groupId — nothing to send")
            return
        }

        // Look up invitee via Contact → GroupPeer fallback
        val routing = resolveRouting(db, recipientPubkeyHex, groupId)
        if (routing == null) {
            Log.w(TAG, "sendInviteBundle: no onion for invitee ${recipientPubkeyHex.take(16)} — queueing for retry")
            val payload = hexToBytes(groupId) + packOps(ops)
            queuePendingDelivery(groupId, recipientPubkeyHex, 0x30.toByte(), payload)
            return
        }

        // Build payload: [groupId:32][packedOps]
        val payload = hexToBytes(groupId) + packOps(ops)
        try {
            val success = RustBridge.sendMessageBlob(routing.onion, payload, 0x30.toByte())
            Log.i(TAG, "sendInviteBundle: sent ${ops.size} ops (${payload.size} bytes) to ${routing.displayName} — success=$success")
            if (!success) {
                Log.w(TAG, "sendInviteBundle: send returned false — queueing for retry")
                queuePendingDelivery(groupId, recipientPubkeyHex, 0x30.toByte(), payload)
            }
        } catch (e: Exception) {
            Log.e(TAG, "sendInviteBundle: failed to send to ${routing.displayName} — queueing for retry", e)
            queuePendingDelivery(groupId, recipientPubkeyHex, 0x30.toByte(), payload)
        }
    }

    // ==================== Routing Exchange (0x35 / 0x36) ====================

    /**
     * Binary format for a single routing entry:
     * [ed25519Pubkey:32][x25519Pubkey:32][onionLen:u16 BE][onion:N][nameLen:u16 BE][name:N UTF-8]
     */
    data class RoutingEntry(
        val pubkeyHex: String,
        val x25519Hex: String,
        val onion: String,
        val displayName: String
    )

    /**
     * Pack routing entries into wire format for 0x35 ROUTING_UPDATE.
     * Payload: [groupId:32][senderPubkey:32][ed25519Sig:64][count:u16 BE][entries...]
     * The signature covers everything from count onward.
     */
    private fun packRoutingUpdate(groupId: String, entries: List<RoutingEntry>): ByteArray {
        // Build the inner payload (count + entries) — this is what gets signed
        val innerBuf = ByteArrayOutputStream()
        // count: u16 BE
        innerBuf.write(byteArrayOf(
            (entries.size shr 8 and 0xFF).toByte(),
            (entries.size and 0xFF).toByte()
        ))
        for (entry in entries) {
            val pubkeyBytes = hexToBytes(entry.pubkeyHex)
            val x25519Bytes = if (entry.x25519Hex.length == 64) hexToBytes(entry.x25519Hex) else ByteArray(32)
            val onionBytes = entry.onion.toByteArray(Charsets.UTF_8)
            val nameBytes = entry.displayName.toByteArray(Charsets.UTF_8)

            innerBuf.write(pubkeyBytes)       // 32 bytes
            innerBuf.write(x25519Bytes)       // 32 bytes
            // onion length + bytes
            innerBuf.write(byteArrayOf((onionBytes.size shr 8 and 0xFF).toByte(), (onionBytes.size and 0xFF).toByte()))
            innerBuf.write(onionBytes)
            // name length + bytes
            innerBuf.write(byteArrayOf((nameBytes.size shr 8 and 0xFF).toByte(), (nameBytes.size and 0xFF).toByte()))
            innerBuf.write(nameBytes)
        }
        val innerPayload = innerBuf.toByteArray()

        // Sign the inner payload with our Ed25519 key
        val privKey = keyManager.getSigningKeyBytes()
        val signature = RustBridge.signData(innerPayload, privKey)

        // Build full payload: [groupId:32][senderPubkey:32][sig:64][innerPayload]
        val senderPubkey = keyManager.getSigningPublicKey()
        val fullBuf = ByteArrayOutputStream()
        fullBuf.write(hexToBytes(groupId))    // 32 bytes
        fullBuf.write(senderPubkey)           // 32 bytes
        fullBuf.write(signature)              // 64 bytes
        fullBuf.write(innerPayload)
        return fullBuf.toByteArray()
    }

    /**
     * Parse and verify a 0x35 ROUTING_UPDATE payload (after groupId is stripped).
     * Input data starts AFTER the 32-byte groupId (stripped by TorService).
     * Format: [senderPubkey:32][sig:64][count:u16 BE][entries...]
     *
     * @return list of RoutingEntry, or null if verification fails
     */
    suspend fun parseAndVerifyRoutingUpdate(groupIdHex: String, data: ByteArray): List<RoutingEntry>? {
        if (data.size < 32 + 64 + 2) {
            Log.w(TAG, "ROUTING_UPDATE too short: ${data.size} bytes")
            return null
        }

        val senderPubkey = data.copyOfRange(0, 32)
        val signature = data.copyOfRange(32, 96)
        val innerPayload = data.copyOfRange(96, data.size)

        // Verify Ed25519 signature
        if (!RustBridge.verifySignature(innerPayload, signature, senderPubkey)) {
            Log.e(TAG, "ROUTING_UPDATE: INVALID SIGNATURE — dropping")
            return null
        }

        // Verify sender is an accepted, non-removed member of the group
        val senderHex = bytesToHex(senderPubkey)
        try {
            ensureLoaded(groupIdHex)
            val members = queryMembers(groupIdHex)
            val senderMember = members.find { it.pubkeyHex == senderHex }
            if (senderMember == null || !senderMember.accepted || senderMember.removed) {
                Log.e(TAG, "ROUTING_UPDATE: sender ${senderHex.take(8)} is NOT an active group member — dropping")
                return null
            }
        } catch (e: Exception) {
            Log.w(TAG, "ROUTING_UPDATE: could not verify membership for ${senderHex.take(8)} — accepting on trust (group may not be loaded)", e)
        }

        // Parse entries
        if (innerPayload.size < 2) return null
        val count = ((innerPayload[0].toInt() and 0xFF) shl 8) or (innerPayload[1].toInt() and 0xFF)
        val entries = mutableListOf<RoutingEntry>()
        var offset = 2

        for (i in 0 until count) {
            if (offset + 64 > innerPayload.size) break // need 32+32 bytes for pubkeys
            val pubkey = innerPayload.copyOfRange(offset, offset + 32)
            offset += 32
            val x25519 = innerPayload.copyOfRange(offset, offset + 32)
            offset += 32

            if (offset + 2 > innerPayload.size) break
            val onionLen = ((innerPayload[offset].toInt() and 0xFF) shl 8) or (innerPayload[offset + 1].toInt() and 0xFF)
            offset += 2
            if (offset + onionLen > innerPayload.size) break
            val onion = String(innerPayload.copyOfRange(offset, offset + onionLen), Charsets.UTF_8)
            offset += onionLen

            if (offset + 2 > innerPayload.size) break
            val nameLen = ((innerPayload[offset].toInt() and 0xFF) shl 8) or (innerPayload[offset + 1].toInt() and 0xFF)
            offset += 2
            if (offset + nameLen > innerPayload.size) break
            val name = String(innerPayload.copyOfRange(offset, offset + nameLen), Charsets.UTF_8)
            offset += nameLen

            entries.add(RoutingEntry(
                pubkeyHex = bytesToHex(pubkey),
                x25519Hex = bytesToHex(x25519),
                onion = onion.trim().lowercase(),
                displayName = name
            ))
        }

        Log.i(TAG, "ROUTING_UPDATE: verified ${entries.size} entries from ${senderHex.take(8)}")
        return entries
    }

    /**
     * Send full routing directory to a specific member (used during invite).
     * Includes routing for all accepted members (Contact + GroupPeer fallback).
     */
    private suspend fun sendRoutingDirectoryToMember(groupId: String, recipientPubkeyHex: String) {
        val db = getDatabase()
        val members = queryMembers(groupId).filter { it.accepted && !it.removed }
        val localPubkeyHex = bytesToHex(keyManager.getSigningPublicKey())

        val entries = mutableListOf<RoutingEntry>()
        for (member in members) {
            if (member.pubkeyHex == recipientPubkeyHex) continue // don't send their own routing to them

            val routing = resolveRouting(db, member.pubkeyHex, groupId)
            val onion = routing?.onion ?: continue
            val displayName = routing.displayName

            // Get x25519 key: try Contact, then GroupPeer
            val pubkeyB64 = Base64.encodeToString(hexToBytes(member.pubkeyHex), Base64.NO_WRAP)
            val contact = db.contactDao().getContactByPublicKey(pubkeyB64)
            val x25519Hex = if (contact?.x25519PublicKeyBase64 != null) {
                try {
                    bytesToHex(Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP))
                } catch (_: Exception) { "" }
            } else {
                db.groupPeerDao().getByGroupAndPubkey(groupId, member.pubkeyHex)?.x25519PubkeyHex ?: ""
            }

            entries.add(RoutingEntry(member.pubkeyHex, x25519Hex, onion, displayName))
        }

        // Also include our own routing info
        val localOnion = keyManager.getMessagingOnion()
        if (localOnion != null) {
            val localX25519Hex = bytesToHex(keyManager.getEncryptionPublicKey())
            val localName = keyManager.getUsername() ?: "unknown"
            entries.add(RoutingEntry(localPubkeyHex, localX25519Hex, localOnion.trim().lowercase(), localName))
        }

        if (entries.isEmpty()) {
            Log.w(TAG, "sendRoutingDirectory: no routing entries to send")
            return
        }

        val payload = packRoutingUpdate(groupId, entries)
        val recipientRouting = resolveRouting(db, recipientPubkeyHex, groupId)
        if (recipientRouting == null) {
            Log.w(TAG, "sendRoutingDirectory: can't reach invitee ${recipientPubkeyHex.take(8)} — queueing")
            queuePendingDelivery(groupId, recipientPubkeyHex, 0x35.toByte(), payload)
            return
        }

        try {
            val success = RustBridge.sendMessageBlob(recipientRouting.onion, payload, 0x35.toByte())
            Log.i(TAG, "sendRoutingDirectory: sent ${entries.size} entries to ${recipientRouting.displayName} — success=$success")
            if (!success) {
                Log.w(TAG, "sendRoutingDirectory: send returned false — queueing for retry")
                queuePendingDelivery(groupId, recipientPubkeyHex, 0x35.toByte(), payload)
            }
        } catch (e: Exception) {
            Log.e(TAG, "sendRoutingDirectory: failed — queueing for retry", e)
            queuePendingDelivery(groupId, recipientPubkeyHex, 0x35.toByte(), payload)
        }
    }

    /**
     * Broadcast a single member's routing info to all existing group members.
     * Used when inviting: tell everyone how to reach the new member.
     */
    private suspend fun broadcastRoutingAnnounce(groupId: String, newMemberPubkeyHex: String) {
        val db = getDatabase()

        // Get new member's routing info (they're our friend, so Contact table has it)
        val routing = resolveRouting(db, newMemberPubkeyHex, groupId)
        if (routing == null) {
            Log.w(TAG, "broadcastRoutingAnnounce: no routing for new member ${newMemberPubkeyHex.take(8)}")
            return
        }

        // Get x25519 key for new member
        val pubkeyB64 = Base64.encodeToString(hexToBytes(newMemberPubkeyHex), Base64.NO_WRAP)
        val contact = db.contactDao().getContactByPublicKey(pubkeyB64)
        val x25519Hex = if (contact?.x25519PublicKeyBase64 != null) {
            try {
                bytesToHex(Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP))
            } catch (_: Exception) { "" }
        } else { "" }

        val entry = RoutingEntry(newMemberPubkeyHex, x25519Hex, routing.onion, routing.displayName)
        val payload = packRoutingUpdate(groupId, listOf(entry))

        // Broadcast to all via broadcastRaw (0x35)
        broadcastRaw(groupId, 0x35.toByte(), payload)
        Log.i(TAG, "broadcastRoutingAnnounce: announced ${routing.displayName} to group ${groupId.take(16)}")
    }

    /**
     * Handle incoming 0x35 ROUTING_UPDATE — store entries and flush pending deliveries.
     * Called from TorService when a routing update is received.
     *
     * @param groupIdHex group ID (64-char hex)
     * @param data payload AFTER groupId (starts at senderPubkey)
     */
    suspend fun handleRoutingUpdate(groupIdHex: String, data: ByteArray) {
        val entries = parseAndVerifyRoutingUpdate(groupIdHex, data)
        if (entries == null || entries.isEmpty()) return

        val db = getDatabase()
        val localPubkeyHex = bytesToHex(keyManager.getSigningPublicKey())

        for (entry in entries) {
            if (entry.pubkeyHex == localPubkeyHex) continue // skip self
            db.groupPeerDao().upsertPeer(GroupPeer(
                groupId = groupIdHex,
                pubkeyHex = entry.pubkeyHex,
                x25519PubkeyHex = entry.x25519Hex,
                messagingOnion = entry.onion,
                displayName = entry.displayName
            ))
            // Flush any pending deliveries for this member
            flushPendingDelivery(groupIdHex, entry.pubkeyHex, entry.onion)
        }

        Log.i(TAG, "handleRoutingUpdate: stored ${entries.size} routing entries for group ${groupIdHex.take(16)}")
    }

    /**
     * Handle incoming 0x36 ROUTING_REQUEST — respond with requested routing info.
     * Called from TorService when a peer requests routing info.
     *
     * @param groupIdHex group ID (64-char hex)
     * @param data payload AFTER groupId: [senderPubkey:32][sig:64][requestedPubkey:32]
     * @param senderOnion the requesting peer's .onion address to send response to
     */
    suspend fun handleRoutingRequest(groupIdHex: String, data: ByteArray, senderOnion: String) {
        // Minimal verification: check structure
        if (data.size < 32 + 64 + 32) {
            Log.w(TAG, "ROUTING_REQUEST too short: ${data.size} bytes")
            return
        }

        val senderPubkey = data.copyOfRange(0, 32)
        val signature = data.copyOfRange(32, 96)
        val innerPayload = data.copyOfRange(96, data.size)

        // Verify signature
        if (!RustBridge.verifySignature(innerPayload, signature, senderPubkey)) {
            Log.e(TAG, "ROUTING_REQUEST: INVALID SIGNATURE — dropping")
            return
        }

        // Verify sender is group member
        val senderHex = bytesToHex(senderPubkey)
        try {
            ensureLoaded(groupIdHex)
            val members = queryMembers(groupIdHex)
            val senderMember = members.find { it.pubkeyHex == senderHex }
            if (senderMember == null || !senderMember.accepted || senderMember.removed) {
                Log.e(TAG, "ROUTING_REQUEST: sender ${senderHex.take(8)} is NOT active member — dropping")
                return
            }
        } catch (e: Exception) {
            Log.w(TAG, "ROUTING_REQUEST: membership check failed — dropping", e)
            return
        }

        if (innerPayload.size < 32) return
        val requestedPubkey = innerPayload.copyOfRange(0, 32)
        val isAllZeros = requestedPubkey.all { it == 0.toByte() }

        val db = getDatabase()
        val entries = mutableListOf<RoutingEntry>()

        if (isAllZeros) {
            // Send all known routing for this group
            val allMembers = queryMembers(groupIdHex).filter { it.accepted && !it.removed }
            val localPubkeyHex = bytesToHex(keyManager.getSigningPublicKey())
            for (member in allMembers) {
                if (member.pubkeyHex == senderHex) continue // don't send requester their own info
                val routing = resolveRouting(db, member.pubkeyHex, groupIdHex)
                if (routing != null) {
                    val peer = db.groupPeerDao().getByGroupAndPubkey(groupIdHex, member.pubkeyHex)
                    entries.add(RoutingEntry(
                        member.pubkeyHex,
                        peer?.x25519PubkeyHex ?: "",
                        routing.onion,
                        routing.displayName
                    ))
                }
            }
            // Include our own routing info
            val localOnion = keyManager.getMessagingOnion()
            if (localOnion != null) {
                entries.add(RoutingEntry(
                    localPubkeyHex,
                    bytesToHex(keyManager.getEncryptionPublicKey()),
                    localOnion.trim().lowercase(),
                    keyManager.getUsername() ?: "unknown"
                ))
            }
        } else {
            // Send routing for specific member
            val requestedHex = bytesToHex(requestedPubkey)
            val routing = resolveRouting(db, requestedHex, groupIdHex)
            if (routing != null) {
                val peer = db.groupPeerDao().getByGroupAndPubkey(groupIdHex, requestedHex)
                entries.add(RoutingEntry(requestedHex, peer?.x25519PubkeyHex ?: "", routing.onion, routing.displayName))
            }
        }

        if (entries.isEmpty()) {
            Log.w(TAG, "ROUTING_REQUEST: no entries to respond with")
            return
        }

        val responsePayload = packRoutingUpdate(groupIdHex, entries)
        try {
            RustBridge.sendMessageBlob(senderOnion, responsePayload, 0x35.toByte())
            Log.i(TAG, "ROUTING_RESPONSE: sent ${entries.size} entries to ${senderHex.take(8)}")
        } catch (e: Exception) {
            Log.e(TAG, "ROUTING_RESPONSE: failed to send", e)
        }
    }

    /**
     * Send ROUTING_REQUEST (0x36) for a specific member to a reachable peer.
     * Used for self-healing when routing is missing.
     */
    suspend fun sendRoutingRequest(groupId: String, requestedPubkeyHex: String, targetOnion: String) {
        val requestedPubkey = hexToBytes(requestedPubkeyHex)

        // Sign the request
        val privKey = keyManager.getSigningKeyBytes()
        val signature = RustBridge.signData(requestedPubkey, privKey)

        val buf = ByteArrayOutputStream()
        buf.write(hexToBytes(groupId))                    // 32 bytes
        buf.write(keyManager.getSigningPublicKey())        // 32 bytes
        buf.write(signature)                               // 64 bytes
        buf.write(requestedPubkey)                         // 32 bytes
        val payload = buf.toByteArray()

        try {
            RustBridge.sendMessageBlob(targetOnion, payload, 0x36.toByte())
            Log.i(TAG, "ROUTING_REQUEST: asked for ${requestedPubkeyHex.take(8)} via $targetOnion")
        } catch (e: Exception) {
            Log.e(TAG, "ROUTING_REQUEST: failed to send", e)
        }
    }

    /**
     * Check if we have a pending invite for this group and process it.
     * Called after applyReceivedOps to detect incoming invites.
     *
     * If our local pubkey is in the member list with accepted=false,
     * we have a pending invite. Extract the group secret and create
     * a Group entity so the group shows in the list.
     *
     * @return true if a pending invite was found and processed
     */
    suspend fun checkAndProcessPendingInvites(groupId: String): Boolean {
        val db = getDatabase()

        // If Group entity already exists, no need to process invite
        val existingGroup = db.groupDao().getGroupById(groupId)
        if (existingGroup != null) return false

        // Query members to check if we're in the list
        val localPubkeyHex = bytesToHex(keyManager.getSigningPublicKey())
        val members: List<CrdtMember>
        try {
            members = queryMembers(groupId)
        } catch (e: Exception) {
            Log.w(TAG, "checkPendingInvites: queryMembers failed for $groupId — group may not be loadable yet", e)
            return false
        }

        val myEntry = members.find { it.pubkeyHex == localPubkeyHex }
        if (myEntry == null || myEntry.removed) return false

        // We're in the member list — extract group secret and create Group entity
        val groupSecretB64 = myEntry.encryptedGroupSecretB64
        if (groupSecretB64.isEmpty()) {
            Log.w(TAG, "checkPendingInvites: no group secret in invite for $groupId")
            return false
        }

        // Try to get group name and avatar from metadata
        var groupName = "Group"
        var groupIcon: String? = null
        try {
            val metadata = queryMetadata(groupId)
            if (!metadata.name.isNullOrEmpty()) {
                groupName = metadata.name
            }
            if (!metadata.avatarB64.isNullOrEmpty()) {
                groupIcon = metadata.avatarB64
            }
        } catch (_: Exception) { /* metadata query failed — use defaults */ }

        val now = System.currentTimeMillis()
        val acceptedCount = members.count { it.accepted && !it.removed }
        db.groupDao().insertGroup(Group(
            groupId = groupId,
            name = groupName,
            groupSecretB64 = groupSecretB64,
            groupIcon = groupIcon,
            createdAt = now,
            lastActivityTimestamp = now,
            memberCount = acceptedCount,
            isPendingInvite = !myEntry.accepted
        ))

        Log.i(TAG, "checkPendingInvites: created Group entity for pending invite — group=$groupId name=$groupName accepted=${myEntry.accepted}")

        // Seed GroupPeer routing for members we can already resolve (from Contact table).
        // The full directory arrives via 0x35 ROUTING_UPDATE from the inviter shortly after.
        var seeded = 0
        for (member in members) {
            if (member.pubkeyHex == localPubkeyHex || member.removed) continue
            try {
                val routing = resolveRouting(db, member.pubkeyHex, groupId)
                if (routing != null) {
                    // Try to get x25519 key from Contact
                    val pubkeyB64 = Base64.encodeToString(hexToBytes(member.pubkeyHex), Base64.NO_WRAP)
                    val contact = db.contactDao().getContactByPublicKey(pubkeyB64)
                    val x25519Hex = if (contact?.x25519PublicKeyBase64 != null) {
                        try { bytesToHex(Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)) }
                        catch (_: Exception) { "" }
                    } else ""

                    db.groupPeerDao().upsertPeer(GroupPeer(
                        groupId = groupId,
                        pubkeyHex = member.pubkeyHex,
                        x25519PubkeyHex = x25519Hex,
                        messagingOnion = routing.onion.trim().lowercase(),
                        displayName = routing.displayName
                    ))
                    seeded++
                }
            } catch (e: Exception) {
                Log.w(TAG, "checkPendingInvites: failed to seed routing for ${member.pubkeyHex.take(8)}", e)
            }
        }
        Log.i(TAG, "checkPendingInvites: seeded GroupPeer routing for $seeded/${members.size - 1} members")

        // Auto-accept for protocol correctness: accept membership so we can receive/decrypt messages.
        // UI stays in "pending invite" state (isPendingInvite=true) until user explicitly taps Accept.
        if (!myEntry.accepted && myEntry.invitedByOpId.isNotEmpty()) {
            try {
                Log.i(TAG, "checkPendingInvites: auto-accepting membership for protocol for $groupId (opId=${myEntry.invitedByOpId})")
                val opBytes = acceptInvite(groupId, myEntry.invitedByOpId)
                // Note: do NOT clear isPendingInvite here — let the UI Accept button do that
                Log.i(TAG, "checkPendingInvites: protocol-accept successful — UI still shows pending until user confirms")
            } catch (e: Exception) {
                Log.w(TAG, "checkPendingInvites: auto-accept failed (user can manually accept later)", e)
            }
        }

        // Show system notification for the invite
        showGroupInviteNotification(groupId, groupName)

        // Broadcast so the groups list refreshes
        context.sendBroadcast(android.content.Intent("com.securelegion.GROUP_INVITE_RECEIVED").apply {
            setPackage(context.packageName)
            putExtra("GROUP_ID", groupId)
            putExtra("GROUP_NAME", groupName)
        })

        return true
    }

    /**
     * Show a system notification for a group invite.
     * Uses the same high-priority auth channel as friend requests.
     */
    private fun showGroupInviteNotification(groupId: String, groupName: String) {
        try {
            val notificationId = 6000 + Math.abs(groupId.hashCode() % 10000)

            val isUnlocked = com.securelegion.utils.SessionManager.isUnlocked(context)

            val intent = if (isUnlocked) {
                android.content.Intent(context, com.securelegion.MainActivity::class.java).apply {
                    putExtra("SHOW_GROUPS", true)
                    flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP
                }
            } else {
                android.content.Intent(context, com.securelegion.LockActivity::class.java).apply {
                    putExtra("TARGET_ACTIVITY", "MainActivity")
                    putExtra("SHOW_GROUPS", true)
                    flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP
                }
            }

            val pendingIntent = android.app.PendingIntent.getActivity(
                context,
                notificationId,
                intent,
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
            )

            val notification = androidx.core.app.NotificationCompat.Builder(context, "message_auth_channel_v2")
                .setSmallIcon(com.securelegion.R.drawable.ic_shield)
                .setContentTitle("Group Invite")
                .setContentText("You've been invited to join $groupName")
                .setPriority(androidx.core.app.NotificationCompat.PRIORITY_HIGH)
                .setCategory(androidx.core.app.NotificationCompat.CATEGORY_SOCIAL)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .setGroup("GROUP_INVITES")
                .build()

            val notificationManager = context.getSystemService(android.app.NotificationManager::class.java)
            notificationManager.notify(notificationId, notification)

            Log.i(TAG, "Group invite notification shown for $groupName (ID: $notificationId)")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show group invite notification", e)
        }
    }

    // ==================== Pull-Based Sync ====================

    /**
     * Request missing ops from all peers for a group.
     * Sends 0x32 SYNC_REQUEST with our max lamport as cursor.
     * Call this on group open and optionally on app resume.
     *
     * Wire payload: [groupId:32][afterLamport:u64 BE][limit:u32 BE]
     */
    suspend fun requestSyncToAllPeers(groupId: String, limit: Int = 2048) {
        val db = getDatabase()
        val afterLamport = db.crdtOpLogDao().getMaxLamport(groupId) ?: 0L

        val buf = java.io.ByteArrayOutputStream()
        buf.write(hexToBytes(groupId))                     // 32 bytes
        buf.write(u64be(afterLamport))                     // 8 bytes
        buf.write(u32be(limit))                            // 4 bytes
        val payload = buf.toByteArray()

        Log.i(TAG, "SYNC_REQUEST: group=${groupId.take(16)} afterLamport=$afterLamport limit=$limit")
        broadcastRaw(groupId, 0x32.toByte(), payload)
    }

    /**
     * Handle an incoming 0x32 SYNC_REQUEST from a peer.
     * Reads the cursor, fetches ops from DB, sends 0x33 SYNC_CHUNK back.
     *
     * @param groupId hex (64 chars)
     * @param requestBytes [afterLamport:u64 BE][limit:u32 BE] (12 bytes)
     * @param senderOnion the peer's .onion address to reply to
     */
    suspend fun handleSyncRequest(groupId: String, requestBytes: ByteArray, senderOnion: String) {
        if (requestBytes.size < 12) {
            Log.w(TAG, "SYNC_REQUEST requestBytes too short: ${requestBytes.size}")
            return
        }
        val afterLamport = readU64be(requestBytes, 0)
        val limit = readU32be(requestBytes, 8)
        Log.i(TAG, "SYNC_REQUEST: group=${groupId.take(16)} afterLamport=$afterLamport limit=$limit from $senderOnion")

        val db = getDatabase()
        val ops = db.crdtOpLogDao().getOpsAfter(groupId, afterLamport, limit)
        if (ops.isEmpty()) {
            Log.d(TAG, "SYNC_REQUEST: no ops to send (peer is up to date)")
            return
        }

        // Build SYNC_CHUNK payload: [groupId:32][packedOps]
        val packed = packOps(ops)
        val payload = hexToBytes(groupId) + packed
        Log.i(TAG, "SYNC_CHUNK: sending ${ops.size} ops (${payload.size} bytes) to $senderOnion")

        try {
            val success = RustBridge.sendMessageBlob(senderOnion, payload, 0x33.toByte())
            if (success) {
                Log.i(TAG, "SYNC_CHUNK sent successfully")
            } else {
                Log.w(TAG, "SYNC_CHUNK sendMessageBlob returned false")
            }
        } catch (e: Exception) {
            Log.e(TAG, "SYNC_CHUNK send failed", e)
        }
    }

    // ==================== Binary Helpers ====================

    private fun u64be(value: Long): ByteArray {
        return byteArrayOf(
            (value shr 56 and 0xFF).toByte(),
            (value shr 48 and 0xFF).toByte(),
            (value shr 40 and 0xFF).toByte(),
            (value shr 32 and 0xFF).toByte(),
            (value shr 24 and 0xFF).toByte(),
            (value shr 16 and 0xFF).toByte(),
            (value shr 8 and 0xFF).toByte(),
            (value and 0xFF).toByte()
        )
    }

    private fun u32be(value: Int): ByteArray {
        return byteArrayOf(
            (value shr 24 and 0xFF).toByte(),
            (value shr 16 and 0xFF).toByte(),
            (value shr 8 and 0xFF).toByte(),
            (value and 0xFF).toByte()
        )
    }

    private fun readU64be(bytes: ByteArray, offset: Int): Long {
        return ((bytes[offset].toLong() and 0xFF) shl 56) or
            ((bytes[offset + 1].toLong() and 0xFF) shl 48) or
            ((bytes[offset + 2].toLong() and 0xFF) shl 40) or
            ((bytes[offset + 3].toLong() and 0xFF) shl 32) or
            ((bytes[offset + 4].toLong() and 0xFF) shl 24) or
            ((bytes[offset + 5].toLong() and 0xFF) shl 16) or
            ((bytes[offset + 6].toLong() and 0xFF) shl 8) or
            (bytes[offset + 7].toLong() and 0xFF)
    }

    private fun readU32be(bytes: ByteArray, offset: Int): Int {
        return ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)
    }

    // ==================== Core Operations ====================

    /**
     * Create a new CRDT group.
     * Generates groupId (32 random bytes, 64-char hex), 32-byte XChaCha20 group secret,
     * creates GroupCreate op, stores op + Group entity.
     * @return groupId hex string (64 chars)
     */
    suspend fun createGroup(name: String, icon: String? = null): String {
        val groupIdBytes = ByteArray(32).also { secureRandom.nextBytes(it) }
        val groupIdHex = bytesToHex(groupIdBytes)

        val groupSecret = ByteArray(32).also { secureRandom.nextBytes(it) }
        val groupSecretB64 = Base64.encodeToString(groupSecret, Base64.NO_WRAP)

        val authorPubkey = keyManager.getSigningPublicKey()
        val authorPrivkey = keyManager.getSigningKeyBytes()

        val paramsJson = JSONObject().apply {
            put("group_name", name)
            put("encrypted_group_secret_b64", groupSecretB64)
        }.toString()

        val resultJson = RustBridge.crdtCreateOp(
            groupIdHex, "GroupCreate", paramsJson,
            authorPubkey, authorPrivkey
        )

        val opBytes = storeOpFromResult(resultJson, groupIdHex, "GroupCreate")

        // Also create MetadataSet("Name") op so name propagates via CRDT to invitees
        val nameB64 = Base64.encodeToString(name.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        val nameParamsJson = JSONObject().apply {
            put("key", "Name")
            put("value_b64", nameB64)
        }.toString()
        val nameResultJson = RustBridge.crdtCreateOp(
            groupIdHex, "MetadataSet", nameParamsJson,
            authorPubkey, authorPrivkey
        )
        storeOpFromResult(nameResultJson, groupIdHex, "MetadataSet")

        // If icon provided, create MetadataSet("Avatar") op so icon propagates.
        // Compress aggressively for CRDT: 256x256, JPEG ~30KB target (well under 64KB op limit).
        if (!icon.isNullOrEmpty()) {
            val compressedIcon = compressAvatarForCrdt(icon)
            if (compressedIcon != null) {
                val avatarParamsJson = JSONObject().apply {
                    put("key", "Avatar")
                    put("value_b64", compressedIcon)
                }.toString()
                val avatarResultJson = RustBridge.crdtCreateOp(
                    groupIdHex, "MetadataSet", avatarParamsJson,
                    authorPubkey, authorPrivkey
                )
                storeOpFromResult(avatarResultJson, groupIdHex, "MetadataSet")
            } else {
                Log.w(TAG, "createGroup: failed to compress avatar — skipping CRDT metadata")
            }
        }

        // Store Group entity (UI cache)
        val now = System.currentTimeMillis()
        getDatabase().groupDao().insertGroup(Group(
            groupId = groupIdHex,
            name = name,
            groupSecretB64 = groupSecretB64,
            groupIcon = icon,
            createdAt = now,
            lastActivityTimestamp = now,
            memberCount = 1
        ))

        synchronized(loadedGroups) { loadedGroups.add(groupIdHex) }

        Log.i(TAG, "Created group: $groupIdHex")
        return groupIdHex
    }

    /**
     * Load group state from persisted ops into Rust in-memory state.
     * Call on app startup or before querying group state.
     * Safe to call multiple times — skips if already loaded.
     * @return true if group is loaded (either freshly or was already loaded)
     */
    suspend fun loadGroup(groupId: String): Boolean {
        synchronized(loadedGroups) {
            if (loadedGroups.contains(groupId)) return true
        }

        val ops = getDatabase().crdtOpLogDao().getOpsForGroup(groupId)
        if (ops.isEmpty()) {
            Log.w(TAG, "loadGroup: no ops for $groupId")
            return false
        }
        val packed = packOps(ops)
        val success = RustBridge.crdtLoadGroup(groupId, packed)
        if (success) {
            synchronized(loadedGroups) { loadedGroups.add(groupId) }
            Log.i(TAG, "loadGroup: loaded ${ops.size} ops for $groupId")
        } else {
            Log.e(TAG, "loadGroup: Rust rebuild failed for $groupId")
        }
        return success
    }

    /**
     * Ensure group is loaded. Call before any crdtQuery or crdtApplyOps.
     * @return true if group is loaded (or was already loaded)
     */
    private suspend fun ensureLoaded(groupId: String): Boolean {
        synchronized(loadedGroups) {
            if (loadedGroups.contains(groupId)) return true
        }
        return loadGroup(groupId)
    }

    /**
     * Unload group state from Rust memory (off-screen or low-memory).
     */
    fun unloadGroup(groupId: String) {
        RustBridge.crdtUnloadGroup(groupId)
        synchronized(loadedGroups) { loadedGroups.remove(groupId) }
    }

    /**
     * Invite a member to the group.
     *
     * This method handles the full invite flow:
     * 1. Create MemberInvite op
     * 2. Broadcast invite op to existing accepted members (0x30)
     * 3. Send full op bundle to invitee (GroupCreate + all ops, so they can bootstrap)
     *
     * @param contactPubkeyHex Ed25519 public key of the invitee (64 hex chars)
     * @return raw op bytes (for reference; broadcast already done internally)
     */
    suspend fun inviteMember(
        groupId: String,
        contactPubkeyHex: String,
        role: String = "Member"
    ): ByteArray {
        val group = getDatabase().groupDao().getGroupById(groupId)
            ?: throw IllegalStateException("Group $groupId not found")

        val authorPubkey = keyManager.getSigningPublicKey()
        val authorPrivkey = keyManager.getSigningKeyBytes()

        // v1: pass raw group secret in invite (transport + SQLCipher protect at rest)
        val paramsJson = JSONObject().apply {
            put("invited_pubkey_hex", contactPubkeyHex)
            put("role", role)
            put("encrypted_group_secret_b64", group.groupSecretB64)
        }.toString()

        val resultJson = RustBridge.crdtCreateOp(
            groupId, "MemberInvite", paramsJson,
            authorPubkey, authorPrivkey
        )

        val opBytes = storeOpFromResult(resultJson, groupId, "MemberInvite")

        // Broadcast invite op to existing accepted members
        broadcastOpToGroup(groupId, opBytes)

        // Send full op bundle to invitee (they need GroupCreate + all prior ops)
        sendInviteBundleToInvitee(groupId, contactPubkeyHex)

        // NEW: Send routing directory to invitee (so they can reach all existing members)
        try {
            sendRoutingDirectoryToMember(groupId, contactPubkeyHex)
        } catch (e: Exception) {
            Log.e(TAG, "inviteMember: failed to send routing directory to invitee", e)
        }

        // NEW: Broadcast invitee's routing info to all existing members (so they can reach the invitee)
        try {
            broadcastRoutingAnnounce(groupId, contactPubkeyHex)
        } catch (e: Exception) {
            Log.e(TAG, "inviteMember: failed to broadcast routing announce", e)
        }

        return opBytes
    }

    /**
     * Accept a pending invite.
     *
     * Creates a MemberAccept op and broadcasts it to all group members.
     * After accepting, the local device becomes an active member and can
     * send/receive messages.
     *
     * @param inviteOpIdHex the op_id of the MemberInvite op ("authorHex:lamportHex:nonceHex")
     * @return raw op bytes (broadcast already done internally)
     */
    suspend fun acceptInvite(groupId: String, inviteOpIdHex: String): ByteArray {
        val authorPubkey = keyManager.getSigningPublicKey()
        val authorPrivkey = keyManager.getSigningKeyBytes()

        val paramsJson = JSONObject().apply {
            put("invite_op_id_hex", inviteOpIdHex)
        }.toString()

        val resultJson = RustBridge.crdtCreateOp(
            groupId, "MemberAccept", paramsJson,
            authorPubkey, authorPrivkey
        )

        val opBytes = storeOpFromResult(resultJson, groupId, "MemberAccept")

        // Clear pending invite flag + update member count
        val db = getDatabase()
        db.groupDao().updatePendingInvite(groupId, false)
        try {
            val members = queryMembers(groupId)
            db.groupDao().updateMemberCount(groupId, members.count { it.accepted && !it.removed })
        } catch (_: Exception) { }

        // Broadcast MemberAccept to all group members
        broadcastOpToGroup(groupId, opBytes)

        return opBytes
    }

    /**
     * Remove a member (kick) or leave the group.
     * @return raw op bytes for Tor broadcast
     */
    suspend fun removeMember(
        groupId: String,
        targetPubkeyHex: String,
        reason: String = "Kick"
    ): ByteArray {
        val authorPubkey = keyManager.getSigningPublicKey()
        val authorPrivkey = keyManager.getSigningKeyBytes()

        val paramsJson = JSONObject().apply {
            put("target_pubkey_hex", targetPubkeyHex)
            put("reason", reason)
        }.toString()

        val resultJson = RustBridge.crdtCreateOp(
            groupId, "MemberRemove", paramsJson,
            authorPubkey, authorPrivkey
        )

        val opBytes = storeOpFromResult(resultJson, groupId, "MemberRemove")

        // Clean up routing + pending deliveries for the removed member
        try {
            val db = getDatabase()
            db.groupPeerDao().deletePeer(groupId, targetPubkeyHex)
            db.pendingGroupDeliveryDao().deleteForTarget(groupId, targetPubkeyHex)
            Log.i(TAG, "removeMember: cleaned up GroupPeer + pending deliveries for ${targetPubkeyHex.take(8)}")
        } catch (e: Exception) {
            Log.w(TAG, "removeMember: cleanup failed for ${targetPubkeyHex.take(8)}", e)
        }

        return opBytes
    }

    /**
     * Send a message to the group.
     * Encrypts plaintext with group secret via XChaCha20-Poly1305.
     * @return Pair(raw op bytes for Tor broadcast, msg_id hex)
     */
    suspend fun sendMessage(groupId: String, plaintext: String): Pair<ByteArray, String> {
        val group = getDatabase().groupDao().getGroupById(groupId)
            ?: throw IllegalStateException("Group $groupId not found")

        val authorPubkey = keyManager.getSigningPublicKey()
        val authorPrivkey = keyManager.getSigningKeyBytes()

        // Encrypt plaintext with group secret
        val groupSecretBytes = Base64.decode(group.groupSecretB64, Base64.NO_WRAP)
        val nonce = ByteArray(24).also { secureRandom.nextBytes(it) }
        val ciphertext = RustBridge.xchacha20Encrypt(
            plaintext.toByteArray(Charsets.UTF_8), groupSecretBytes, nonce
        )

        val paramsJson = JSONObject().apply {
            put("ciphertext_b64", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            put("nonce_b64", Base64.encodeToString(nonce, Base64.NO_WRAP))
        }.toString()

        val resultJson = RustBridge.crdtCreateOp(
            groupId, "MsgAdd", paramsJson,
            authorPubkey, authorPrivkey
        )

        val result = JSONObject(resultJson)
        val msgIdHex = result.optString("msg_id_hex", "")
        val opBytes = storeOpFromResult(resultJson, groupId, "MsgAdd")

        val db = getDatabase()
        val now = System.currentTimeMillis()
        db.groupDao().updateLastActivity(groupId, now)
        // Cache preview: truncate to 80 chars for list display
        val preview = if (plaintext.length > 80) plaintext.take(80) + "..." else plaintext
        db.groupDao().updateLastMessagePreview(groupId, preview)

        return Pair(opBytes, msgIdHex)
    }

    /**
     * Edit a message.
     * @return raw op bytes for Tor broadcast
     */
    suspend fun editMessage(groupId: String, msgIdHex: String, newPlaintext: String): ByteArray {
        val group = getDatabase().groupDao().getGroupById(groupId)
            ?: throw IllegalStateException("Group $groupId not found")

        val authorPubkey = keyManager.getSigningPublicKey()
        val authorPrivkey = keyManager.getSigningKeyBytes()

        val groupSecretBytes = Base64.decode(group.groupSecretB64, Base64.NO_WRAP)
        val nonce = ByteArray(24).also { secureRandom.nextBytes(it) }
        val ciphertext = RustBridge.xchacha20Encrypt(
            newPlaintext.toByteArray(Charsets.UTF_8), groupSecretBytes, nonce
        )

        val paramsJson = JSONObject().apply {
            put("msg_id_hex", msgIdHex)
            put("new_ciphertext_b64", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            put("nonce_b64", Base64.encodeToString(nonce, Base64.NO_WRAP))
        }.toString()

        val resultJson = RustBridge.crdtCreateOp(
            groupId, "MsgEdit", paramsJson,
            authorPubkey, authorPrivkey
        )

        return storeOpFromResult(resultJson, groupId, "MsgEdit")
    }

    /**
     * Delete a message (tombstone).
     * @return raw op bytes for Tor broadcast
     */
    suspend fun deleteMessage(groupId: String, msgIdHex: String): ByteArray {
        val authorPubkey = keyManager.getSigningPublicKey()
        val authorPrivkey = keyManager.getSigningKeyBytes()

        val paramsJson = JSONObject().apply {
            put("msg_id_hex", msgIdHex)
        }.toString()

        val resultJson = RustBridge.crdtCreateOp(
            groupId, "MsgDelete", paramsJson,
            authorPubkey, authorPrivkey
        )

        return storeOpFromResult(resultJson, groupId, "MsgDelete")
    }

    /**
     * Set/remove a reaction on a message.
     * @return raw op bytes for Tor broadcast
     */
    suspend fun setReaction(
        groupId: String,
        msgIdHex: String,
        emoji: String,
        present: Boolean
    ): ByteArray {
        val authorPubkey = keyManager.getSigningPublicKey()
        val authorPrivkey = keyManager.getSigningKeyBytes()

        val paramsJson = JSONObject().apply {
            put("msg_id_hex", msgIdHex)
            put("emoji", emoji)
            put("present", present)
        }.toString()

        val resultJson = RustBridge.crdtCreateOp(
            groupId, "ReactionSet", paramsJson,
            authorPubkey, authorPrivkey
        )

        return storeOpFromResult(resultJson, groupId, "ReactionSet")
    }

    /**
     * Set group metadata (name, topic, avatar).
     * @param key "Name", "Topic", or "Avatar"
     * @param valueB64 Base64-encoded value
     * @return raw op bytes for Tor broadcast
     */
    suspend fun setMetadata(groupId: String, key: String, valueB64: String): ByteArray {
        val authorPubkey = keyManager.getSigningPublicKey()
        val authorPrivkey = keyManager.getSigningKeyBytes()

        val paramsJson = JSONObject().apply {
            put("key", key)
            put("value_b64", valueB64)
        }.toString()

        val resultJson = RustBridge.crdtCreateOp(
            groupId, "MetadataSet", paramsJson,
            authorPubkey, authorPrivkey
        )

        val opBytes = storeOpFromResult(resultJson, groupId, "MetadataSet")

        // Update Group entity cache if name changed
        if (key == "Name") {
            val name = String(Base64.decode(valueB64, Base64.NO_WRAP), Charsets.UTF_8)
            getDatabase().groupDao().updateGroupName(groupId, name)
        }

        return opBytes
    }

    // ==================== Receive / Apply ====================

    /**
     * Apply received ops from a remote peer.
     * rawPackedBytes is length-prefixed: [4-byte BE u32 len][op bytes]...
     * Persists ops in DB first, then applies to in-memory CRDT state.
     *
     * Also checks for pending invites — if the received ops include a
     * MemberInvite for our local device, creates a Group entity so the
     * group appears in the list.
     *
     * @return Pair(applied count, rejected count)
     */
    suspend fun applyReceivedOps(groupId: String, rawPackedBytes: ByteArray): Pair<Int, Int> {
        val db = getDatabase()

        // 1. Persist individual ops in DB (persistence before state)
        val individualOps = splitPackedOps(rawPackedBytes, groupId)
        for (op in individualOps) {
            db.crdtOpLogDao().insertOp(op)
        }

        // 2. Try to load group + apply ops in Rust
        // This may fail for brand-new groups (e.g., invite bundle with GroupCreate).
        // In that case, ops are still persisted in DB — loadGroup will retry on next access.
        var applied = 0
        var rejected = 0
        try {
            ensureLoaded(groupId)
            val resultJson = RustBridge.crdtApplyOps(groupId, rawPackedBytes)
            val result = JSONObject(resultJson)
            applied = result.getInt("applied")
            rejected = result.getInt("rejected")
        } catch (e: Exception) {
            // Group may not be loadable yet (e.g., ops arrived out of order).
            // Ops are persisted — they'll be applied on next loadGroup attempt.
            Log.w(TAG, "applyReceivedOps: Rust apply failed for $groupId (ops persisted, will retry)", e)

            // Force reload: clear loaded flag so next ensureLoaded retries from DB
            synchronized(loadedGroups) { loadedGroups.remove(groupId) }
            try {
                ensureLoaded(groupId)
                val resultJson = RustBridge.crdtApplyOps(groupId, rawPackedBytes)
                val result = JSONObject(resultJson)
                applied = result.getInt("applied")
                rejected = result.getInt("rejected")
            } catch (e2: Exception) {
                Log.w(TAG, "applyReceivedOps: retry also failed — ops are persisted for later", e2)
            }
        }

        // 3. Check for pending invites (creates Group entity if we were invited)
        try {
            checkAndProcessPendingInvites(groupId)
        } catch (e: Exception) {
            Log.w(TAG, "applyReceivedOps: checkPendingInvites failed (non-fatal)", e)
        }

        // 4. Update cache fields if Group entity exists
        try {
            if (db.groupDao().groupExists(groupId)) {
                val now = System.currentTimeMillis()
                db.groupDao().updateLastActivity(groupId, now)

                // Update member count
                val members = queryMembers(groupId)
                db.groupDao().updateMemberCount(groupId, members.count { it.accepted && !it.removed })

                // Update last message preview (decrypt most recent message)
                val group = db.groupDao().getGroupById(groupId)
                if (group != null && !group.isPendingInvite) {
                    try {
                        val groupSecretBytes = Base64.decode(group.groupSecretB64, Base64.NO_WRAP)
                        val messages = queryMessagesAfter(groupId, 0, 1000)
                        val lastMsg = messages.lastOrNull()
                        if (lastMsg != null && !lastMsg.deleted) {
                            val text = decryptMessage(lastMsg, groupSecretBytes)
                            if (text != null) {
                                val preview = if (text.length > 80) text.take(80) + "..." else text
                                db.groupDao().updateLastMessagePreview(groupId, preview)
                            }
                        }
                    } catch (_: Exception) { }
                }
            }
        } catch (_: Exception) { /* Group entity may not exist yet */ }

        Log.i(TAG, "applyReceivedOps: $groupId applied=$applied rejected=$rejected")
        return Pair(applied, rejected)
    }

    /**
     * Split length-prefixed packed bytes into individual CrdtOpLog entries.
     * Uses SHA-256 content hash as opId for deduplication.
     *
     * Note: received ops are stored with lamport=0 because we can't parse
     * bincode in Kotlin. The DAO query orders by (lamport ASC, createdAt ASC)
     * so received ops sort by arrival time. CRDTs converge regardless of
     * replay order, so this is correct but not optimal for replay performance.
     */
    private fun splitPackedOps(rawPackedBytes: ByteArray, groupId: String): List<CrdtOpLog> {
        val ops = mutableListOf<CrdtOpLog>()
        var offset = 0
        val now = System.currentTimeMillis()
        val digest = MessageDigest.getInstance("SHA-256")
        val MAX_OP_SIZE = 64 * 1024 // 64KB per op (guardrail)

        while (offset + 4 <= rawPackedBytes.size) {
            val len = ((rawPackedBytes[offset].toInt() and 0xFF) shl 24) or
                      ((rawPackedBytes[offset + 1].toInt() and 0xFF) shl 16) or
                      ((rawPackedBytes[offset + 2].toInt() and 0xFF) shl 8) or
                      (rawPackedBytes[offset + 3].toInt() and 0xFF)
            offset += 4

            // Guard: reject zero-length, negative, or oversized ops
            if (len <= 0 || len > MAX_OP_SIZE) {
                Log.w(TAG, "splitPackedOps: bad len=$len at offset=${offset - 4} — aborting parse")
                break
            }
            if (offset + len > rawPackedBytes.size) {
                Log.w(TAG, "splitPackedOps: truncated op (need $len, have ${rawPackedBytes.size - offset}) — aborting parse")
                break
            }

            val opBytes = rawPackedBytes.copyOfRange(offset, offset + len)
            offset += len

            // Content-addressable dedup: SHA-256(op_bytes) → hex as opId
            digest.reset()
            val hash = digest.digest(opBytes)
            val opId = "sha256:" + bytesToHex(hash)

            ops.add(CrdtOpLog(
                opId = opId,
                groupId = groupId,
                opType = "Received",
                opBytes = opBytes,
                lamport = 0,
                createdAt = now
            ))

            // Increment createdAt to preserve arrival order within a batch
            // (ops in the same batch get sequential timestamps)
        }

        return ops
    }

    // ==================== Queries ====================

    /**
     * Query group members from in-memory CRDT state.
     * Group must be loaded first via loadGroup() / ensureLoaded().
     */
    suspend fun queryMembers(groupId: String): List<CrdtMember> {
        if (!ensureLoaded(groupId)) return emptyList()
        val json = RustBridge.crdtQuery(groupId, "members", "{}")
        val arr = JSONArray(json)
        return (0 until arr.length()).map { i ->
            val obj = arr.getJSONObject(i)
            CrdtMember(
                deviceIdHex = obj.getString("device_id"),
                pubkeyHex = obj.getString("pubkey_hex"),
                role = obj.getString("role"),
                accepted = obj.getBoolean("accepted"),
                removed = obj.getBoolean("removed"),
                invitedByOpId = obj.optString("invited_by_op_id", ""),
                encryptedGroupSecretB64 = obj.optString("encrypted_group_secret_b64", "")
            )
        }
    }

    /**
     * Query messages after a lamport cursor (for pagination).
     * Returns messages with ciphertext — call decryptMessage() to decrypt each.
     */
    suspend fun queryMessagesAfter(
        groupId: String,
        afterLamport: Long = 0,
        limit: Int = 100
    ): List<CrdtMessage> {
        if (!ensureLoaded(groupId)) return emptyList()
        val params = JSONObject().apply {
            put("after_lamport", afterLamport)
            put("limit", limit)
        }.toString()
        val json = RustBridge.crdtQuery(groupId, "messages_after", params)
        return parseMessagesJson(json)
    }

    /**
     * Query all renderable messages (membership-gated, not deleted).
     */
    suspend fun queryAllMessages(groupId: String): List<CrdtMessage> {
        if (!ensureLoaded(groupId)) return emptyList()
        val json = RustBridge.crdtQuery(groupId, "messages", "{}")
        return parseMessagesJson(json)
    }

    /**
     * Decrypt a message's ciphertext using the group secret.
     * @return decrypted plaintext, or null if decryption fails or message is deleted
     */
    fun decryptMessage(msg: CrdtMessage, groupSecretBytes: ByteArray): String? {
        if (msg.deleted) return null
        if (msg.ciphertextB64.isEmpty() || msg.nonceB64.isEmpty()) return null
        return try {
            val ciphertext = Base64.decode(msg.ciphertextB64, Base64.NO_WRAP)
            val nonce = Base64.decode(msg.nonceB64, Base64.NO_WRAP)
            if (nonce.size != 24) return null
            val plaintext = RustBridge.xchacha20Decrypt(ciphertext, groupSecretBytes, nonce)
            plaintext?.toString(Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt message ${msg.msgIdHex}", e)
            null
        }
    }

    /**
     * Query and decrypt all messages for a group.
     * Loads group secret from DB and decrypts in one call.
     */
    suspend fun queryAndDecryptMessages(
        groupId: String,
        afterLamport: Long = 0,
        limit: Int = 100
    ): List<CrdtMessage> {
        val group = getDatabase().groupDao().getGroupById(groupId)
            ?: return emptyList()
        val groupSecretBytes = try {
            Base64.decode(group.groupSecretB64, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "queryAndDecryptMessages: invalid groupSecretB64 for $groupId", e)
            return emptyList()
        }
        if (groupSecretBytes.size != 32) {
            Log.e(TAG, "queryAndDecryptMessages: bad secret length ${groupSecretBytes.size} for $groupId")
            return emptyList()
        }

        val messages = queryMessagesAfter(groupId, afterLamport, limit)
        for (msg in messages) {
            msg.decryptedText = decryptMessage(msg, groupSecretBytes)
        }
        return messages
    }

    /**
     * Query group metadata (name, topic, avatar).
     */
    suspend fun queryMetadata(groupId: String): CrdtMetadata {
        if (!ensureLoaded(groupId)) return CrdtMetadata(null, null, null)
        val json = RustBridge.crdtQuery(groupId, "metadata", "{}")
        val obj = JSONObject(json)
        return CrdtMetadata(
            name = obj.optString("name", null),
            topic = obj.optString("topic", null),
            avatarB64 = obj.optString("avatar_b64", null)
        )
    }

    /**
     * Query convergence hash (for sync verification).
     */
    suspend fun queryStateHash(groupId: String): String {
        if (!ensureLoaded(groupId)) return ""
        val json = RustBridge.crdtQuery(groupId, "state_hash", "{}")
        return JSONObject(json).getString("hash")
    }

    // ==================== Delete Group ====================

    /**
     * Delete a group locally (removes ops + Group entity, unloads from Rust).
     */
    suspend fun deleteGroup(groupId: String) {
        unloadGroup(groupId)
        val db = getDatabase()
        db.crdtOpLogDao().deleteOpsForGroup(groupId)
        db.groupPeerDao().deletePeersForGroup(groupId)
        db.pendingGroupDeliveryDao().deleteForGroup(groupId)
        db.groupDao().deleteGroupById(groupId)
        Log.i(TAG, "Deleted group: $groupId")
    }

    // ==================== Internal Helpers ====================

    /**
     * Parse crdtCreateOp result JSON, store op in DB, return raw op bytes.
     */
    private suspend fun storeOpFromResult(
        resultJson: String,
        groupId: String,
        opType: String
    ): ByteArray {
        val result = JSONObject(resultJson)
        val opBytesB64 = result.getString("op_bytes_b64")
        val opId = result.getString("op_id")
        val lamport = result.getLong("lamport")
        val opBytes = Base64.decode(opBytesB64, Base64.NO_WRAP)

        getDatabase().crdtOpLogDao().insertOp(CrdtOpLog(
            opId = opId,
            groupId = groupId,
            opType = opType,
            opBytes = opBytes,
            lamport = lamport,
            createdAt = System.currentTimeMillis()
        ))

        return opBytes
    }

    private fun parseMessagesJson(json: String): List<CrdtMessage> {
        val arr = JSONArray(json)
        return (0 until arr.length()).map { i ->
            val obj = arr.getJSONObject(i)
            val reactions = mutableListOf<CrdtReaction>()
            val reactionsArr = obj.optJSONArray("reactions")
            if (reactionsArr != null) {
                for (j in 0 until reactionsArr.length()) {
                    val r = reactionsArr.getJSONObject(j)
                    reactions.add(CrdtReaction(
                        reactorHex = r.getString("reactor"),
                        emoji = r.getString("emoji")
                    ))
                }
            }
            CrdtMessage(
                msgIdHex = obj.getString("msg_id"),
                authorDeviceHex = obj.getString("author"),
                timestampMs = obj.getLong("timestamp_ms"),
                deleted = obj.getBoolean("deleted"),
                ciphertextB64 = obj.getString("ciphertext_b64"),
                nonceB64 = obj.getString("nonce_b64"),
                reactions = reactions
            )
        }
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Compress a base64 photo for CRDT metadata ops.
     * Resizes to 256x256 max, JPEG quality stepped down until under 30KB raw (~40KB base64).
     * This keeps the MetadataSet op well under the 64KB CRDT payload limit.
     * Returns compressed base64 or null on failure.
     */
    private fun compressAvatarForCrdt(iconBase64: String): String? {
        return try {
            val rawBytes = Base64.decode(iconBase64, Base64.NO_WRAP)
            val bitmap = BitmapFactory.decodeByteArray(rawBytes, 0, rawBytes.size) ?: return null

            // Resize to 256x256 max
            val maxDim = 256
            val scaled = if (bitmap.width > maxDim || bitmap.height > maxDim) {
                val ratio = minOf(maxDim.toFloat() / bitmap.width, maxDim.toFloat() / bitmap.height)
                Bitmap.createScaledBitmap(bitmap, (bitmap.width * ratio).toInt(), (bitmap.height * ratio).toInt(), true)
            } else {
                bitmap
            }

            // Compress JPEG, step down quality until under 30KB
            val out = ByteArrayOutputStream()
            var quality = 70
            do {
                out.reset()
                scaled.compress(Bitmap.CompressFormat.JPEG, quality, out)
                quality -= 10
            } while (out.size() > 30_000 && quality > 10)

            val compressed = out.toByteArray()
            Log.i(TAG, "compressAvatarForCrdt: ${rawBytes.size} → ${compressed.size} bytes (quality=${quality + 10})")
            Base64.encodeToString(compressed, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "compressAvatarForCrdt: failed", e)
            null
        }
    }

    // ==================== Data Classes ====================

    data class CrdtMember(
        val deviceIdHex: String,
        val pubkeyHex: String,
        val role: String,
        val accepted: Boolean,
        val removed: Boolean,
        val invitedByOpId: String = "",
        val encryptedGroupSecretB64: String = ""
    )

    data class CrdtMessage(
        val msgIdHex: String,
        val authorDeviceHex: String,
        val timestampMs: Long,
        val deleted: Boolean,
        val ciphertextB64: String,
        val nonceB64: String,
        val reactions: List<CrdtReaction>,
        var decryptedText: String? = null
    )

    data class CrdtReaction(
        val reactorHex: String,
        val emoji: String
    )

    data class CrdtMetadata(
        val name: String?,
        val topic: String?,
        val avatarB64: String?
    )
}
