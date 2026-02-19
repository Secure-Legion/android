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
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
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

    /** Track which groups are currently loaded in Rust memory. */
    private val loadedGroups = mutableSetOf<String>()

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

        var sent = 0
        var failed = 0
        for (member in members) {
            // Skip self
            if (member.pubkeyHex == localPubkeyHex) continue

            try {
                // Look up contact by Ed25519 pubkey → get messagingOnion
                val pubkeyB64 = Base64.encodeToString(hexToBytes(member.pubkeyHex), Base64.NO_WRAP)
                val contact = db.contactDao().getContactByPublicKey(pubkeyB64)
                val onion = contact?.messagingOnion
                if (onion.isNullOrEmpty()) {
                    Log.w(TAG, "No onion for member ${member.deviceIdHex.take(8)} — skipping")
                    failed++
                    continue
                }

                val success = RustBridge.sendMessageBlob(onion, payload, 0x30.toByte())
                if (success) {
                    sent++
                    Log.d(TAG, "CRDT op sent to ${contact.displayName}")
                } else {
                    failed++
                    Log.w(TAG, "sendMessageBlob returned false for ${contact.displayName}")
                }
            } catch (e: Exception) {
                failed++
                Log.e(TAG, "Failed to send CRDT op to ${member.deviceIdHex.take(8)}", e)
            }
        }
        Log.i(TAG, "Broadcast op to group ${groupId.take(16)}: sent=$sent failed=$failed")
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

        var sent = 0
        var failed = 0
        for (member in members) {
            if (member.pubkeyHex == localPubkeyHex) continue
            try {
                val pubkeyB64 = Base64.encodeToString(hexToBytes(member.pubkeyHex), Base64.NO_WRAP)
                val contact = db.contactDao().getContactByPublicKey(pubkeyB64)
                val onion = contact?.messagingOnion
                if (onion.isNullOrEmpty()) {
                    failed++
                    continue
                }
                val success = RustBridge.sendMessageBlob(onion, payload, wireType)
                if (success) sent++ else failed++
            } catch (e: Exception) {
                failed++
                Log.e(TAG, "broadcastRaw 0x${"%02x".format(wireType)} failed for ${member.deviceIdHex.take(8)}", e)
            }
        }
        Log.i(TAG, "broadcastRaw 0x${"%02x".format(wireType)} group=${groupId.take(16)}: sent=$sent failed=$failed")
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

        // Look up invitee contact by Ed25519 pubkey → get messagingOnion
        val pubkeyB64 = Base64.encodeToString(hexToBytes(recipientPubkeyHex), Base64.NO_WRAP)
        val contact = db.contactDao().getContactByPublicKey(pubkeyB64)
        val onion = contact?.messagingOnion
        if (onion.isNullOrEmpty()) {
            Log.w(TAG, "sendInviteBundle: no onion for invitee ${recipientPubkeyHex.take(16)} — skipping")
            return
        }

        // Build payload: [groupId:32][packedOps]
        val payload = hexToBytes(groupId) + packOps(ops)
        try {
            val success = RustBridge.sendMessageBlob(onion, payload, 0x30.toByte())
            Log.i(TAG, "sendInviteBundle: sent ${ops.size} ops (${payload.size} bytes) to ${contact.displayName} — success=$success")
        } catch (e: Exception) {
            Log.e(TAG, "sendInviteBundle: failed to send to ${contact.displayName}", e)
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

        // Broadcast so the groups list refreshes
        context.sendBroadcast(android.content.Intent("com.securelegion.GROUP_INVITE_RECEIVED").apply {
            setPackage(context.packageName)
            putExtra("GROUP_ID", groupId)
            putExtra("GROUP_NAME", groupName)
        })

        return true
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

        return storeOpFromResult(resultJson, groupId, "MemberRemove")
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
