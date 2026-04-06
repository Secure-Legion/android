package com.securelegion.services

import android.content.Context
import android.util.Base64
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Contact List Sync Service (wire types 0x80/0x81/0x82).
 *
 * Spec: CONTACT_LIST_SYNC_PROTOCOL.md at repo root.
 *
 * Owns:
 *   - the inbound-frame polling loop (one coroutine)
 *   - dispatch into authorized handlers (PUSH store, REQUEST reply, RESPONSE import)
 *   - outbound helpers (push-to-one, push-to-all-friends, request-my-list)
 *
 * Authorization (§6.3 of the spec) happens here in Kotlin because this is where
 * the Contact DB is. Rust already did structural + signature + timestamp +
 * rate-limit checks.
 */
class ContactListSyncService private constructor(private val context: Context) {

    companion object {
        private const val TAG = "ContactListSyncService"
        private const val POLL_INTERVAL_MS = 500L
        private const val POLL_BACKOFF_MS = 5000L // after errors

        // Header sizes in the Rust → Kotlin serialized frame
        private const val TYPE_LEN = 1
        private const val PK_LEN = 32
        private const val TS_LEN = 8
        private const val CID_LEN_FIELD = 2
        private const val BLOB_LEN_FIELD = 4
        private const val HEADER_LEN = TYPE_LEN + PK_LEN + TS_LEN + CID_LEN_FIELD

        const val MSG_TYPE_CONTACT_LIST_REQUEST: Byte = 0x80.toByte()
        const val MSG_TYPE_CONTACT_LIST_RESPONSE: Byte = 0x81.toByte()
        const val MSG_TYPE_CONTACT_LIST_PUSH: Byte = 0x82.toByte()

        @Volatile private var instance: ContactListSyncService? = null

        fun getInstance(context: Context): ContactListSyncService {
            return instance ?: synchronized(this) {
                instance ?: ContactListSyncService(context.applicationContext).also { instance = it }
            }
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pollJob: Job? = null

    /** CIDs for which we have an outbound REQUEST in flight (for correlation). */
    private val inFlightRequests = mutableSetOf<String>()
    private val inFlightLock = Any()

    data class DecodedFrame(
        val msgType: Byte,
        val senderPk: ByteArray,
        val timestamp: Long,
        val cid: String,
        val blob: ByteArray,
    )

    // ─── Lifecycle ────────────────────────────────────────────────────────────

    fun startPolling() {
        if (pollJob?.isActive == true) {
            Log.d(TAG, "polling already running")
            return
        }
        Log.i(TAG, "starting contact-list-sync polling loop")
        pollJob = scope.launch {
            while (isActive) {
                try {
                    val raw = RustBridge.pollContactListFrame()
                    if (raw == null) {
                        delay(POLL_INTERVAL_MS)
                        continue
                    }
                    val decoded = try {
                        decodeFrame(raw)
                    } catch (e: Exception) {
                        Log.e(TAG, "frame decode failed, dropping", e)
                        continue
                    }
                    handleInboundFrame(decoded)
                } catch (e: Exception) {
                    Log.e(TAG, "poll loop error — backing off", e)
                    delay(POLL_BACKOFF_MS)
                }
            }
            Log.i(TAG, "polling loop exited")
        }
    }

    fun stopPolling() {
        Log.i(TAG, "stopping contact-list-sync polling loop")
        pollJob?.cancel()
        pollJob = null
    }

    // ─── Inbound decode / dispatch ────────────────────────────────────────────

    private fun decodeFrame(raw: ByteArray): DecodedFrame {
        if (raw.size < HEADER_LEN + BLOB_LEN_FIELD) {
            throw IllegalArgumentException("frame too short: ${raw.size}")
        }
        val buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        val msgType = buf.get()
        val senderPk = ByteArray(PK_LEN).also { buf.get(it) }
        val timestamp = buf.long
        val cidLen = (buf.short.toInt() and 0xFFFF)
        if (cidLen <= 0 || cidLen > 128) throw IllegalArgumentException("bad cid_len=$cidLen")
        val cidBytes = ByteArray(cidLen).also { buf.get(it) }
        val cid = String(cidBytes, Charsets.US_ASCII)
        val blobLen = buf.int
        if (blobLen < 0 || blobLen > 2 * 1024 * 1024) throw IllegalArgumentException("bad blob_len=$blobLen")
        val blob = ByteArray(blobLen).also { buf.get(it) }
        return DecodedFrame(msgType, senderPk, timestamp, cid, blob)
    }

    private suspend fun handleInboundFrame(frame: DecodedFrame) {
        when (frame.msgType) {
            MSG_TYPE_CONTACT_LIST_PUSH -> handlePush(frame)
            MSG_TYPE_CONTACT_LIST_REQUEST -> handleRequest(frame)
            MSG_TYPE_CONTACT_LIST_RESPONSE -> handleResponse(frame)
            else -> Log.w(TAG, "unknown frame type 0x${String.format("%02x", frame.msgType)}")
        }
    }

    /**
     * 0x82 PUSH: a friend is updating/pinning their own list with us.
     * Authorize: (sender_pk, cid) MUST match an existing Contact row.
     */
    private suspend fun handlePush(frame: DecodedFrame) {
        val senderPkB64 = Base64.encodeToString(frame.senderPk, Base64.NO_WRAP)
        val contact = findContactByPublicKey(senderPkB64)
        if (contact == null) {
            Log.w(TAG, "PUSH from unknown pk=${senderPkB64.take(12)}… — drop")
            return
        }
        if (contact.ipfsCid != frame.cid) {
            Log.w(
                TAG,
                "PUSH cid mismatch from ${contact.displayName}: got=${frame.cid} expected=${contact.ipfsCid} — drop"
            )
            return
        }
        if (frame.blob.isEmpty()) {
            Log.w(TAG, "PUSH with empty blob from ${contact.displayName} — drop")
            return
        }

        val ipfsManager = IPFSManager.getInstance(context)
        val stored = storeBlobLocally(ipfsManager, frame.cid, frame.blob, "${contact.displayName}'s Contact List")
        if (stored) {
            Log.i(
                TAG,
                "PUSH accepted from ${contact.displayName}: cid=${frame.cid} size=${frame.blob.size}"
            )
        }
    }

    /**
     * 0x80 REQUEST: someone is asking for the blob at a given CID.
     * Reply if authorized, else send an empty-blob NACK.
     */
    private suspend fun handleRequest(frame: DecodedFrame) {
        val senderPkB64 = Base64.encodeToString(frame.senderPk, Base64.NO_WRAP)

        // Path A: they're asking for a friend's list we have pinned
        val ownerContact = findContactByCid(frame.cid)

        // Path B: they're asking for OUR OWN list (self-recovery from new device)
        val ourCid = runCatching { KeyManager.getInstance(context).deriveContactListCID() }.getOrNull()
        val ourPubKeyB64 = runCatching {
            Base64.encodeToString(KeyManager.getInstance(context).getSolanaPublicKey(), Base64.NO_WRAP)
        }.getOrNull()

        val authorized = when {
            // Requester is the contact who owns this CID
            ownerContact != null && ownerContact.publicKeyBase64 == senderPkB64 -> true
            // Requester is us, asking for our own CID (self-recovery)
            ourCid != null && ourCid == frame.cid && ourPubKeyB64 == senderPkB64 -> true
            else -> false
        }

        val ipfsManager = IPFSManager.getInstance(context)
        val blob: ByteArray = if (authorized) {
            ipfsManager.getContactList(frame.cid) ?: ByteArray(0)
        } else {
            Log.w(TAG, "REQUEST unauthorized: pk=${senderPkB64.take(12)}… cid=${frame.cid}")
            ByteArray(0)
        }

        // We need the requester's messaging onion to reply — look it up.
        // Path A: requester is the owner contact (we know their onion)
        // Path B: requester is us — pointless to send to ourselves, skip
        val replyOnion = if (authorized && ownerContact != null) {
            ownerContact.messagingOnion
        } else if (authorized && ownerContact == null) {
            // Self-recovery request from a new device of ours: we don't reply here;
            // our own new device already has the blob locally in that case.
            null
        } else {
            // Send NACK back if we can figure out their onion via pubkey lookup
            findContactByPublicKey(senderPkB64)?.messagingOnion
        }

        if (replyOnion.isNullOrEmpty()) {
            Log.w(TAG, "REQUEST cannot reply — no onion for pk=${senderPkB64.take(12)}…")
            return
        }

        val ok = withContext(Dispatchers.IO) {
            RustBridge.sendContactListResponse(replyOnion, frame.cid, blob)
        }
        Log.i(
            TAG,
            "REQUEST reply sent authorized=$authorized blob_len=${blob.size} result=$ok cid=${frame.cid}"
        )
    }

    /**
     * 0x81 RESPONSE: reply to our outbound REQUEST.
     * Correlate to in-flight, store locally, optionally import if it's our own recovery.
     */
    private suspend fun handleResponse(frame: DecodedFrame) {
        val inFlight = synchronized(inFlightLock) { inFlightRequests.contains(frame.cid) }
        if (!inFlight) {
            Log.w(TAG, "unsolicited RESPONSE for cid=${frame.cid} — drop")
            return
        }
        synchronized(inFlightLock) { inFlightRequests.remove(frame.cid) }

        if (frame.blob.isEmpty()) {
            Log.w(TAG, "RESPONSE NACK for cid=${frame.cid}")
            return
        }

        val ipfsManager = IPFSManager.getInstance(context)
        val senderContact = findContactByPublicKey(Base64.encodeToString(frame.senderPk, Base64.NO_WRAP))
        val label = senderContact?.displayName?.let { "$it's Contact List" } ?: "Recovered Contact List"
        storeBlobLocally(ipfsManager, frame.cid, frame.blob, label)

        Log.i(TAG, "RESPONSE stored: cid=${frame.cid} size=${frame.blob.size}")

        // If this is our own CID, try to import (recovery flow).
        val ourCid = runCatching { KeyManager.getInstance(context).deriveContactListCID() }.getOrNull()
        if (ourCid == frame.cid) {
            val keyManager = KeyManager.getInstance(context)
            val seed = runCatching { keyManager.getMainWalletSeedForZcash() }.getOrNull()
            if (seed != null) {
                val pin = runCatching { keyManager.deriveContactPinFromSeed(seed) }.getOrNull()
                if (pin != null) {
                    val importResult = ContactListManager.getInstance(context).importContactList(frame.blob, pin)
                    if (importResult.isSuccess) {
                        Log.i(TAG, "RECOVERY import success: ${importResult.getOrDefault(0)} contacts restored")
                    } else {
                        Log.e(TAG, "RECOVERY import failed", importResult.exceptionOrNull())
                    }
                }
            }
        }
    }

    // ─── Outbound helpers ─────────────────────────────────────────────────────

    /** Push our own encrypted contact list to a single friend. */
    suspend fun pushToFriend(friendMessagingOnion: String): Boolean = withContext(Dispatchers.IO) {
        val keyManager = KeyManager.getInstance(context)
        val ourCid = runCatching { keyManager.deriveContactListCID() }.getOrNull() ?: run {
            Log.e(TAG, "pushToFriend: no CID available")
            return@withContext false
        }

        // Export our contact list to encrypted bytes
        val exportResult = ContactListManager.getInstance(context).exportContactList()
        val blob = exportResult.getOrNull() ?: run {
            Log.e(TAG, "pushToFriend: export failed", exportResult.exceptionOrNull())
            return@withContext false
        }

        val rc = RustBridge.sendContactListPush(friendMessagingOnion, ourCid, blob)
        Log.i(TAG, "pushToFriend onion=$friendMessagingOnion cid=$ourCid size=${blob.size} rc=$rc")
        rc == 1
    }

    /** Fire PUSH to every friend with a known messaging onion. Best-effort, no ACK. */
    suspend fun broadcastToAllFriends(): Int = withContext(Dispatchers.IO) {
        val keyManager = KeyManager.getInstance(context)
        val dbPass = keyManager.getDatabasePassphrase()
        val db = SecureLegionDatabase.getInstance(context, dbPass)
        val contacts = db.contactDao().getAllContacts()

        val ourCid = runCatching { keyManager.deriveContactListCID() }.getOrNull() ?: return@withContext 0
        val exportResult = ContactListManager.getInstance(context).exportContactList()
        val blob = exportResult.getOrNull() ?: return@withContext 0

        var okCount = 0
        for (c in contacts) {
            val onion = c.messagingOnion
            if (onion.isNullOrEmpty()) continue
            val rc = RustBridge.sendContactListPush(onion, ourCid, blob)
            if (rc == 1) okCount++
        }
        Log.i(TAG, "broadcastToAllFriends: sent to $okCount/${contacts.size} friends")
        okCount
    }

    /** Ask a friend to send us back our own encrypted list (recovery bootstrap). */
    suspend fun requestOwnListFrom(friendMessagingOnion: String): Boolean = withContext(Dispatchers.IO) {
        val keyManager = KeyManager.getInstance(context)
        val ourCid = runCatching { keyManager.deriveContactListCID() }.getOrNull() ?: run {
            Log.e(TAG, "requestOwnListFrom: no CID available")
            return@withContext false
        }
        synchronized(inFlightLock) { inFlightRequests.add(ourCid) }
        val rc = RustBridge.sendContactListRequest(friendMessagingOnion, ourCid)
        Log.i(TAG, "requestOwnListFrom onion=$friendMessagingOnion cid=$ourCid rc=$rc")
        if (rc != 1) {
            synchronized(inFlightLock) { inFlightRequests.remove(ourCid) }
        }
        rc == 1
    }

    // ─── Local storage helper ─────────────────────────────────────────────────

    private suspend fun storeBlobLocally(
        ipfsManager: IPFSManager,
        cid: String,
        blob: ByteArray,
        label: String,
    ): Boolean {
        // Re-use pinContactCard pathway (writes to ipfs_pins/{cid} + metadata)
        val r = ipfsManager.pinContactCard(cid, blob, label)
        return r.isSuccess
    }

    // ─── Contact DB lookups ───────────────────────────────────────────────────

    private suspend fun findContactByPublicKey(publicKeyBase64: String): Contact? =
        withContext(Dispatchers.IO) {
            runCatching {
                val keyManager = KeyManager.getInstance(context)
                val dbPass = keyManager.getDatabasePassphrase()
                val db = SecureLegionDatabase.getInstance(context, dbPass)
                db.contactDao().getAllContacts().firstOrNull { it.publicKeyBase64 == publicKeyBase64 }
            }.getOrNull()
        }

    private suspend fun findContactByCid(cid: String): Contact? = withContext(Dispatchers.IO) {
        runCatching {
            val keyManager = KeyManager.getInstance(context)
            val dbPass = keyManager.getDatabasePassphrase()
            val db = SecureLegionDatabase.getInstance(context, dbPass)
            db.contactDao().getAllContacts().firstOrNull { it.ipfsCid == cid }
        }.getOrNull()
    }

    fun shutdown() {
        stopPolling()
        scope.cancel()
    }
}
