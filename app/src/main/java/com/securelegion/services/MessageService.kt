package com.securelegion.services

import android.content.Context
import android.content.Intent
import android.util.Base64
import android.util.Log
import com.securelegion.crypto.KeyChainManager
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.NLx402Manager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Message
import com.securelegion.models.AckState
import com.securelegion.models.AckStateTracker
import com.securelegion.models.OutOfOrderBuffer
import com.securelegion.database.entities.ed25519PublicKeyBytes
import com.securelegion.database.entities.x25519PublicKeyBytes
import com.securelegion.database.entities.sendChainKeyBytes
import com.securelegion.database.entities.receiveChainKeyBytes
import com.securelegion.voice.CallSignaling
import com.securelegion.voice.VoiceCallManager
import com.securelegion.IncomingCallActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID

/**
 * Message Service - Handles encrypted P2P messaging over Tor
 *
 * Features:
 * - XChaCha20-Poly1305 encryption using libsodium
 * - Ed25519 digital signatures for authentication
 * - Tor hidden service communication
 * - Message persistence in encrypted SQLCipher database
 * - Delivery status tracking
 * - Message retry logic
 */
class MessageService(private val context: Context) {

    companion object {
        private const val TAG = "MessageService"

        /**
         * ACK State Tracker - Enforces strict ACK ordering per message
         * CRITICAL: Prevents out-of-order ACKs from causing permanent crypto desync
         *
         * State machine: NONE -> PING_ACKED -> PONG_ACKED -> MESSAGE_ACKED
         * Only valid transitions are allowed; all others are silently dropped
         *
         * THREAD SAFETY: Internally uses ConcurrentHashMap and CopyOnWriteArraySet
         * Safely accessed from TorService background thread, MessageRetryWorker, and UI threads
         */
        private val ackTracker = AckStateTracker()

        /**
         * Buffered out-of-order message waiting for gap to fill
         */
        data class BufferedMessage(
            val sequence: Long,
            val encryptedData: String,
            val senderPublicKey: ByteArray,
            val senderOnionAddress: String,
            val messageType: String,
            val voiceDuration: Int?,
            val selfDestructAt: Long?,
            val requiresReadReceipt: Boolean,
            val pingId: String?,
            val timestamp: Long
        )

        /**
         * Buffer for out-of-order messages per contact (legacy, deprecated)
         * Key: contactId, Value: Map of sequence -> BufferedMessage
         *
         * THREAD SAFETY: Uses ConcurrentHashMap for thread-safe concurrent access
         */
        private val messageBuffer = java.util.concurrent.ConcurrentHashMap<Long, java.util.concurrent.ConcurrentHashMap<Long, BufferedMessage>>()

        /**
         * Gap timeout buffers per contact
         * Detects and handles permanent message loss (gaps exceeding MAX_SKIP)
         * Key: contactId, Value: OutOfOrderBuffer instance
         *
         * CRITICAL: Prevents unbounded memory growth and conversation hangs
         * when messages are permanently lost (don't arrive within gap timeout)
         *
         * THREAD SAFETY: Uses ConcurrentHashMap with OutOfOrderBuffer instances
         * that internally use CopyOnWriteArrayList and @Volatile fields
         * Safely accessed from message receive path and gap timeout checks
         */
        private val gapTimeoutBuffers = java.util.concurrent.ConcurrentHashMap<Long, OutOfOrderBuffer>()

        /**
         * Get the shared ACK State Tracker instance
         * Used by TorService to check ACK validity before processing
         * Ensures all ACKs go through the state machine (prevents duplicates and out-of-order)
         */
        fun getAckTracker(): AckStateTracker = ackTracker

        /**
         * Generate a cryptographically random 24-byte nonce for ping ID
         * Returns hex-encoded string (48 characters)
         * This matches the format Rust PingToken expects
         */
        fun generatePingId(): String {
            val nonce = ByteArray(24)
            java.security.SecureRandom().nextBytes(nonce)
            return nonce.joinToString("") { "%02x".format(it) }
        }

        /**
         * Generate a cryptographically random 64-bit nonce for message ID determinism
         *
         * CRITICAL: This is generated ONCE at message creation and NEVER regenerated.
         * It is stored in the Message entity and reused for every retry, ensuring:
         * - Same plaintext + same contacts = same messageId (stable identity)
         * - Retries resend the EXACT SAME message (no ghost duplicates)
         * - Crash recovery reconstructs the same ID (deterministic)
         *
         * Why: If messageNonce is regenerated on retry, the messageId changes,
         * creating ghost duplicates. The receiver thinks each retry is a new message.
         *
         * @return Random 64-bit long (8 bytes of entropy)
         */
        fun generateMessageNonce(): Long {
            return java.security.SecureRandom().nextLong()
        }

        /**
         * Generate a stable, deterministic message ID from message metadata
         *
         * ==================== PHASE 1.2: SORTED PUBKEYS ====================
         * For 1-to-1 chats, both Alice and Bob MUST derive the same conversationId.
         * This requires sorted pubkeys in the hash input.
         *
         * SCENARIO (why this matters):
         * Alice sends to Bob:
         * Alice computes: conversationId = sort([AlicePubKey, BobPubKey])
         * → "AlicePubKey|BobPubKey" (alphabetically sorted)
         *
         * Bob receives from Alice:
         * Bob computes: conversationId = sort([AlicePubKey, BobPubKey])
         * → "AlicePubKey|BobPubKey" (SAME order, because it's sorted)
         *
         * WITHOUT SORTING (broken):
         * Alice: conversationId = "AlicePubKey|BobPubKey"
         * Bob: conversationId = "BobPubKey|AlicePubKey" ← DIFFERENT!
         * → Two separate threads, broken dedup, "why do I see two chats?" bug
         *
         * Hash inputs (in this exact order for consistent ordering):
         * v1 || conversationId || senderEd25519 || recipientEd25519 || plaintextHash || messageNonce
         *
         * Where:
         * - v1: Version string ("v1")
         * - conversationId: SORTED pair of Ed25519 public keys (this is PHASE 1.2)
         * - senderEd25519: Base64-encoded Ed25519 public key of sender
         * - recipientEd25519: Base64-encoded Ed25519 public key of recipient
         * - plaintextHash: SHA-256 hash of plaintext content (hex-encoded)
         * - messageNonce: The 64-bit random nonce (stored in Message entity)
         *
         * Why no timestamp:
         * Timestamp breaks crash recovery. After app crash/recreate, we load the
         * Message from DB using the stored messageNonce and recompute the ID.
         * If timestamp was in the hash, the ID would be different (broken determinism).
         *
         * Why messageNonce:
         * Ensures this message (even if retried 100 times with same plaintext)
         * has a unique ID that's ALWAYS the same across retries.
         *
         * MANDATORY INVARIANT (DO NOT BREAK):
         * - conversationId MUST be computed from SORTED public keys
         * - sort() must use lexicographic (string) ordering
         * - Both sender and receiver independently compute same conversationId
         * - This ensures dedup works across both devices
         *
         * @param plaintext The message content
         * @param senderEd25519Base64 The sender's Ed25519 public key (Base64)
         * @param recipientEd25519Base64 The recipient's Ed25519 public key (Base64)
         * @param messageNonce The per-message random nonce (generated once at creation)
         * @return Deterministic messageId (Base64-encoded, 32 chars)
         */
        fun generateDeterministicMessageId(
            plaintext: String,
            senderEd25519Base64: String,
            recipientEd25519Base64: String,
            messageNonce: Long
        ): String {
            // Compute SHA-256(plaintext)
            val plaintextHash = MessageDigest.getInstance("SHA-256")
                .digest(plaintext.toByteArray())
                .joinToString("") { "%02x".format(it) }

            // PHASE 1.2: SORTED PUBKEYS (MANDATORY)
            // Sort keys lexicographically to ensure Alice and Bob derive the same conversationId
            // Alice: sort([AlicePubKey, BobPubKey]) → "AlicePubKey|BobPubKey"
            // Bob: sort([AlicePubKey, BobPubKey]) → "AlicePubKey|BobPubKey" (SAME!)
            // Without sorting: Alice gets "A|B", Bob gets "B|A" → TWO SEPARATE THREADS
            // DO NOT REMOVE SORTING or 1-to-1 chats will break
            val sortedKeys = listOf(senderEd25519Base64, recipientEd25519Base64).sorted()
            val conversationId = sortedKeys.joinToString("|")

            // Hash input: v1 || conversationId || senderEd25519 || recipientEd25519 || plaintextHash || messageNonce
            val hashInput = "v1||$conversationId||$senderEd25519Base64||$recipientEd25519Base64||$plaintextHash||$messageNonce"

            // Compute SHA-256(hashInput)
            val messageIdHash = MessageDigest.getInstance("SHA-256")
                .digest(hashInput.toByteArray())

            // Base64-encode and take first 32 characters (256 bits / 8 * 4 = 128 chars, so 32 is reasonable)
            return android.util.Base64.encodeToString(messageIdHash, android.util.Base64.NO_WRAP).take(32)
        }

        /**
         * Schedule retry for a message
         * Used by MessageRetryWorker to track retry attempts
         * Increments retry count and updates last retry timestamp with exponential backoff
         * Persists the updated message to the database (suspend operation)
         *
         * @param database The SecureLegion database for persistence
         * @param message The message to retry
         */
        suspend fun scheduleRetry(database: SecureLegionDatabase, message: Message) {
            try {
                // Calculate exponential backoff
                val retryCount = message.retryCount + 1
                val initialDelay = Message.INITIAL_RETRY_DELAY_MS
                val backoffExponent = (retryCount - 1).toDouble()
                val nextRetryDelay = (initialDelay * Math.pow(Message.RETRY_BACKOFF_MULTIPLIER, backoffExponent)).toLong()

                // CRITICAL: Use partial update to avoid overwriting delivery status
                // (fixes race where MESSAGE_ACK sets delivered=true between read and write)
                database.messageDao().updateRetryState(
                    message.id,
                    retryCount,
                    System.currentTimeMillis()
                )
                Log.d(TAG, "Scheduled retry #$retryCount for message ${message.messageId}, next retry in ${nextRetryDelay}ms")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to schedule retry for message ${message.messageId}", e)
            }
        }

        /**
         * Get or create the gap timeout buffer for a contact
         * Used to detect and handle permanent message loss
         */
        fun getGapTimeoutBuffer(contactId: Long): OutOfOrderBuffer {
            return gapTimeoutBuffers.getOrPut(contactId) {
                OutOfOrderBuffer(gapTimeoutSeconds = 30L)
            }
        }

        /**
         * Clear gap timeout buffer when contact/thread is deleted
         * Prevents memory leaks from deleted contacts
         */
        fun clearGapTimeoutBuffer(contactId: Long) {
            gapTimeoutBuffers.remove(contactId)?.apply {
                clear()
                Log.d(TAG, "Cleared gap timeout buffer for contact $contactId")
            }
        }

        /**
         * Check for gap timeouts on all contacts
         * Called periodically to detect and handle permanent message loss
         */
        fun checkAllGapTimeouts(): Map<Long, List<LongRange>> {
            val lostGaps = mutableMapOf<Long, List<LongRange>>()

            gapTimeoutBuffers.forEach { (contactId, buffer) ->
                val lostRanges = buffer.checkForGapTimeout()
                if (lostRanges.isNotEmpty()) {
                    lostGaps[contactId] = lostRanges
                    Log.w(TAG, "Gap timeout detected for contact $contactId: ${lostRanges.size} gaps")
                }
            }

            return lostGaps
        }
    }

    private val keyManager = KeyManager.getInstance(context)

    /**
     * Send a voice message to a contact via Tor
     * @param contactId Database ID of the recipient contact
     * @param audioBytes The recorded audio as ByteArray
     * @param durationSeconds Duration of the voice clip in seconds
     * @param enableSelfDestruct Whether to enable self-destruct (24h)
     * @param onMessageSaved Callback when message is saved to DB (before sending)
     * @return Result with Message entity if successful
     */
    suspend fun sendVoiceMessage(
        contactId: Long,
        audioBytes: ByteArray,
        durationSeconds: Int,
        selfDestructDurationMs: Long? = null,
        onMessageSaved: ((Message) -> Unit)? = null
    ): Result<Message> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Sending voice message to contact ID: $contactId (${audioBytes.size} bytes, ${durationSeconds}s)")

            // Get database instance
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Get contact details
            val contact = database.contactDao().getContactById(contactId)
                ?: return@withContext Result.failure(Exception("Contact not found"))

            Log.d(TAG, "Sending voice to: ${contact.displayName} (${contact.torOnionAddress})")

            // Get our keypair for signing (needed for messageId determinism)
            val ourPublicKey = keyManager.getSigningPublicKey()
            val ourPrivateKey = keyManager.getSigningKeyBytes()
            val ourPublicKeyBase64 = android.util.Base64.encodeToString(ourPublicKey, android.util.Base64.NO_WRAP)

            // PHASE 1.1: STABLE IDENTITY
            // Generate message nonce ONCE (never regenerated on retry)
            val messageNonce = generateMessageNonce()

            // Generate STABLE messageId for voice message
            // Convert audio bytes to string for hashing (same as encryption input)
            val audioAsString = String(audioBytes, Charsets.ISO_8859_1)
            val messageId = generateDeterministicMessageId(
                plaintext = audioAsString,
                senderEd25519Base64 = ourPublicKeyBase64,
                recipientEd25519Base64 = contact.publicKeyBase64,
                messageNonce = messageNonce
            )
            Log.d(TAG, "Generated deterministic messageId for voice: $messageId (from nonce: $messageNonce)")

            // Get key chain for this contact (for progressive ephemeral key evolution)
            Log.d(TAG, "SEND KEY CHAIN LOAD (VOICE): Loading key chain from database...")
            Log.d(TAG, "contactId=$contactId (${contact.displayName})")
            Log.d(TAG, "Audio bytes: ${audioBytes.size} bytes")
            Log.d(TAG, "Duration: ${durationSeconds}s")

            val keyChain = KeyChainManager.getKeyChain(context, contactId)
                ?: throw Exception("Key chain not found for contact ${contact.displayName} (ID: $contactId)")
            Log.d(TAG, "SEND KEY CHAIN LOAD (VOICE): Loaded from database successfully")
            Log.d(TAG, "sendCounter=${keyChain.sendCounter} <- will use this for encryption")

            // NEW: Prepend message type and duration INSIDE plaintext BEFORE encryption
            // VOICE format: [0x01][duration:4 BE][audioBytes...]
            val durationBytes = byteArrayOf(
                (durationSeconds shr 24).toByte(),
                (durationSeconds shr 16).toByte(),
                (durationSeconds shr 8).toByte(),
                durationSeconds.toByte()
            )
            val plaintextWithType = byteArrayOf(0x01) + durationBytes + audioBytes
            val plaintextForEncryption = String(plaintextWithType, Charsets.ISO_8859_1)
            Log.d(TAG, "SEND KEY EVOLUTION (VOICE): Plaintext with type: ${plaintextWithType.size} bytes (type=0x01 VOICE, duration=${durationSeconds}s)")

            // Encrypt using current send chain key and counter (ATOMIC key evolution)
            // Wire format: [version:1][sequence:8][nonce:24][ciphertext][tag:16]
            Log.d(TAG, "SEND KEY EVOLUTION (VOICE): Encrypting with sequence ${keyChain.sendCounter}")
            val result = RustBridge.encryptMessageWithEvolution(
                plaintextForEncryption,
                keyChain.sendChainKeyBytes,
                keyChain.sendCounter
            )
            val encryptedBytes = result.ciphertext
            Log.d(TAG, "SEND KEY EVOLUTION (VOICE): Encryption complete, encrypted ${encryptedBytes.size} bytes")

            // Save evolved key to database (key evolution happened atomically in Rust)
            Log.d(TAG, "SEND KEY EVOLUTION (VOICE): Updating database with new sendCounter=${keyChain.sendCounter + 1}")
            database.contactKeyChainDao().updateSendChainKey(
                contactId = contactId,
                newSendChainKeyBase64 = android.util.Base64.encodeToString(result.evolvedChainKey, android.util.Base64.NO_WRAP),
                newSendCounter = keyChain.sendCounter + 1,
                timestamp = System.currentTimeMillis()
            )
            // VERIFY the update actually persisted
            val verifyKeyChain = database.contactKeyChainDao().getKeyChainByContactId(contactId)
            Log.d(TAG, "SEND VERIFICATION (VOICE): After update, database shows sendCounter=${verifyKeyChain?.sendCounter}")
            if (verifyKeyChain?.sendCounter != keyChain.sendCounter + 1) {
                Log.e(TAG, "SEND ERROR (VOICE): Counter update did NOT persist! Expected ${keyChain.sendCounter + 1}, got ${verifyKeyChain?.sendCounter}")
            } else {
                Log.d(TAG, "SEND (VOICE): Counter update verified successfully")
            }

            // Get our X25519 public key for sender identification
            val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

            // Wire format: [X25519:32][Encrypted payload] - NO type byte prepended after encryption
            val encryptedWithMetadata = ourX25519PublicKey + encryptedBytes
            val encryptedBase64 = Base64.encodeToString(encryptedWithMetadata, Base64.NO_WRAP)

            Log.d(TAG, "Metadata: 1 byte type + 4 bytes duration + 32 bytes X25519")
            Log.d(TAG, "Total payload: ${encryptedWithMetadata.size} bytes (${encryptedBase64.length} Base64 chars)")

            // Extract nonce from wire format (bytes 9-32, after version and sequence)
            val nonce = encryptedBytes.sliceArray(9 until 33)
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // Sign the message
            Log.d(TAG, "Signing voice message...")
            val messageData = (messageId + durationSeconds.toString() + System.currentTimeMillis()).toByteArray()
            val signature = RustBridge.signData(messageData, ourPrivateKey)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            // Save audio to local storage
            val voiceRecorder = com.securelegion.utils.VoiceRecorder(context)
            val voiceFilePath = voiceRecorder.saveVoiceMessage(audioBytes, durationSeconds)

            // Calculate self-destruct timestamp if custom duration provided
            val currentTime = System.currentTimeMillis()
            val selfDestructAt = selfDestructDurationMs?.let { currentTime + it }

            // Generate Ping ID and timestamp ONCE (never changes, prevents ghost pings)
            val pingId = generatePingId() // 24-byte nonce as hex string
            val pingTimestamp = currentTime
            Log.d(TAG, "Generated Ping ID: ${pingId.take(16)}... (timestamp: $pingTimestamp)")

            // Create message entity with VOICE type
            val message = Message(
                contactId = contactId,
                messageId = messageId,
                encryptedContent = "", // Empty for voice messages
                messageType = Message.MESSAGE_TYPE_VOICE,
                voiceDuration = durationSeconds,
                voiceFilePath = voiceFilePath,
                isSentByMe = true,
                timestamp = currentTime,
                status = Message.STATUS_PING_SENT, // Start as PING_SENT so pollForPongsAndSendMessages() can find it
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
                messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                selfDestructAt = selfDestructAt,
                requiresReadReceipt = false, // Voice messages don't need read receipts
                pingId = pingId,
                pingTimestamp = pingTimestamp,
                encryptedPayload = encryptedBase64,
                retryCount = 0,
                lastRetryTimestamp = currentTime
            )

            Log.d(TAG, "Voice message queued for persistent delivery (PING_SENT)")

            // Save to database
            Log.d(TAG, "Saving voice message to database...")
            val savedMessageId = database.messageDao().insertMessage(message)
            val savedMessage = message.copy(id = savedMessageId)

            // Notify that message is saved (allows UI to update immediately)
            onMessageSaved?.invoke(savedMessage)

            // Broadcast to MainActivity to refresh chat list preview
            val intent = android.content.Intent("com.securelegion.NEW_PING")
            intent.setPackage(context.packageName)
            intent.putExtra("CONTACT_ID", contactId)
            context.sendBroadcast(intent)
            Log.d(TAG, "Sent explicit NEW_PING broadcast to refresh MainActivity chat list")

            // Immediately attempt to send Ping
            Log.i(TAG, "Voice message queued successfully: $messageId (Ping ID: $pingId)")
            Log.d(TAG, "Attempting immediate Ping send...")

            try {
                val sendResult = sendPingForMessage(savedMessage)
                if (sendResult.isSuccess) {
                    Log.i(TAG, "Ping sent successfully, will poll for Pong later")
                } else {
                    val errorMsg = sendResult.exceptionOrNull()?.message ?: "Unknown error"
                    Log.w(TAG, "Ping send failed: $errorMsg")

                    // Immediate retry with delay if Tor is warming up
                    if (errorMsg.contains("warming up")) {
                        val delayMs = Regex("retry in (\\d+)ms").find(errorMsg)?.groupValues?.get(1)?.toLongOrNull() ?: 2000L
                        Log.i(TAG, "Scheduling immediate retry in ${delayMs}ms...")
                        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                            kotlinx.coroutines.delay(delayMs + 500)
                            try {
                                val retryResult = sendPingForMessage(savedMessage)
                                if (retryResult.isSuccess) {
                                    Log.i(TAG, "Retry Ping sent successfully after warm-up delay")
                                } else {
                                    Log.w(TAG, "Retry after warm-up still failed: ${retryResult.exceptionOrNull()?.message}")
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "Retry after warm-up threw exception: ${e.message}")
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Immediate Ping send failed, retry worker will retry: ${e.message}")
            }


            Result.success(savedMessage)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send voice message", e)
            Result.failure(e)
        }
    }

    /**
     * Send an image message to a contact via Tor
     * @param contactId Database ID of the recipient contact
     * @param imageBase64 The compressed image as Base64 string
     * @param selfDestructDurationMs Custom self-destruct duration in milliseconds (null = disabled)
     * @param onMessageSaved Callback when message is saved to DB (before sending)
     * @return Result with Message entity if successful
     */
    suspend fun sendImageMessage(
        contactId: Long,
        imageBase64: String,
        selfDestructDurationMs: Long? = null,
        onMessageSaved: ((Message) -> Unit)? = null
    ): Result<Message> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Sending image message to contact ID: $contactId (${imageBase64.length} Base64 chars)")

            // Get database instance
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Get contact details
            val contact = database.contactDao().getContactById(contactId)
                ?: return@withContext Result.failure(Exception("Contact not found"))

            Log.d(TAG, "Sending image to: ${contact.displayName} (${contact.torOnionAddress})")

            // Get our keypair for signing (needed for messageId determinism)
            val ourPublicKey = keyManager.getSigningPublicKey()
            val ourPrivateKey = keyManager.getSigningKeyBytes()
            val ourPublicKeyBase64 = android.util.Base64.encodeToString(ourPublicKey, android.util.Base64.NO_WRAP)

            // PHASE 1.1: STABLE IDENTITY
            // Generate message nonce ONCE (never regenerated on retry)
            val messageNonce = generateMessageNonce()

            // Generate STABLE messageId for image message
            // Use the original image Base64 for hashing (before encryption)
            val messageId = generateDeterministicMessageId(
                plaintext = imageBase64,
                senderEd25519Base64 = ourPublicKeyBase64,
                recipientEd25519Base64 = contact.publicKeyBase64,
                messageNonce = messageNonce
            )
            Log.d(TAG, "Generated deterministic messageId for image: $messageId (from nonce: $messageNonce)")

            // Get key chain for this contact (for progressive ephemeral key evolution)
            Log.d(TAG, "Encrypting image message with key evolution...")
            val imageBytes = Base64.decode(imageBase64, Base64.NO_WRAP)
            Log.d(TAG, "Image bytes: ${imageBytes.size} bytes")

            val keyChain = KeyChainManager.getKeyChain(context, contactId)
                ?: throw Exception("Key chain not found for contact ${contact.displayName} (ID: $contactId)")

            // NEW: Prepend message type INSIDE plaintext BEFORE encryption
            // IMAGE format: [0x02][imageBytes...]
            val plaintextWithType = byteArrayOf(0x02) + imageBytes
            val plaintextForEncryption = String(plaintextWithType, Charsets.ISO_8859_1)
            Log.d(TAG, "Plaintext with type: ${plaintextWithType.size} bytes (type=0x02 IMAGE)")

            // Encrypt using current send chain key and counter (ATOMIC key evolution)
            // Wire format: [version:1][sequence:8][nonce:24][ciphertext][tag:16]
            val result = RustBridge.encryptMessageWithEvolution(
                plaintextForEncryption,
                keyChain.sendChainKeyBytes,
                keyChain.sendCounter
            )
            val encryptedBytes = result.ciphertext
            Log.d(TAG, "Encrypted: ${encryptedBytes.size} bytes (sequence ${keyChain.sendCounter})")

            // Save evolved key to database (key evolution happened atomically in Rust)
            database.contactKeyChainDao().updateSendChainKey(
                contactId = contactId,
                newSendChainKeyBase64 = android.util.Base64.encodeToString(result.evolvedChainKey, android.util.Base64.NO_WRAP),
                newSendCounter = keyChain.sendCounter + 1,
                timestamp = System.currentTimeMillis()
            )

            // Get our X25519 public key for sender identification
            val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

            // Wire format: [X25519:32][version:1][sequence:8][nonce:24][ciphertext][tag:16]
            // NOTE: Wire protocol type byte (0x09) is added by android.rs sendPing()
            val encryptedWithMetadata = ourX25519PublicKey + encryptedBytes
            Log.d(TAG, "Total with metadata: ${encryptedWithMetadata.size} bytes (X25519 + encrypted)")

            val encryptedBase64 = Base64.encodeToString(encryptedWithMetadata, Base64.NO_WRAP)

            Log.d(TAG, "Total payload: ${encryptedBytes.size} bytes (${encryptedBase64.length} Base64 chars)")

            // Extract nonce from wire format (bytes 9-32, after version and sequence)
            val nonce = encryptedBytes.sliceArray(9 until 33)
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // Sign the message
            Log.d(TAG, "Signing image message...")
            val messageData = (messageId + System.currentTimeMillis()).toByteArray()
            val signature = RustBridge.signData(messageData, ourPrivateKey)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            // Calculate self-destruct timestamp if custom duration provided
            val currentTime = System.currentTimeMillis()
            val selfDestructAt = selfDestructDurationMs?.let { currentTime + it }

            // Generate Ping ID for persistent messaging
            val pingId = generatePingId() // 24-byte nonce as hex string
            val pingTimestamp = currentTime
            Log.d(TAG, "Generated Ping ID: $pingId")

            // Create message entity with IMAGE type
            val message = Message(
                contactId = contactId,
                messageId = messageId,
                encryptedContent = "", // Empty for image messages
                messageType = Message.MESSAGE_TYPE_IMAGE,
                attachmentType = "image",
                attachmentData = imageBase64, // Store original for display
                isSentByMe = true,
                timestamp = currentTime,
                status = Message.STATUS_PING_SENT, // Start as PING_SENT so pollForPongsAndSendMessages() can find it
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
                messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                selfDestructAt = selfDestructAt,
                requiresReadReceipt = false, // Image messages don't need read receipts
                pingId = pingId,
                pingTimestamp = pingTimestamp,
                encryptedPayload = encryptedBase64,
                retryCount = 0,
                lastRetryTimestamp = currentTime
            )

            Log.d(TAG, "Image message queued for persistent delivery (PING_SENT)")

            // Save to database
            Log.d(TAG, "Saving image message to database...")
            val savedMessageId = database.messageDao().insertMessage(message)
            val savedMessage = message.copy(id = savedMessageId)

            // Notify that message is saved (allows UI to update immediately)
            onMessageSaved?.invoke(savedMessage)

            // Broadcast to MainActivity to refresh chat list preview
            val intent = android.content.Intent("com.securelegion.NEW_PING")
            intent.setPackage(context.packageName)
            intent.putExtra("CONTACT_ID", contactId)
            context.sendBroadcast(intent)
            Log.d(TAG, "Sent explicit NEW_PING broadcast to refresh MainActivity chat list")

            // Immediately attempt to send Ping
            Log.i(TAG, "Image message queued successfully: $messageId (Ping ID: $pingId)")
            Log.d(TAG, "Attempting immediate Ping send...")

            try {
                val sendResult = sendPingForMessage(savedMessage)
                if (sendResult.isSuccess) {
                    Log.i(TAG, "Ping sent successfully, will poll for Pong later")
                } else {
                    val errorMsg = sendResult.exceptionOrNull()?.message ?: "Unknown error"
                    Log.w(TAG, "Ping send failed: $errorMsg")

                    // Immediate retry with delay if Tor is warming up
                    if (errorMsg.contains("warming up")) {
                        val delayMs = Regex("retry in (\\d+)ms").find(errorMsg)?.groupValues?.get(1)?.toLongOrNull() ?: 2000L
                        Log.i(TAG, "Scheduling immediate retry in ${delayMs}ms...")
                        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                            kotlinx.coroutines.delay(delayMs + 500)
                            try {
                                val retryResult = sendPingForMessage(savedMessage)
                                if (retryResult.isSuccess) {
                                    Log.i(TAG, "Retry Ping sent successfully after warm-up delay")
                                } else {
                                    Log.w(TAG, "Retry after warm-up still failed: ${retryResult.exceptionOrNull()?.message}")
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "Retry after warm-up threw exception: ${e.message}")
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Immediate Ping send failed, retry worker will retry: ${e.message}")
            }


            Result.success(savedMessage)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send image message", e)
            Result.failure(e)
        }
    }

    /**
     * Send a profile photo update to a single contact via Tor
     * Sends directly via RustBridge without saving to messages table (zero trace).
     * @param contactId Database ID of the recipient contact
     * @param photoBase64 Base64-encoded profile photo (empty string = removal)
     * @return Result with Unit if successful
     */
    suspend fun sendProfileUpdate(
        contactId: Long,
        photoBase64: String
    ): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Sending profile update to contact ID: $contactId (${photoBase64.length} Base64 chars)")

            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            val contact = database.contactDao().getContactById(contactId)
                ?: return@withContext Result.failure(Exception("Contact not found"))

            Log.d(TAG, "Sending profile update to: ${contact.displayName}")

            val keyChain = KeyChainManager.getKeyChain(context, contactId)
                ?: throw Exception("Key chain not found for contact ${contact.displayName}")

            // PROFILE_UPDATE format: [0x0F][photoBytes...] (empty body = removal)
            val photoBytes = if (photoBase64.isNotBlank()) {
                Base64.decode(photoBase64, Base64.NO_WRAP)
            } else {
                ByteArray(0) // Empty = photo removal
            }
            val plaintextWithType = byteArrayOf(0x0F) + photoBytes
            val plaintextForEncryption = String(plaintextWithType, Charsets.ISO_8859_1)

            // Encrypt with key chain evolution (CRITICAL: must evolve key for future messages)
            val encryptResult = RustBridge.encryptMessageWithEvolution(
                plaintextForEncryption,
                keyChain.sendChainKeyBytes,
                keyChain.sendCounter
            )
            val encryptedBytes = encryptResult.ciphertext

            // Persist evolved send chain key
            database.contactKeyChainDao().updateSendChainKey(
                contactId = contactId,
                newSendChainKeyBase64 = android.util.Base64.encodeToString(encryptResult.evolvedChainKey, android.util.Base64.NO_WRAP),
                newSendCounter = keyChain.sendCounter + 1,
                timestamp = System.currentTimeMillis()
            )
            Log.d(TAG, "Send chain key evolved: counter ${keyChain.sendCounter} → ${keyChain.sendCounter + 1}")

            // Get recipient keys for Ping
            val recipientEd25519PubKey = Base64.decode(contact.publicKeyBase64, Base64.NO_WRAP)
            val recipientX25519PubKey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)
            val onionAddress = contact.messagingOnion ?: contact.torOnionAddress ?: ""

            // Generate ping ID for this send
            val pingId = generatePingId()
            val pingTimestamp = System.currentTimeMillis()

            // Send directly via Rust bridge — NO message saved to DB (zero trace)
            val pingResponse = RustBridge.sendPing(
                recipientEd25519PubKey,
                recipientX25519PubKey,
                onionAddress,
                encryptedBytes,
                0x0F.toByte(), // PROFILE_UPDATE wire byte
                pingId,
                pingTimestamp
            )

            if (pingResponse != null) {
                Log.i(TAG, "Profile update sent to ${contact.displayName} (ping: ${pingId.take(8)}...)")
            } else {
                Log.w(TAG, "Profile update ping returned null for ${contact.displayName}")
            }

            Result.success(Unit)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e // Don't swallow cancellation — rethrow for structured concurrency
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send profile update to contact $contactId", e)
            Result.failure(e)
        }
    }

    /**
     * Broadcast a profile photo update to ALL contacts
     * Sends the photo through the encrypted Tor pipeline to each contact.
     * @param photoBase64 Base64-encoded profile photo (empty string = removal)
     */
    suspend fun broadcastProfileUpdate(photoBase64: String) = withContext(Dispatchers.IO) {
        val dbPassphrase = keyManager.getDatabasePassphrase()
        val database = SecureLegionDatabase.getInstance(context, dbPassphrase)
        val contacts = database.contactDao().getAllContacts()

        Log.i(TAG, "Broadcasting profile update to ${contacts.size} contacts")

        var successCount = 0
        var failCount = 0

        // Send sequentially but with a per-contact timeout so one slow SOCKS
        // connection doesn't block the entire broadcast for 36+ seconds
        contacts.forEach { contact ->
            try {
                val result = kotlinx.coroutines.withTimeoutOrNull(20_000L) {
                    sendProfileUpdate(contact.id, photoBase64)
                }
                if (result != null && result.isSuccess) {
                    successCount++
                } else {
                    failCount++
                    if (result == null) {
                        Log.w(TAG, "Profile update timed out for ${contact.displayName}")
                    } else {
                        Log.w(TAG, "Profile update failed for ${contact.displayName}: ${result.exceptionOrNull()?.message}")
                    }
                }
            } catch (e: Exception) {
                failCount++
                Log.e(TAG, "Profile update error for ${contact.displayName}", e)
            }
        }

        Log.i(TAG, "Profile update broadcast complete: $successCount succeeded, $failCount failed")
    }

    /**
     * Send an encrypted message to a contact via Tor
     * @param contactId Database ID of the recipient contact
     * @param plaintext The message content
     * @param selfDestructDurationMs Custom self-destruct duration in milliseconds (null = disabled)
     * @param enableReadReceipt Whether to enable read receipts
     * @param onMessageSaved Callback when message is saved to DB (before sending)
     * @return Result with Message entity if successful
     */
    suspend fun sendMessage(
        contactId: Long,
        plaintext: String,
        selfDestructDurationMs: Long? = null,
        enableReadReceipt: Boolean = true,
        correlationId: String? = null, // For stress test tracing
        onMessageSaved: ((Message) -> Unit)? = null
    ): Result<Message> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Sending message to contact ID: $contactId")

            // Get database instance
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Get contact details
            val contact = database.contactDao().getContactById(contactId)
                ?: return@withContext Result.failure(Exception("Contact not found"))

            Log.d(TAG, "Sending to: ${contact.displayName} (${contact.torOnionAddress})")

            // Get our keypair for signing (needed for messageId determinism)
            val ourPublicKey = keyManager.getSigningPublicKey()
            val ourPrivateKey = keyManager.getSigningKeyBytes()
            val ourPublicKeyBase64 = android.util.Base64.encodeToString(ourPublicKey, android.util.Base64.NO_WRAP)

            // PHASE 1.1: STABLE IDENTITY
            // Generate message nonce ONCE (never regenerated on retry)
            // This nonce is stored in DB and reused for all retries/resends
            val messageNonce = generateMessageNonce()

            // Generate STABLE messageId using deterministic hash
            // Formula: SHA-256(v1 || conversationId || senderEd25519 || recipientEd25519 || plaintextHash || messageNonce)
            // Returns same ID if plaintext + contacts + nonce are same (guarantees dedup on retry)
            val messageId = generateDeterministicMessageId(
                plaintext = plaintext,
                senderEd25519Base64 = ourPublicKeyBase64,
                recipientEd25519Base64 = contact.publicKeyBase64,
                messageNonce = messageNonce
            )
            Log.d(TAG, "Generated deterministic messageId: $messageId (from nonce: $messageNonce)")

            // Get key chain for this contact (for progressive ephemeral key evolution)
            Log.d(TAG, "SEND KEY CHAIN LOAD: Loading key chain from database...")
            Log.d(TAG, "contactId=$contactId (${contact.displayName})")
            val keyChain = KeyChainManager.getKeyChain(context, contactId)
                ?: throw Exception("Key chain not found for contact ${contact.displayName} (ID: $contactId)")
            Log.d(TAG, "SEND KEY CHAIN LOAD: Loaded from database successfully")
            Log.d(TAG, "sendCounter=${keyChain.sendCounter} <- will use this for encryption")
            Log.d(TAG, "receiveCounter=${keyChain.receiveCounter}")

            // ATOMIC ENCRYPTION + KEY EVOLUTION
            // Encrypts and evolves key in one indivisible operation to prevent desync
            // Wire format: [version:1][sequence:8][nonce:24][ciphertext][tag:16]
            // NEW: Prepend message type byte INSIDE plaintext before encryption
            // TEXT format: [0x00][utf8 text bytes...]
            val plaintextWithType = byteArrayOf(0x00) + plaintext.toByteArray(Charsets.UTF_8)
            val plaintextForEncryption = String(plaintextWithType, Charsets.ISO_8859_1)
            Log.d(TAG, "SEND KEY EVOLUTION: About to encrypt and evolve send chain key")
            Log.d(TAG, "contactId=$contactId (${contact.displayName})")
            Log.d(TAG, "Current sendCounter=${keyChain.sendCounter}")
            Log.d(TAG, "Will encrypt with sequence ${keyChain.sendCounter}")
            Log.d(TAG, "Plaintext with type prefix: ${plaintextWithType.size} bytes (type=0x00 TEXT)")
            val result = RustBridge.encryptMessageWithEvolution(
                plaintextForEncryption,
                keyChain.sendChainKeyBytes,
                keyChain.sendCounter
            )
            val encryptedBytes = result.ciphertext
            Log.d(TAG, "SEND KEY EVOLUTION: Encryption complete, encrypted ${encryptedBytes.size} bytes")

            // Save evolved key to database (key evolution happened atomically in Rust)
            Log.d(TAG, "SEND KEY EVOLUTION: Updating database with new sendCounter=${keyChain.sendCounter + 1}")
            database.contactKeyChainDao().updateSendChainKey(
                contactId = contactId,
                newSendChainKeyBase64 = android.util.Base64.encodeToString(result.evolvedChainKey, android.util.Base64.NO_WRAP),
                newSendCounter = keyChain.sendCounter + 1,
                timestamp = System.currentTimeMillis()
            )
            // VERIFY the update actually persisted
            val verifyKeyChain = database.contactKeyChainDao().getKeyChainByContactId(contactId)
            Log.d(TAG, "SEND VERIFICATION: After update, database shows sendCounter=${verifyKeyChain?.sendCounter}")
            if (verifyKeyChain?.sendCounter != keyChain.sendCounter + 1) {
                Log.e(TAG, "SEND ERROR: Counter update did NOT persist! Expected ${keyChain.sendCounter + 1}, got ${verifyKeyChain?.sendCounter}")
            } else {
                Log.d(TAG, "SEND: Counter update verified successfully")
            }
            Log.d(TAG, "Message encrypted with sequence ${keyChain.sendCounter}")

            // FIX: Do NOT prepend pubkey here - android.rs sendMessageBlob() already does it
            // Old buggy code: val encryptedWithMetadata = ourX25519PublicKey + encryptedBytes
            // Correct: Just use encryptedBytes directly (pubkey will be added by Rust layer)
            val encryptedBase64 = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)

            // Extract nonce from wire format (bytes 9-32, after version and sequence)
            val nonce = encryptedBytes.sliceArray(9 until 33)
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // Sign the message
            Log.d(TAG, "Signing message...")
            val messageData = (messageId + plaintext + System.currentTimeMillis()).toByteArray()
            val signature = RustBridge.signData(messageData, ourPrivateKey)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            // Calculate self-destruct timestamp if custom duration provided
            val currentTime = System.currentTimeMillis()
            val selfDestructAt = selfDestructDurationMs?.let { currentTime + it }

            // Generate Ping ID and timestamp ONCE (never changes, prevents ghost pings)
            val pingId = generatePingId() // 24-byte nonce as hex string
            val pingTimestamp = currentTime
            Log.d(TAG, "Generated Ping ID: ${pingId.take(16)}... (timestamp: $pingTimestamp)")

            // Create message entity with PING_SENT status for persistent queue
            val message = Message(
                contactId = contactId,
                messageId = messageId,
                encryptedContent = plaintext, // Store plaintext for now (will encrypt in future)
                isSentByMe = true,
                timestamp = currentTime,
                status = Message.STATUS_PING_SENT, // Start as PING_SENT so pollForPongsAndSendMessages() can find it
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
                messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                selfDestructAt = selfDestructAt,
                requiresReadReceipt = enableReadReceipt,
                pingId = pingId, // Generated ONCE, used for all retries
                pingTimestamp = pingTimestamp, // Generated ONCE with pingId
                encryptedPayload = encryptedBase64, // Store encrypted payload to send after Pong
                retryCount = 0, // Initialize retry counter
                lastRetryTimestamp = currentTime, // Track when we last attempted
                correlationId = correlationId // For stress test tracing (null for normal messages)
            )

            val durationText = selfDestructDurationMs?.let { duration ->
                when {
                    duration < 60000 -> "${duration / 1000}s"
                    duration < 3600000 -> "${duration / 60000}min"
                    else -> "${duration / 3600000}h"
                }
            } ?: "disabled"
            Log.d(TAG, "Self-destruct: $durationText")
            Log.d(TAG, "Read receipt: ${if (enableReadReceipt) "enabled" else "disabled"}")
            Log.d(TAG, "Message queued for persistent delivery (PING_SENT)")

            // Save to database
            Log.d(TAG, "Saving message to database...")
            val savedMessageId = database.messageDao().insertMessage(message)
            val savedMessage = message.copy(id = savedMessageId)

            // Notify that message is saved (allows UI to update immediately)
            onMessageSaved?.invoke(savedMessage)

            // Broadcast to MainActivity to refresh chat list preview (explicit broadcast)
            val intent = android.content.Intent("com.securelegion.NEW_PING")
            intent.setPackage(context.packageName) // Make it explicit
            intent.putExtra("CONTACT_ID", contactId)
            context.sendBroadcast(intent)
            Log.d(TAG, "Sent explicit NEW_PING broadcast to refresh MainActivity chat list")

            // Immediately attempt to send Ping (but don't wait for Pong)
            // This provides instant send attempt for online recipients
            // Retry worker will handle retries and Pong polling
            Log.i(TAG, "Message queued successfully: $messageId (Ping ID: $pingId)")
            Log.d(TAG, "Attempting immediate Ping send...")

            try {
                val sendResult = sendPingForMessage(savedMessage)
                if (sendResult.isSuccess) {
                    Log.i(TAG, "Ping sent successfully, will poll for Pong later")
                } else {
                    val errorMsg = sendResult.exceptionOrNull()?.message ?: "Unknown error"
                    Log.w(TAG, "Ping send failed: $errorMsg")

                    // Immediate retry with delay if Tor is warming up (don't wait for 15-min worker)
                    if (errorMsg.contains("warming up")) {
                        val delayMs = Regex("retry in (\\d+)ms").find(errorMsg)?.groupValues?.get(1)?.toLongOrNull() ?: 2000L
                        Log.i(TAG, "Scheduling immediate retry in ${delayMs}ms...")
                        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                            kotlinx.coroutines.delay(delayMs + 500) // Add 500ms buffer
                            try {
                                val retryResult = sendPingForMessage(savedMessage)
                                if (retryResult.isSuccess) {
                                    Log.i(TAG, "Retry Ping sent successfully after warm-up delay")
                                } else {
                                    Log.w(TAG, "Retry after warm-up still failed: ${retryResult.exceptionOrNull()?.message}")
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "Retry after warm-up threw exception: ${e.message}")
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                // Silent failure - retry worker will handle it
                Log.w(TAG, "Immediate Ping send failed, retry worker will retry: ${e.message}")
            }


            Result.success(savedMessage)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send message", e)
            Result.failure(e)
        }
    }

    /**
     * Send a payment request message (NLx402 quote) to a contact via Tor
     * @param contactId Database ID of the recipient contact
     * @param quote The NLx402 payment quote
     * @param onMessageSaved Callback when message is saved to DB (before sending)
     * @return Result with Message entity if successful
     */
    suspend fun sendPaymentRequest(
        contactId: Long,
        quote: NLx402Manager.PaymentQuote,
        onMessageSaved: ((Message) -> Unit)? = null
    ): Result<Message> = withContext(Dispatchers.IO) {
        try {
            Log.i(TAG, "")
            Log.i(TAG, "MessageService.sendPaymentRequest()")
            Log.i(TAG, "Contact ID: $contactId")
            Log.i(TAG, "Quote ID: ${quote.quoteId}")
            Log.i(TAG, "Amount: ${quote.formattedAmount}")
            Log.i(TAG, "")

            // Get database instance
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Get contact details
            val contact = database.contactDao().getContactById(contactId)
                ?: return@withContext Result.failure(Exception("Contact not found"))

            Log.d(TAG, "Sending payment request to: ${contact.displayName} (${contact.torOnionAddress})")

            // Generate unique message ID using quote ID
            val messageId = "pay_req_${quote.quoteId}"

            // Get our keypair for signing
            val ourPrivateKey = keyManager.getSigningKeyBytes()

            // Create the payment request payload (JSON with quote)
            val paymentRequestPayload = """{"type":"PAYMENT_REQUEST","quote":${quote.rawJson}}"""

            // Get key chain for this contact (for progressive ephemeral key evolution)
            Log.d(TAG, "SEND KEY CHAIN LOAD: Loading key chain from database...")
            Log.d(TAG, "contactId=$contactId (${contact.displayName})")
            val keyChain = KeyChainManager.getKeyChain(context, contactId)
                ?: throw Exception("Key chain not found for contact ${contact.displayName} (ID: $contactId)")
            Log.d(TAG, "SEND KEY CHAIN LOAD: Loaded from database successfully")
            Log.d(TAG, "sendCounter=${keyChain.sendCounter} <- will use this for encryption")

            // NEW: Prepend message type INSIDE plaintext BEFORE encryption
            // PAYMENT_REQUEST format: [0x0A][jsonBytes...]
            val plaintextWithType = byteArrayOf(0x0A) + paymentRequestPayload.toByteArray(Charsets.UTF_8)
            val plaintextForEncryption = String(plaintextWithType, Charsets.ISO_8859_1)
            Log.d(TAG, "Plaintext with type: ${plaintextWithType.size} bytes (type=0x0A PAYMENT_REQUEST)")

            // ATOMIC ENCRYPTION + KEY EVOLUTION
            // Encrypts and evolves key in one indivisible operation to prevent desync
            // Wire format: [version:1][sequence:8][nonce:24][ciphertext][tag:16]
            Log.d(TAG, "SEND KEY EVOLUTION: About to encrypt and evolve send chain key")
            Log.d(TAG, "contactId=$contactId (${contact.displayName})")
            Log.d(TAG, "Current sendCounter=${keyChain.sendCounter}")
            Log.d(TAG, "Will encrypt with sequence ${keyChain.sendCounter}")
            val result = RustBridge.encryptMessageWithEvolution(
                plaintextForEncryption,
                keyChain.sendChainKeyBytes,
                keyChain.sendCounter
            )
            val encryptedBytes = result.ciphertext
            Log.d(TAG, "SEND KEY EVOLUTION: Encryption complete, encrypted ${encryptedBytes.size} bytes")

            // Save evolved key to database (key evolution happened atomically in Rust)
            Log.d(TAG, "SEND KEY EVOLUTION: Updating database with new sendCounter=${keyChain.sendCounter + 1}")
            database.contactKeyChainDao().updateSendChainKey(
                contactId = contactId,
                newSendChainKeyBase64 = android.util.Base64.encodeToString(result.evolvedChainKey, android.util.Base64.NO_WRAP),
                newSendCounter = keyChain.sendCounter + 1,
                timestamp = System.currentTimeMillis()
            )
            // VERIFY the update actually persisted
            val verifyKeyChain = database.contactKeyChainDao().getKeyChainByContactId(contactId)
            Log.d(TAG, "SEND VERIFICATION: After update, database shows sendCounter=${verifyKeyChain?.sendCounter}")
            if (verifyKeyChain?.sendCounter != keyChain.sendCounter + 1) {
                Log.e(TAG, "SEND ERROR: Counter update did NOT persist! Expected ${keyChain.sendCounter + 1}, got ${verifyKeyChain?.sendCounter}")
            } else {
                Log.d(TAG, "SEND: Counter update verified successfully")
            }
            Log.d(TAG, "Payment request encrypted with sequence ${keyChain.sendCounter}")

            // Get our X25519 public key for sender identification
            val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

            // Wire format: [X25519:32][version:1][sequence:8][nonce:24][ciphertext][tag:16]
            // NOTE: Wire protocol type byte (0x0A) is added by android.rs sendPing()
            val encryptedWithMetadata = ourX25519PublicKey + encryptedBytes
            Log.d(TAG, "Total with metadata: ${encryptedWithMetadata.size} bytes (X25519 + encrypted)")

            val encryptedBase64 = Base64.encodeToString(encryptedWithMetadata, Base64.NO_WRAP)

            // Extract nonce from wire format (bytes 9-32, after version and sequence)
            val nonce = encryptedBytes.sliceArray(9 until 33)
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // Sign the message
            Log.d(TAG, "Signing payment request...")
            val messageData = (messageId + quote.rawJson + System.currentTimeMillis()).toByteArray()
            val signature = RustBridge.signData(messageData, ourPrivateKey)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            val currentTime = System.currentTimeMillis()

            // Generate Ping ID for persistent messaging
            val pingId = generatePingId() // 24-byte nonce as hex string
            val pingTimestamp = currentTime
            Log.d(TAG, "Generated Ping ID for payment request: $pingId")

            // PHASE 1.1: STABLE IDENTITY
            // Generate message nonce ONCE (never regenerated on retry)
            // For payment messages, messageId is stable (pay_req_${quoteId}), but we still need nonce for retries
            val messageNonce = generateMessageNonce()

            // Create message entity with PAYMENT_REQUEST type
            val message = Message(
                contactId = contactId,
                messageId = messageId,
                encryptedContent = "Payment Request: ${quote.formattedAmount}", // Display text
                messageType = Message.MESSAGE_TYPE_PAYMENT_REQUEST,
                isSentByMe = true,
                timestamp = currentTime,
                status = Message.STATUS_PING_SENT, // Start as PING_SENT so pollForPongsAndSendMessages() can find it
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
                messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                pingId = pingId,
                pingTimestamp = pingTimestamp,
                encryptedPayload = encryptedBase64,
                retryCount = 0,
                lastRetryTimestamp = currentTime,
                // Payment-specific fields
                paymentQuoteJson = quote.rawJson,
                paymentStatus = Message.PAYMENT_STATUS_PENDING,
                paymentToken = quote.token,
                paymentAmount = quote.amount
            )

            Log.d(TAG, "Payment request queued for persistent delivery (PING_SENT)")

            // Save to database
            Log.d(TAG, "Saving payment request to database...")
            val savedMessageId = database.messageDao().insertMessage(message)
            val savedMessage = message.copy(id = savedMessageId)

            // Notify that message is saved (allows UI to update immediately)
            onMessageSaved?.invoke(savedMessage)

            // Broadcast to ChatActivity to refresh messages (so payment request shows immediately)
            val chatIntent = android.content.Intent("com.securelegion.MESSAGE_RECEIVED")
            chatIntent.setPackage(context.packageName)
            chatIntent.putExtra("CONTACT_ID", contactId)
            context.sendBroadcast(chatIntent)
            Log.d(TAG, "Sent explicit MESSAGE_RECEIVED broadcast to refresh ChatActivity")

            // Broadcast to MainActivity to refresh chat list preview
            val intent = android.content.Intent("com.securelegion.NEW_PING")
            intent.setPackage(context.packageName)
            intent.putExtra("CONTACT_ID", contactId)
            context.sendBroadcast(intent)
            Log.d(TAG, "Sent explicit NEW_PING broadcast to refresh MainActivity chat list")

            // Immediately attempt to send Ping
            Log.i(TAG, "Payment request queued successfully: $messageId (Ping ID: $pingId)")
            Log.d(TAG, "Attempting immediate Ping send...")

            try {
                val sendResult = sendPingForMessage(savedMessage)
                if (sendResult.isSuccess) {
                    Log.i(TAG, "Ping sent successfully, will poll for Pong later")
                } else {
                    val errorMsg = sendResult.exceptionOrNull()?.message ?: "Unknown error"
                    Log.w(TAG, "Ping send failed: $errorMsg")

                    // Immediate retry with delay if Tor is warming up
                    if (errorMsg.contains("warming up")) {
                        val delayMs = Regex("retry in (\\d+)ms").find(errorMsg)?.groupValues?.get(1)?.toLongOrNull() ?: 2000L
                        Log.i(TAG, "Scheduling immediate retry in ${delayMs}ms...")
                        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
                            kotlinx.coroutines.delay(delayMs + 500)
                            try {
                                val retryResult = sendPingForMessage(savedMessage)
                                if (retryResult.isSuccess) {
                                    Log.i(TAG, "Retry Ping sent successfully after warm-up delay")
                                } else {
                                    Log.w(TAG, "Retry after warm-up still failed: ${retryResult.exceptionOrNull()?.message}")
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "Retry after warm-up threw exception: ${e.message}")
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Immediate Ping send failed, retry worker will retry: ${e.message}")
            }

            // Schedule fast retry worker for this message (5s intervals)
            Log.d(TAG, "Scheduled immediate retry worker for payment request $messageId")

            Result.success(savedMessage)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send payment request", e)
            Result.failure(e)
        }
    }

    /**
     * Send a payment confirmation message (after paying someone's request)
     * @param contactId Database ID of the recipient contact
     * @param originalQuote The original payment quote that was paid
     * @param txSignature The transaction signature
     * @param onMessageSaved Callback when message is saved to DB (before sending)
     * @return Result with Message entity if successful
     */
    suspend fun sendPaymentConfirmation(
        contactId: Long,
        originalQuote: NLx402Manager.PaymentQuote,
        txSignature: String,
        onMessageSaved: ((Message) -> Unit)? = null
    ): Result<Message> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Sending payment confirmation to contact ID: $contactId")
            Log.d(TAG, "Paid quote: ${originalQuote.quoteId} (${originalQuote.formattedAmount})")
            Log.d(TAG, "TX: $txSignature")

            // Get database instance
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Get contact details
            val contact = database.contactDao().getContactById(contactId)
                ?: return@withContext Result.failure(Exception("Contact not found"))

            Log.d(TAG, "Sending payment confirmation to: ${contact.displayName}")

            // Generate unique message ID using quote ID and tx signature
            val messageId = "pay_sent_${originalQuote.quoteId}_${txSignature.take(8)}"

            // Get our keypair for signing
            val ourPrivateKey = keyManager.getSigningKeyBytes()

            // Create the payment confirmation payload
            val paymentConfirmPayload = """{"type":"PAYMENT_SENT","quote_id":"${originalQuote.quoteId}","tx_signature":"$txSignature","amount":${originalQuote.amount},"token":"${originalQuote.token}"}"""

            // Get key chain for this contact
            Log.d(TAG, "SEND KEY CHAIN LOAD: Loading key chain from database for payment confirmation...")
            Log.d(TAG, "contactId=$contactId (${contact.displayName})")
            val keyChain = KeyChainManager.getKeyChain(context, contactId)
                ?: throw Exception("Key chain not found for contact ${contact.displayName}")
            Log.d(TAG, "sendCounter=${keyChain.sendCounter}")

            // NEW: Prepend message type INSIDE plaintext BEFORE encryption
            // PAYMENT_SENT format: [0x0B][jsonBytes...]
            val plaintextWithType = byteArrayOf(0x0B) + paymentConfirmPayload.toByteArray(Charsets.UTF_8)
            val plaintextForEncryption = String(plaintextWithType, Charsets.ISO_8859_1)
            Log.d(TAG, "Plaintext with type: ${plaintextWithType.size} bytes (type=0x0B PAYMENT_SENT)")

            // ATOMIC ENCRYPTION + KEY EVOLUTION
            Log.d(TAG, "SEND KEY EVOLUTION: Encrypting payment confirmation with sequence ${keyChain.sendCounter}")
            val result = RustBridge.encryptMessageWithEvolution(
                plaintextForEncryption,
                keyChain.sendChainKeyBytes,
                keyChain.sendCounter
            )
            val encryptedBytes = result.ciphertext
            Log.d(TAG, "SEND KEY EVOLUTION: Payment confirmation encrypted: ${encryptedBytes.size} bytes")

            // Save evolved key to database
            database.contactKeyChainDao().updateSendChainKey(
                contactId = contactId,
                newSendChainKeyBase64 = android.util.Base64.encodeToString(result.evolvedChainKey, android.util.Base64.NO_WRAP),
                newSendCounter = keyChain.sendCounter + 1,
                timestamp = System.currentTimeMillis()
            )
            Log.d(TAG, "SEND: Updated sendCounter to ${keyChain.sendCounter + 1}")

            // Get our X25519 public key for sender identification
            val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

            // Wire format: [X25519:32][version:1][sequence:8][nonce:24][ciphertext][tag:16]
            // NOTE: Wire protocol type byte (0x0B) is added by android.rs sendPing()
            val encryptedWithMetadata = ourX25519PublicKey + encryptedBytes
            val encryptedBase64 = Base64.encodeToString(encryptedWithMetadata, Base64.NO_WRAP)

            // Extract nonce from wire format (bytes 9-32, after version and sequence)
            val nonce = encryptedBytes.sliceArray(9 until 33)
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // Sign the message
            val messageData = (messageId + txSignature + System.currentTimeMillis()).toByteArray()
            val signature = RustBridge.signData(messageData, ourPrivateKey)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            val currentTime = System.currentTimeMillis()
            val pingId = generatePingId() // 24-byte nonce as hex string
            val pingTimestamp = currentTime

            // PHASE 1.1: STABLE IDENTITY
            // Generate message nonce ONCE (never regenerated on retry)
            val messageNonce = generateMessageNonce()

            // Create message entity with PAYMENT_SENT type
            val message = Message(
                contactId = contactId,
                messageId = messageId,
                encryptedContent = "Paid: ${originalQuote.formattedAmount}", // Display text
                messageType = Message.MESSAGE_TYPE_PAYMENT_SENT,
                isSentByMe = true,
                timestamp = currentTime,
                status = Message.STATUS_PING_SENT, // Start as PING_SENT so pollForPongsAndSendMessages() can find it
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
                messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                pingId = pingId,
                pingTimestamp = pingTimestamp,
                encryptedPayload = encryptedBase64,
                retryCount = 0,
                lastRetryTimestamp = currentTime,
                // Payment-specific fields
                paymentQuoteJson = originalQuote.rawJson,
                paymentStatus = Message.PAYMENT_STATUS_PAID,
                paymentToken = originalQuote.token,
                paymentAmount = originalQuote.amount,
                txSignature = txSignature
            )

            // Save to database
            val savedMessageId = database.messageDao().insertMessage(message)
            val savedMessage = message.copy(id = savedMessageId)

            // Notify that message is saved
            onMessageSaved?.invoke(savedMessage)

            // Broadcast to ChatActivity to refresh messages
            val chatIntent = android.content.Intent("com.securelegion.MESSAGE_RECEIVED")
            chatIntent.setPackage(context.packageName)
            chatIntent.putExtra("CONTACT_ID", contactId)
            context.sendBroadcast(chatIntent)
            Log.d(TAG, "Sent MESSAGE_RECEIVED broadcast for payment confirmation")

            // Broadcast to MainActivity
            val intent = android.content.Intent("com.securelegion.NEW_PING")
            intent.setPackage(context.packageName)
            intent.putExtra("CONTACT_ID", contactId)
            context.sendBroadcast(intent)

            // Attempt to send Ping
            try {
                sendPingForMessage(savedMessage)
            } catch (e: Exception) {
                Log.w(TAG, "Immediate Ping send failed for payment confirmation: ${e.message}")
            }

            // Schedule retry worker

            Log.i(TAG, "Payment confirmation sent: $messageId")
            Result.success(savedMessage)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send payment confirmation", e)
            Result.failure(e)
        }
    }

    /**
     * Send a payment acceptance message
     * When someone sends you money, you accept by providing your receive address
     * This triggers the sender's app to execute the blockchain transfer
     */
    suspend fun sendPaymentAcceptance(
        contactId: Long,
        originalQuote: NLx402Manager.PaymentQuote,
        receiveAddress: String,
        onMessageSaved: ((Message) -> Unit)? = null
    ): Result<Message> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Sending payment acceptance to contact ID: $contactId")
            Log.d(TAG, "Quote: ${originalQuote.quoteId}, receive to: $receiveAddress")

            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            val contact = database.contactDao().getContactById(contactId)
                ?: return@withContext Result.failure(Exception("Contact not found"))

            Log.d(TAG, "Sending payment acceptance to: ${contact.displayName}")

            // PHASE 1.1: STABLE IDENTITY
            // Generate message nonce ONCE (never regenerated on retry)
            val messageNonce = generateMessageNonce()

            // Fixed: Remove timestamp from messageId for determinism
            // Use only quote.quoteId + nonce to ensure same message ID across retries
            val messageId = "pay_accept_${originalQuote.quoteId}"

            val ourPrivateKey = keyManager.getSigningKeyBytes()

            // Create the payment acceptance payload with receive address
            val paymentAcceptPayload = """{"type":"PAYMENT_ACCEPTED","quote_id":"${originalQuote.quoteId}","receive_address":"$receiveAddress","amount":${originalQuote.amount},"token":"${originalQuote.token}"}"""

            // Get key chain for this contact
            Log.d(TAG, "SEND KEY CHAIN LOAD: Loading key chain from database for payment acceptance...")
            Log.d(TAG, "contactId=$contactId (${contact.displayName})")
            val keyChain = KeyChainManager.getKeyChain(context, contactId)
                ?: throw Exception("Key chain not found for contact ${contact.displayName}")
            Log.d(TAG, "sendCounter=${keyChain.sendCounter}")

            // NEW: Prepend message type INSIDE plaintext BEFORE encryption
            // PAYMENT_ACCEPTED format: [0x0C][jsonBytes...]
            val plaintextWithType = byteArrayOf(0x0C) + paymentAcceptPayload.toByteArray(Charsets.UTF_8)
            val plaintextForEncryption = String(plaintextWithType, Charsets.ISO_8859_1)
            Log.d(TAG, "Plaintext with type: ${plaintextWithType.size} bytes (type=0x0C PAYMENT_ACCEPTED)")

            // ATOMIC ENCRYPTION + KEY EVOLUTION
            Log.d(TAG, "SEND KEY EVOLUTION: Encrypting payment acceptance with sequence ${keyChain.sendCounter}")
            val result = RustBridge.encryptMessageWithEvolution(
                plaintextForEncryption,
                keyChain.sendChainKeyBytes,
                keyChain.sendCounter
            )
            val encryptedBytes = result.ciphertext
            Log.d(TAG, "SEND KEY EVOLUTION: Payment acceptance encrypted: ${encryptedBytes.size} bytes")

            // Save evolved key to database
            database.contactKeyChainDao().updateSendChainKey(
                contactId = contactId,
                newSendChainKeyBase64 = android.util.Base64.encodeToString(result.evolvedChainKey, android.util.Base64.NO_WRAP),
                newSendCounter = keyChain.sendCounter + 1,
                timestamp = System.currentTimeMillis()
            )
            Log.d(TAG, "SEND: Updated sendCounter to ${keyChain.sendCounter + 1}")

            // Get our X25519 public key for sender identification
            val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

            // Wire format: [X25519:32][version:1][sequence:8][nonce:24][ciphertext][tag:16]
            // NOTE: Wire protocol type byte (0x0C) is added by android.rs sendPing()
            val encryptedWithMetadata = ourX25519PublicKey + encryptedBytes
            val encryptedBase64 = Base64.encodeToString(encryptedWithMetadata, Base64.NO_WRAP)

            // Extract nonce from wire format (bytes 9-32, after version and sequence)
            val nonce = encryptedBytes.sliceArray(9 until 33)
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            val messageData = (messageId + receiveAddress + System.currentTimeMillis()).toByteArray()
            val signature = RustBridge.signData(messageData, ourPrivateKey)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            val currentTime = System.currentTimeMillis()
            val pingId = generatePingId() // 24-byte nonce as hex string
            val pingTimestamp = currentTime

            val message = Message(
                contactId = contactId,
                messageId = messageId,
                encryptedContent = "Payment accepted: ${originalQuote.formattedAmount}",
                messageType = Message.MESSAGE_TYPE_PAYMENT_ACCEPTED,
                isSentByMe = true,
                timestamp = currentTime,
                status = Message.STATUS_PING_SENT, // Start as PING_SENT so pollForPongsAndSendMessages() can find it
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
                messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                pingId = pingId,
                pingTimestamp = pingTimestamp,
                encryptedPayload = encryptedBase64,
                retryCount = 0,
                lastRetryTimestamp = currentTime,
                paymentQuoteJson = originalQuote.rawJson,
                paymentToken = originalQuote.token,
                paymentAmount = originalQuote.amount,
                paymentStatus = Message.PAYMENT_STATUS_PENDING
            )

            val savedMessageId = database.messageDao().insertMessage(message)
            val savedMessage = message.copy(id = savedMessageId)

            onMessageSaved?.invoke(savedMessage)

            // Broadcast to ChatActivity to refresh messages
            val chatIntent = android.content.Intent("com.securelegion.MESSAGE_RECEIVED")
            chatIntent.setPackage(context.packageName)
            chatIntent.putExtra("CONTACT_ID", contactId)
            context.sendBroadcast(chatIntent)
            Log.d(TAG, "Sent MESSAGE_RECEIVED broadcast for payment acceptance")

            // Broadcast to MainActivity
            val intent = android.content.Intent("com.securelegion.NEW_PING")
            intent.setPackage(context.packageName)
            intent.putExtra("CONTACT_ID", contactId)
            context.sendBroadcast(intent)

            // Try immediate send via Ping
            try {
                sendPingForMessage(savedMessage)
                Log.d(TAG, "Sent Ping for payment acceptance")
            } catch (e: Exception) {
                Log.w(TAG, "Immediate Ping send failed for payment acceptance: ${e.message}")
            }


            Log.i(TAG, "Payment acceptance sent: $messageId")
            Result.success(savedMessage)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send payment acceptance", e)
            Result.failure(e)
        }
    }

    /**
     * Receive and decrypt an incoming message
     * @param encryptedData The encrypted message data
     * @param senderPublicKey The sender's public key
     * @param senderOnionAddress The sender's .onion address
     * @param messageType Message type ("TEXT" or "VOICE")
     * @param voiceDuration Duration in seconds (for voice messages)
     * @param selfDestructAt Self-destruct timestamp (or null)
     * @param requiresReadReceipt Whether sender wants read receipt
     * @return Result with Message entity if successful
     */
    suspend fun receiveMessage(
        encryptedData: String,
        senderPublicKey: ByteArray,
        senderOnionAddress: String,
        messageType: String = Message.MESSAGE_TYPE_TEXT,
        voiceDuration: Int? = null,
        selfDestructAt: Long? = null,
        requiresReadReceipt: Boolean = true,
        pingId: String? = null
    ): Result<Message> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Receiving $messageType message from: $senderOnionAddress")

            // PHASE 1.2: Get our public key for deterministic messageId calculation
            // Both sender and receiver must compute same ID using SORTED pubkeys
            val ourPublicKeyBase64 = android.util.Base64.encodeToString(keyManager.getSigningPublicKey(), android.util.Base64.NO_WRAP)
            val senderPublicKeyBase64 = android.util.Base64.encodeToString(senderPublicKey, android.util.Base64.NO_WRAP)

            // Get database instance
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Find contact by Tor address
            val contact = database.contactDao().getContactByOnionAddress(senderOnionAddress)
                ?: return@withContext Result.failure(Exception("Unknown sender: $senderOnionAddress"))

            Log.d(TAG, "Message from: ${contact.displayName}")

            // Get key chain for this contact (for progressive ephemeral key evolution)
            Log.d(TAG, "Decrypting message with skipped key support...")
            val keyChain = KeyChainManager.getKeyChain(context, contact.id)
            if (keyChain == null) {
                Log.e(TAG, "DECRYPTION FAILED: Key chain not found for contact ${contact.id} (${contact.displayName})")
                Log.e(TAG, "This contact was probably added before key chain support was implemented.")
                Log.e(TAG, "Fix: Remove and re-add this contact to initialize a new key chain.")
                throw Exception("Key chain not found for contact ${contact.id}")
            }

            // Log current key chain state for debugging
            Log.d(TAG, "Key chain state: sendCounter=${keyChain.sendCounter}, receiveCounter=${keyChain.receiveCounter}")

            // Wire format: [version:1][sequence:8][nonce:24][ciphertext][tag:16]
            val encryptedBytes = Base64.decode(encryptedData, Base64.NO_WRAP)

            // Extract sequence from wire format
            val messageSequence = if (encryptedBytes.size >= 9) {
                java.nio.ByteBuffer.wrap(encryptedBytes.sliceArray(1..8)).long
            } else {
                Log.e(TAG, "DECRYPTION FAILED: Ciphertext too short (${encryptedBytes.size} bytes)")
                return@withContext Result.failure(Exception("Ciphertext too short"))
            }

            val receiveCounter = keyChain.receiveCounter
            Log.d(TAG, "Message sequence: $messageSequence (expecting: $receiveCounter)")

            // MAX_SKIP security limit to prevent memory exhaustion attacks
            val MAX_SKIP = 100L

            // Skipped message key algorithm: Four distinct paths
            val decryptedData: String
            val newReceiveCounter: Long
            val newReceiveChainKey: ByteArray

            when {
                // PATH 1: Past message (n < Nr) - check skipped keys table
                messageSequence < receiveCounter -> {
                    Log.d(TAG, "PAST MESSAGE: seq=$messageSequence < receiveCounter=$receiveCounter")
                    Log.d(TAG, "Checking skipped_message_keys table...")

                    val skippedKey = database.skippedMessageKeyDao().getKey(contact.id, messageSequence)
                    if (skippedKey == null) {
                        Log.e(TAG, "SKIPPED KEY NOT FOUND: seq=$messageSequence (too old or never skipped)")
                        return@withContext Result.failure(Exception("Message key not found - message too old"))
                    }

                    Log.d(TAG, "Found skipped key for seq=$messageSequence, attempting decryption...")

                    // Decrypt using stored message key (no chain key evolution)
                    val plaintext = RustBridge.decryptWithMessageKey(encryptedBytes, skippedKey.messageKey)
                    if (plaintext == null) {
                        Log.e(TAG, "DECRYPTION FAILED: Invalid message key for seq=$messageSequence")
                        return@withContext Result.failure(Exception("Decryption failed with skipped key"))
                    }

                    decryptedData = plaintext

                    // Delete used key immediately (forward secrecy)
                    database.skippedMessageKeyDao().deleteKey(contact.id, messageSequence)
                    Log.d(TAG, "Deleted used skipped key for seq=$messageSequence")

                    // Chain key state unchanged (past message doesn't affect current state)
                    newReceiveCounter = receiveCounter
                    newReceiveChainKey = keyChain.receiveChainKeyBytes
                }

                // PATH 2: Gap too large (n - Nr > MAX_SKIP) - reject
                messageSequence - receiveCounter > MAX_SKIP -> {
                    Log.e(TAG, "SEQUENCE TOO FAR: seq=$messageSequence, receiveCounter=$receiveCounter, gap=${messageSequence - receiveCounter} > MAX_SKIP=$MAX_SKIP")
                    return@withContext Result.failure(Exception("Sequence too far ahead - possible desync or attack"))
                }

                // PATH 3: Future message (n > Nr) - derive and store skipped keys
                messageSequence > receiveCounter -> {
                    Log.d(TAG, "FUTURE MESSAGE: seq=$messageSequence > receiveCounter=$receiveCounter")
                    Log.d(TAG, "Deriving ${messageSequence - receiveCounter} skipped message keys for gap [${receiveCounter}..${messageSequence - 1}]")

                    var currentChainKey = keyChain.receiveChainKeyBytes
                    val skippedKeys = mutableListOf<com.securelegion.database.entities.SkippedMessageKey>()

                    // Derive and store message keys for skipped sequences [Nr..n-1]
                    for (seq in receiveCounter until messageSequence) {
                        // Derive message key from current chain key
                        val messageKey = RustBridge.deriveMessageKey(currentChainKey)
                            ?: throw Exception("Failed to derive message key for sequence $seq")

                        // Store skipped key for this sequence
                        skippedKeys.add(
                            com.securelegion.database.entities.SkippedMessageKey(
                                id = "${contact.id}_$seq",
                                contactId = contact.id,
                                sequence = seq,
                                messageKey = messageKey,
                                timestamp = System.currentTimeMillis()
                            )
                        )

                        // Evolve chain key to next state
                        currentChainKey = RustBridge.evolveChainKey(currentChainKey)
                            ?: throw Exception("Failed to evolve chain key at sequence $seq")
                    }

                    // Bulk insert skipped keys
                    database.skippedMessageKeyDao().insertAll(skippedKeys)
                    Log.d(TAG, "Stored ${skippedKeys.size} skipped message keys")

                    // currentChainKey is now at sequence n (current message)
                    // Derive message key for current message
                    val currentMessageKey = RustBridge.deriveMessageKey(currentChainKey)
                        ?: throw Exception("Failed to derive message key for sequence $messageSequence")

                    // Decrypt current message using derived key
                    val plaintext = RustBridge.decryptWithMessageKey(encryptedBytes, currentMessageKey)
                    if (plaintext == null) {
                        Log.e(TAG, "DECRYPTION FAILED: Message key invalid for seq=$messageSequence")
                        return@withContext Result.failure(Exception("Decryption failed after skipping"))
                    }

                    decryptedData = plaintext

                    // Evolve chain key once more for next expected message
                    val evolvedChainKey = RustBridge.evolveChainKey(currentChainKey)
                        ?: throw Exception("Failed to evolve chain key after decrypting sequence $messageSequence")

                    // Update state: receiveCounter = n + 1
                    newReceiveCounter = messageSequence + 1
                    newReceiveChainKey = evolvedChainKey
                    Log.d(TAG, "Decrypted message seq=$messageSequence, updated receiveCounter=$newReceiveCounter")
                }

                // PATH 4: In-order message (n == Nr) - normal flow
                else -> {
                    Log.d(TAG, "IN-ORDER MESSAGE: seq=$messageSequence == receiveCounter=$receiveCounter")

                    // Normal decryption with atomic key evolution
                    val result = RustBridge.decryptMessageWithEvolution(
                        encryptedBytes,
                        keyChain.receiveChainKeyBytes,
                        receiveCounter
                    )

                    if (result == null) {
                        Log.e(TAG, "DECRYPTION FAILED: RustBridge returned null")
                        return@withContext Result.failure(Exception("Failed to decrypt message"))
                    }

                    decryptedData = result.plaintext

                    // Update state: receiveCounter = n + 1
                    newReceiveCounter = receiveCounter + 1
                    newReceiveChainKey = result.evolvedChainKey
                    Log.d(TAG, "Decrypted in-order message, updated receiveCounter=$newReceiveCounter")
                }
            }

            // Save updated chain key state to database (only if changed)
            if (newReceiveCounter != receiveCounter) {
                database.contactKeyChainDao().updateReceiveChainKey(
                    contactId = contact.id,
                    newReceiveChainKeyBase64 = android.util.Base64.encodeToString(newReceiveChainKey, android.util.Base64.NO_WRAP),
                    newReceiveCounter = newReceiveCounter,
                    timestamp = System.currentTimeMillis()
                )
                Log.d(TAG, "Saved updated key chain state: receiveCounter=$newReceiveCounter")
            }

            // Extract nonce from wire format (bytes 9-32, after version and sequence)
            val nonce = encryptedBytes.sliceArray(9 until 33)
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // PHASE 1.1: STABLE IDENTITY
            // Generate message nonce ONCE for received messages (used for dedup + retry stability)
            val messageNonce = generateMessageNonce()

            // Handle based on message type
            val message = when (messageType) {
                Message.MESSAGE_TYPE_VOICE -> {
                    // Voice message: decryptedData is audio bytes
                    val audioBytes = decryptedData.toByteArray(Charsets.ISO_8859_1)

                    // Save audio to local storage
                    val voiceRecorder = com.securelegion.utils.VoiceRecorder(context)
                    val voiceFilePath = voiceRecorder.saveVoiceMessage(audioBytes, voiceDuration ?: 0)

                    // PHASE 1.2: Generate deterministic messageId using SORTED pubkeys
                    // Sender computed: generateDeterministicMessageId(audio, senderKey, recipientKey, nonce)
                    // Receiver computes: generateDeterministicMessageId(audio, senderKey, ourKey, nonce) with SORTED keys
                    // sort([senderKey, ourKey]) == sort([ourKey, senderKey]) ← ensures same ID on both sides
                    val audioAsString = String(audioBytes, Charsets.ISO_8859_1)
                    val messageId = generateDeterministicMessageId(
                        plaintext = audioAsString,
                        senderEd25519Base64 = senderPublicKeyBase64,
                        recipientEd25519Base64 = ourPublicKeyBase64,
                        messageNonce = messageNonce // Use the nonce we generated for this received message
                    )

                    // Check for duplicate
                    if (database.messageDao().messageExists(messageId)) {
                        Log.w(TAG, "Duplicate voice message ignored: $messageId")
                        return@withContext Result.failure(Exception("Duplicate message"))
                    }

                    Message(
                        contactId = contact.id,
                        messageId = messageId,
                        encryptedContent = "", // Empty for voice messages
                        messageType = Message.MESSAGE_TYPE_VOICE,
                        voiceDuration = voiceDuration,
                        voiceFilePath = voiceFilePath,
                        isSentByMe = false,
                        timestamp = System.currentTimeMillis(),
                        status = Message.STATUS_DELIVERED,
                        signatureBase64 = "",
                        nonceBase64 = nonceBase64,
                        messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                        selfDestructAt = selfDestructAt,
                        requiresReadReceipt = requiresReadReceipt,
                        pingId = pingId
                    )
                }
                Message.MESSAGE_TYPE_IMAGE -> {
                    // Image message: decryptedData is image bytes
                    val imageBytes = decryptedData.toByteArray(Charsets.ISO_8859_1)
                    val imageBase64 = Base64.encodeToString(imageBytes, Base64.NO_WRAP)

                    // PHASE 1.2: Generate deterministic messageId using SORTED pubkeys
                    val messageId = generateDeterministicMessageId(
                        plaintext = imageBase64,
                        senderEd25519Base64 = senderPublicKeyBase64,
                        recipientEd25519Base64 = ourPublicKeyBase64,
                        messageNonce = messageNonce
                    )

                    // Check for duplicate
                    if (database.messageDao().messageExists(messageId)) {
                        Log.w(TAG, "Duplicate image message ignored: $messageId")
                        return@withContext Result.failure(Exception("Duplicate message"))
                    }

                    Message(
                        contactId = contact.id,
                        messageId = messageId,
                        encryptedContent = "", // Empty for image messages
                        messageType = Message.MESSAGE_TYPE_IMAGE,
                        attachmentType = "image",
                        attachmentData = imageBase64, // Store Base64 for display
                        isSentByMe = false,
                        timestamp = System.currentTimeMillis(),
                        status = Message.STATUS_DELIVERED,
                        signatureBase64 = "",
                        nonceBase64 = nonceBase64,
                        messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                        selfDestructAt = selfDestructAt,
                        requiresReadReceipt = requiresReadReceipt,
                        pingId = pingId
                    )
                }
                Message.MESSAGE_TYPE_PAYMENT_REQUEST -> {
                    // Payment request: decryptedData is JSON {"type":"PAYMENT_REQUEST","quote":{...}}
                    val payloadJson = org.json.JSONObject(decryptedData)
                    val quoteJson = payloadJson.getJSONObject("quote").toString()

                    // Parse quote to extract payment details
                    val quote = NLx402Manager.PaymentQuote.fromJson(quoteJson)
                        ?: return@withContext Result.failure(Exception("Failed to parse payment quote"))

                    // Generate message ID from quote ID + sender
                    val messageId = "pay_req_${quote.quoteId}"

                    // Check for duplicate
                    if (database.messageDao().messageExists(messageId)) {
                        Log.w(TAG, "Duplicate payment request ignored: $messageId")
                        return@withContext Result.failure(Exception("Duplicate message"))
                    }

                    Message(
                        contactId = contact.id,
                        messageId = messageId,
                        encryptedContent = "", // Empty for payment messages
                        messageType = Message.MESSAGE_TYPE_PAYMENT_REQUEST,
                        paymentQuoteJson = quoteJson, // Store the raw quote JSON
                        paymentStatus = Message.PAYMENT_STATUS_PENDING,
                        paymentToken = quote.token,
                        paymentAmount = quote.amount,
                        isSentByMe = false,
                        timestamp = System.currentTimeMillis(),
                        status = Message.STATUS_DELIVERED,
                        signatureBase64 = "",
                        nonceBase64 = nonceBase64,
                        messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                        selfDestructAt = selfDestructAt,
                        requiresReadReceipt = requiresReadReceipt,
                        pingId = pingId
                    )
                }
                Message.MESSAGE_TYPE_PAYMENT_SENT -> {
                    // Payment sent confirmation: {"type":"PAYMENT_SENT","quote_id":"...","tx_signature":"...","amount":...,"token":"..."}
                    val payloadJson = org.json.JSONObject(decryptedData)
                    val quoteId = payloadJson.getString("quote_id")
                    val txSignature = payloadJson.getString("tx_signature")
                    val amount = payloadJson.getLong("amount")
                    val token = payloadJson.getString("token")

                    // Generate message ID
                    val messageId = "pay_sent_${quoteId}"

                    // Check for duplicate
                    if (database.messageDao().messageExists(messageId)) {
                        Log.w(TAG, "Duplicate payment sent message ignored: $messageId")
                        return@withContext Result.failure(Exception("Duplicate message"))
                    }

                    // Update the original payment request status to PAID
                    val originalRequestId = "pay_req_${quoteId}"
                    database.messageDao().updatePaymentStatus(originalRequestId, Message.PAYMENT_STATUS_PAID, txSignature)

                    Message(
                        contactId = contact.id,
                        messageId = messageId,
                        encryptedContent = "",
                        messageType = Message.MESSAGE_TYPE_PAYMENT_SENT,
                        paymentStatus = Message.PAYMENT_STATUS_PAID,
                        txSignature = txSignature,
                        paymentToken = token,
                        paymentAmount = amount,
                        isSentByMe = false,
                        timestamp = System.currentTimeMillis(),
                        status = Message.STATUS_DELIVERED,
                        signatureBase64 = "",
                        nonceBase64 = nonceBase64,
                        messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                        selfDestructAt = selfDestructAt,
                        requiresReadReceipt = requiresReadReceipt,
                        pingId = pingId
                    )
                }
                Message.MESSAGE_TYPE_PAYMENT_ACCEPTED -> {
                    // Payment acceptance: {"type":"PAYMENT_ACCEPTED","quote_id":"...","receive_address":"...","amount":...,"token":"..."}
                    val payloadJson = org.json.JSONObject(decryptedData)
                    val quoteId = payloadJson.getString("quote_id")
                    val receiveAddress = payloadJson.getString("receive_address")
                    val amount = payloadJson.getLong("amount")
                    val token = payloadJson.getString("token")

                    // Generate message ID
                    val messageId = "pay_accept_${quoteId}"

                    // Check for duplicate
                    if (database.messageDao().messageExists(messageId)) {
                        Log.w(TAG, "Duplicate payment acceptance ignored: $messageId")
                        return@withContext Result.failure(Exception("Duplicate message"))
                    }

                    Message(
                        contactId = contact.id,
                        messageId = messageId,
                        encryptedContent = receiveAddress, // Store receive address in content field
                        messageType = Message.MESSAGE_TYPE_PAYMENT_ACCEPTED,
                        paymentStatus = Message.PAYMENT_STATUS_PENDING,
                        paymentToken = token,
                        paymentAmount = amount,
                        isSentByMe = false,
                        timestamp = System.currentTimeMillis(),
                        status = Message.STATUS_DELIVERED,
                        signatureBase64 = "",
                        nonceBase64 = nonceBase64,
                        messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                        selfDestructAt = selfDestructAt,
                        requiresReadReceipt = requiresReadReceipt,
                        pingId = pingId
                    )
                }
                Message.MESSAGE_TYPE_PROFILE_UPDATE -> {
                    // Profile photo update: decryptedData is [0x0F][photoBytes...]
                    // Strip the type prefix byte and extract photo
                    val rawBytes = decryptedData.toByteArray(Charsets.ISO_8859_1)
                    val photoBytes = if (rawBytes.size > 1) rawBytes.copyOfRange(1, rawBytes.size) else ByteArray(0)

                    if (photoBytes.isEmpty()) {
                        // Empty body = photo removal
                        database.contactDao().updateContactPhoto(contact.id, null)
                        Log.i(TAG, "Profile photo removed for ${contact.displayName}")
                    } else {
                        val photoBase64 = Base64.encodeToString(photoBytes, Base64.NO_WRAP)
                        database.contactDao().updateContactPhoto(contact.id, photoBase64)
                        Log.i(TAG, "Profile photo updated for ${contact.displayName} (${photoBytes.size} bytes)")
                    }

                    // Return early - profile updates are never saved to messages table
                    return@withContext Result.failure(Exception("Profile update processed"))
                }
                else -> {
                    // Text message (default)
                    val plaintext = decryptedData

                    // PHASE 1.2: Generate deterministic messageId using SORTED pubkeys
                    // This matches the sender's computation exactly, enabling dedup
                    val messageId = generateDeterministicMessageId(
                        plaintext = plaintext,
                        senderEd25519Base64 = senderPublicKeyBase64,
                        recipientEd25519Base64 = ourPublicKeyBase64,
                        messageNonce = messageNonce
                    )

                    // Check for duplicate
                    if (database.messageDao().messageExists(messageId)) {
                        Log.w(TAG, "Duplicate message ignored: $messageId")
                        return@withContext Result.failure(Exception("Duplicate message"))
                    }

                    Message(
                        contactId = contact.id,
                        messageId = messageId,
                        encryptedContent = plaintext,
                        messageType = Message.MESSAGE_TYPE_TEXT,
                        isSentByMe = false,
                        timestamp = System.currentTimeMillis(),
                        status = Message.STATUS_DELIVERED,
                        signatureBase64 = "",
                        nonceBase64 = nonceBase64,
                        messageNonce = messageNonce, // CRITICAL: Stored once, reused on all retries
                        selfDestructAt = selfDestructAt,
                        requiresReadReceipt = requiresReadReceipt,
                        pingId = pingId
                    )
                }
            }

            if (selfDestructAt != null) {
                Log.d(TAG, "Message has self-destruct enabled, expires at: $selfDestructAt")
            }

            // Save to database
            val savedMessageId = database.messageDao().insertMessage(message)

            // Broadcast to MainActivity to refresh chat list preview (explicit broadcast)
            val intent = android.content.Intent("com.securelegion.NEW_PING")
            intent.setPackage(context.packageName) // Make it explicit
            intent.putExtra("CONTACT_ID", contact.id)
            context.sendBroadcast(intent)
            Log.d(TAG, "Sent explicit NEW_PING broadcast to refresh MainActivity chat list")

            Log.i(TAG, "$messageType message received and saved: ${message.messageId}")

            // Note: Out-of-order messages are now handled by skipped message key algorithm
            // No buffering needed - late messages decrypt using stored keys

            Result.success(message.copy(id = savedMessageId))

        } catch (e: Exception) {
            Log.e(TAG, "Failed to receive message", e)
            Result.failure(e)
        }
    }

    /**
     * Handle incoming ACK with strict ordering enforcement
     *
     * CRITICAL: This enforces the ACK state machine to prevent permanent crypto desync:
     * NONE -> PING_ACKED -> PONG_ACKED -> MESSAGE_ACKED
     *
     * Out-of-order ACKs are silently dropped (logged as warnings).
     * Duplicate ACKs are detected and ignored (idempotency guard).
     *
     * @param messageId The message ID this ACK is for
     * @param ackType The type of ACK ("PING_ACK", "PONG_ACK", "MESSAGE_ACK")
     * @param contactId The contact ID (for logging and updates)
     * @return true if ACK was accepted and state advanced, false if rejected
     */
    suspend fun handleIncomingAck(
        messageId: String,
        ackType: String,
        contactId: Long
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Processing ACK: msg=$messageId type=$ackType contact=$contactId")

            // Let state machine validate ordering
            if (!ackTracker.processAck(messageId, ackType)) {
                Log.w(TAG, "ACK rejected (invalid ordering or duplicate): $messageId/$ackType")
                return@withContext false
            }

            val currentState = ackTracker.getState(messageId)
            Log.d(TAG, "ACK accepted, state now: $currentState")

            // Update database based on new state
            try {
                val keyManager = KeyManager.getInstance(context)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

                // Look up the message to update
                val message = database.messageDao().getMessageByMessageId(messageId)
                if (message != null) {
                    // Create updated message based on new state
                    val updatedMessage = when (currentState) {
                        AckState.PING_ACKED -> {
                            // Ping acknowledged - mark pingDelivered
                            message.copy(pingDelivered = true)
                        }
                        AckState.PONG_ACKED -> {
                            // Pong acknowledged - mark pongDelivered
                            message.copy(pongDelivered = true)
                        }
                        AckState.MESSAGE_ACKED -> {
                            // Full delivery - mark messageDelivered and status = DELIVERED
                            message.copy(
                                messageDelivered = true,
                                status = Message.STATUS_DELIVERED
                            )
                        }
                        else -> null // NONE state - no update needed
                    }

                    // Save updated message if state changed
                    if (updatedMessage != null) {
                        database.messageDao().updateMessage(updatedMessage)
                        Log.d(TAG, "Updated message status: $currentState for $messageId")

                        // Broadcast UI update for all delivery status changes
                        if (currentState == AckState.PING_ACKED || currentState == AckState.PONG_ACKED || currentState == AckState.MESSAGE_ACKED) {
                            val intent = Intent("com.securelegion.MESSAGE_RECEIVED")
                            intent.setPackage(context.packageName)
                            intent.putExtra("CONTACT_ID", contactId)
                            context.sendBroadcast(intent)
                            val statusDesc = when(currentState) {
                                AckState.PING_ACKED -> "PING_ACK"
                                AckState.PONG_ACKED -> "PONG_ACK"
                                AckState.MESSAGE_ACKED -> "MESSAGE_ACK"
                                else -> "UNKNOWN"
                            }
                            Log.d(TAG, "Broadcast MESSAGE_RECEIVED for $statusDesc (contact $contactId)")
                        }
                    }
                } else {
                    Log.w(TAG, "Could not find message for ACK: $messageId")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to update message state for ACK: $ackType on $messageId", e)
                // Don't return failure - ACK was processed by state machine, DB update is secondary
            }

            return@withContext true

        } catch (e: Exception) {
            Log.e(TAG, "Error handling ACK: $ackType for message: $messageId", e)
            return@withContext false
        }
    }

    /**
     * Get the current ACK state for a message (for testing/debugging)
     */
    fun getAckState(messageId: String): AckState {
        return ackTracker.getState(messageId)
    }

    /**
     * Clear ACK state for a message (called when message deleted)
     */
    fun clearAckState(messageId: String) {
        ackTracker.clear(messageId)
    }

    /**
     * Clear ACK state for all messages in a thread (called when thread deleted)
     */
    fun clearAckStateForThread(messageIds: List<String>) {
        ackTracker.clearByThread(messageIds)
    }

    /**
     * Handle incoming call signaling messages (CALL_OFFER, CALL_ANSWER, etc.)
     * This intercepts call-related messages before they go to the database
     *
     * @param encryptedData Base64 encrypted message data
     * @param senderPublicKey Sender's Ed25519 public key
     * @param senderOnionAddress Sender's .onion address
     * @param contactId Optional contact ID (if already looked up)
     * @return true if message was a call signaling message (handled), false otherwise
     */
    suspend fun handleCallSignaling(
        encryptedData: String,
        senderPublicKey: ByteArray,
        senderOnionAddress: String,
        contactId: Long? = null
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "handleCallSignaling: Checking if message is call signaling...")
            // Decrypt message to check if it's call signaling
            // Call signaling uses X25519 encryption keys (not Ed25519 signing keys)
            val encryptedBytes = Base64.decode(encryptedData, Base64.NO_WRAP)
            Log.d(TAG, "handleCallSignaling: Encrypted bytes size: ${encryptedBytes.size}")

            val ourPrivateKey = keyManager.getEncryptionKeyBytes()
            val decryptedData = RustBridge.decryptMessage(encryptedBytes, senderPublicKey, ourPrivateKey)

            if (decryptedData == null) {
                Log.w(TAG, "handleCallSignaling: Decryption FAILED - not call signaling")
                return@withContext false
            }

            Log.d(TAG, "handleCallSignaling: Decryption successful, data: ${decryptedData.take(100)}...")

            // Try to parse as call signaling message
            val callMessage = CallSignaling.parseCallMessage(decryptedData)

            if (callMessage == null) {
                Log.w(TAG, "handleCallSignaling: Parse FAILED - not call signaling JSON")
                return@withContext false
            }

            Log.i(TAG, "handleCallSignaling: Received call signaling message: ${callMessage.javaClass.simpleName}")

            // Get database instance to lookup contact
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Find contact (use provided contactId if available, otherwise lookup by onion address)
            val contact = if (contactId != null) {
                database.contactDao().getContactById(contactId)
            } else {
                database.contactDao().getContactByOnionAddress(senderOnionAddress)
            } ?: run {
                Log.e(TAG, "Unknown sender for call: $senderOnionAddress")
                return@withContext true // Still handled (don't store in DB)
            }

            // Handle based on message type
            when (callMessage) {
                is CallSignaling.CallSignalingMessage.CallOffer -> {
                    Log.i(TAG, "Incoming call from ${contact.displayName} (voiceOnion: ${callMessage.voiceOnion})")

                    // CRITICAL: Update contact's voiceOnion if we don't have it
                    if (contact.voiceOnion.isNullOrEmpty() && callMessage.voiceOnion.isNotEmpty()) {
                        Log.i(TAG, "Updating contact ${contact.displayName} voiceOnion: ${callMessage.voiceOnion}")
                        val updatedContact = contact.copy(voiceOnion = callMessage.voiceOnion)
                        database.contactDao().updateContact(updatedContact)
                    }

                    // Check if incoming calls are allowed when app is closed
                    val prefs = context.getSharedPreferences("security", android.content.Context.MODE_PRIVATE)
                    val allowIncomingCallsWhenClosed = prefs.getBoolean(
                        com.securelegion.SecurityModeActivity.PREF_ALLOW_INCOMING_CALLS_WHEN_CLOSED,
                        true // default: allow calls
                    )

                    if (!allowIncomingCallsWhenClosed) {
                        // Setting disabled - save as missed call and send rejection
                        Log.i(TAG, "Incoming calls when app closed is disabled - saving as missed call")

                        // Save missed call to database
                        val callHistory = com.securelegion.database.entities.CallHistory(
                            contactId = contact.id,
                            contactName = contact.displayName,
                            callId = callMessage.callId,
                            timestamp = System.currentTimeMillis(),
                            type = com.securelegion.database.entities.CallType.MISSED,
                            duration = 0,
                            missedReason = "Incoming calls disabled when app closed"
                        )
                        database.callHistoryDao().insert(callHistory)
                        Log.i(TAG, "Saved missed call to database: ${contact.displayName}")

                        // Send CALL_REJECT to caller
                        val keyManager = KeyManager.getInstance(context)
                        val ourX25519PublicKey = keyManager.getEncryptionPublicKey()
                        CallSignaling.sendCallReject(
                            contact.x25519PublicKeyBytes,
                            callMessage.voiceOnion,
                            callMessage.callId,
                            "Call privacy settings: incoming calls disabled",
                            ourX25519PublicKey
                        )
                        Log.i(TAG, "Sent CALL_REJECT due to privacy settings")

                        return@withContext true // Message handled
                    }

                    // Get call manager
                    val callManager = VoiceCallManager.getInstance(context)

                    // Register incoming call (returns true if new, false if duplicate)
                    // Use voiceOnion from CALL_OFFER (this is where CALL_ANSWER will be sent)
                    val isNewCall = callManager.handleIncomingCallOffer(
                        callId = callMessage.callId,
                        contactOnion = callMessage.voiceOnion,
                        contactEd25519PublicKey = contact.ed25519PublicKeyBytes,
                        contactName = contact.displayName,
                        ephemeralPublicKey = callMessage.ephemeralPublicKey
                    )

                    // Only launch IncomingCallActivity for NEW calls (not duplicates)
                    if (isNewCall) {
                        Log.i(TAG, "New incoming call - launching IncomingCallActivity")
                        val intent = Intent(context, IncomingCallActivity::class.java)
                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        intent.putExtra(IncomingCallActivity.EXTRA_CALL_ID, callMessage.callId)
                        intent.putExtra(IncomingCallActivity.EXTRA_CONTACT_ID, contact.id)
                        intent.putExtra(IncomingCallActivity.EXTRA_CONTACT_NAME, contact.displayName)
                        // Use voiceOnion from CALL_OFFER for sending CALL_ANSWER back
                        intent.putExtra(IncomingCallActivity.EXTRA_CONTACT_ONION, callMessage.voiceOnion)
                        intent.putExtra(IncomingCallActivity.EXTRA_CONTACT_ED25519_PUBLIC_KEY, contact.ed25519PublicKeyBytes)
                        intent.putExtra(IncomingCallActivity.EXTRA_CONTACT_X25519_PUBLIC_KEY, contact.x25519PublicKeyBytes)
                        intent.putExtra(IncomingCallActivity.EXTRA_EPHEMERAL_PUBLIC_KEY, callMessage.ephemeralPublicKey)
                        context.startActivity(intent)
                    } else {
                        Log.d(TAG, "Duplicate CALL_OFFER - not launching IncomingCallActivity again")
                    }
                }

                is CallSignaling.CallSignalingMessage.CallAnswer -> {
                    Log.i(TAG, "Call answered by ${contact.displayName} (voiceOnion: ${callMessage.voiceOnion})")

                    // CRITICAL: Update contact's voiceOnion if we don't have it
                    if (contact.voiceOnion.isNullOrEmpty() && callMessage.voiceOnion.isNotEmpty()) {
                        Log.i(TAG, "Updating contact ${contact.displayName} voiceOnion: ${callMessage.voiceOnion}")
                        val updatedContact = contact.copy(voiceOnion = callMessage.voiceOnion)
                        database.contactDao().updateContact(updatedContact)
                    }

                    val callManager = VoiceCallManager.getInstance(context)
                    callManager.handleCallAnswer(callMessage.callId, callMessage.ephemeralPublicKey)
                }

                is CallSignaling.CallSignalingMessage.CallReject -> {
                    Log.i(TAG, "Call rejected by ${contact.displayName}: ${callMessage.reason}")
                    val callManager = VoiceCallManager.getInstance(context)
                    callManager.handleCallReject(callMessage.callId, callMessage.reason)
                }

                is CallSignaling.CallSignalingMessage.CallEnd -> {
                    Log.i(TAG, "Call ended by ${contact.displayName}: ${callMessage.reason}")
                    val callManager = VoiceCallManager.getInstance(context)
                    callManager.endCall(callMessage.reason)
                }

                is CallSignaling.CallSignalingMessage.CallBusy -> {
                    Log.i(TAG, "Contact ${contact.displayName} is busy")
                    val callManager = VoiceCallManager.getInstance(context)
                    callManager.handleCallBusy(callMessage.callId)
                }
            }

            true // Message was handled, don't store in database

        } catch (e: Exception) {
            Log.e(TAG, "Error handling call signaling", e)
            false // Not a call signaling message (or error occurred)
        }
    }

    /**
     * Load all messages for a contact
     */
    suspend fun getMessagesForContact(contactId: Long): List<Message> = withContext(Dispatchers.IO) {
        try {
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)
            val messages = database.messageDao().getMessagesForContact(contactId)
            Log.d(TAG, "Loaded ${messages.size} messages for contact $contactId")
            messages.forEach { msg ->
                Log.d(TAG, "- [${msg.messageType}] ${msg.encryptedContent.take(30)}... (id=${msg.id}, status=${msg.status})")
            }
            messages
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load messages", e)
            emptyList()
        }
    }

    /**
     * Send encrypted message via Tor hidden service using Ping-Pong protocol
     */
    private suspend fun sendViaTor(onionAddress: String, encryptedData: String, messageId: String) {
        withContext(Dispatchers.IO) {
            try {
                Log.d(TAG, "Sending to Tor hidden service")
                Log.d(TAG, "Message ID: $messageId")
                Log.d(TAG, "Encrypted data length: ${encryptedData.length}")

                // Get database to retrieve recipient's keys
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

                // Find contact by onion address
                val contact = database.contactDao().getContactByOnionAddress(onionAddress)
                    ?: throw Exception("Contact not found for onion address: $onionAddress")

                // Get recipient's public keys
                val recipientEd25519PubKey = Base64.decode(contact.publicKeyBase64, Base64.NO_WRAP)
                val recipientX25519PubKey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)

                // Convert encrypted data to bytes
                val encryptedBytes = Base64.decode(encryptedData, Base64.NO_WRAP)

                // Send via Tor using Ping-Pong wake protocol
                val success = RustBridge.sendDirectMessage(
                    recipientEd25519PublicKey = recipientEd25519PubKey,
                    recipientX25519PublicKey = recipientX25519PubKey,
                    recipientOnion = onionAddress,
                    encryptedMessage = encryptedBytes
                )

                if (!success) {
                    throw Exception("Message delivery failed - recipient may be offline or declined")
                }

                Log.i(TAG, "Message sent successfully via Tor: $messageId")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to send via Tor", e)
                throw e
            }
        }
    }

    /**
     * Generate deterministic message ID from content and sender
     * This ensures the same message from the same sender is detected as duplicate
     * NOTE: We don't use nonce because retries create new nonces but have same content
     */
    private fun generateMessageId(content: String, senderAddress: String): String {
        val data = "$content$senderAddress".toByteArray()
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(data)
        return Base64.encodeToString(hash, Base64.NO_WRAP).take(32)
    }

    /**
     * Send Ping for a pending message (Phase 3: Async Ping sending)
     * Called by retry worker to attempt sending Pings for queued messages
     */
    suspend fun sendPingForMessage(message: Message): Result<String> = withContext(Dispatchers.IO) {
        try {
            if (message.pingId == null) {
                return@withContext Result.failure(Exception("Message has no Ping ID"))
            }

            Log.d(TAG, "Sending Ping for message ${message.messageId} (Ping ID: ${message.pingId})")

            // Wait for transport gate (best-effort with send timeout — retry worker handles failures)
            Log.d(TAG, "Waiting for transport gate before sending Ping...")
            TorService.getTransportGate()?.awaitOpen(com.securelegion.network.TransportGate.TIMEOUT_SEND_MS)
            Log.d(TAG, "Transport gate check done - proceeding with Ping send")

            // Check if Tor is warmed up (must wait 20s after restart/network change)
            val warmupRemainingMs = TorService.getTorWarmupRemainingMs()
            if (warmupRemainingMs == null) {
                Log.w(TAG, "TorService not running - cannot send Ping")
                return@withContext Result.failure(Exception("TorService not running"))
            }
            if (warmupRemainingMs > 0) {
                Log.w(TAG, "Tor still warming up (${warmupRemainingMs}ms remaining) - deferring send")
                return@withContext Result.failure(Exception("Tor warming up - retry in ${warmupRemainingMs}ms"))
            }
            Log.d(TAG, "Tor warm-up complete - OK to send")

            // Get database and contact
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)
            val contact = database.contactDao().getContactById(message.contactId)
                ?: return@withContext Result.failure(Exception("Contact not found"))

            // Get recipient keys
            val recipientEd25519PubKey = Base64.decode(contact.publicKeyBase64, Base64.NO_WRAP)
            val recipientX25519PubKey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)

            // Get encrypted message payload
            if (message.encryptedPayload == null) {
                return@withContext Result.failure(Exception("Message has no encrypted payload"))
            }
            val encryptedBytes = Base64.decode(message.encryptedPayload, Base64.NO_WRAP)
            Log.d(TAG, "Encrypted message size: ${encryptedBytes.size} bytes (Base64 encoded size: ${message.encryptedPayload.length})")

            // Convert message type to wire protocol type byte
            val messageTypeByte: Byte = when (message.messageType) {
                Message.MESSAGE_TYPE_VOICE -> 0x04.toByte() // VOICE
                Message.MESSAGE_TYPE_IMAGE -> 0x09.toByte() // IMAGE
                Message.MESSAGE_TYPE_PAYMENT_REQUEST -> 0x0A.toByte() // PAYMENT_REQUEST
                Message.MESSAGE_TYPE_PAYMENT_SENT -> 0x0B.toByte() // PAYMENT_SENT
                Message.MESSAGE_TYPE_PAYMENT_ACCEPTED -> 0x0C.toByte() // PAYMENT_ACCEPTED
                Message.MESSAGE_TYPE_PROFILE_UPDATE -> 0x0F.toByte() // PROFILE_UPDATE
                else -> 0x03.toByte() // TEXT (default)
            }
            Log.d(TAG, "Message type: ${message.messageType} → wire byte: 0x${messageTypeByte.toString(16).padStart(2, '0')}")

            // Send Ping via Rust bridge (with message for instant mode)
            val onionAddress = contact.messagingOnion ?: contact.torOnionAddress ?: ""
            Log.d(TAG, "Resolved messaging .onion for ${contact.displayName}")

            // Validate message has pingId and timestamp (should be generated when message created)
            if (message.pingId == null || message.pingTimestamp == null) {
                return@withContext Result.failure(Exception("Message missing pingId or pingTimestamp - should be set at creation"))
            }

            Log.i(TAG, "Sending Ping with ID: ${message.pingId.take(8)}... (timestamp: ${message.pingTimestamp}, retries use SAME ID)")

            // Send Ping with provided pingId and timestamp (first send and ALL retries use same values)
            val pingResponse = try {
                RustBridge.sendPing(
                    recipientEd25519PubKey,
                    recipientX25519PubKey,
                    onionAddress,
                    encryptedBytes,
                    messageTypeByte,
                    message.pingId!!, // Generated once when message created
                    message.pingTimestamp!! // Generated once when message created
                )
            } catch (e: Exception) {
                val errorMsg = e.message ?: "Unknown error"

                // Check if this is a retryable SOCKS failure (Tor-native behavior)
                val isRetryable = when {
                    // SOCKS status=1 (general server failure) - temporary routing issue
                    errorMsg.contains("status 1", ignoreCase = true) -> true
                    errorMsg.contains("general SOCKS server failure", ignoreCase = true) -> true

                    // Circuit-related failures - circuits still establishing
                    errorMsg.contains("circuit", ignoreCase = true) -> true
                    errorMsg.contains("MEASUREMENT_EXPIRED", ignoreCase = true) -> true

                    // Network unreachable - temporary network issue
                    errorMsg.contains("Network unreachable", ignoreCase = true) -> true
                    errorMsg.contains("Host unreachable", ignoreCase = true) -> true

                    // Connection refused - HS might be offline/restarting
                    errorMsg.contains("Connection refused", ignoreCase = true) -> true

                    else -> false
                }

                if (isRetryable) {
                    Log.w(TAG, "Soft failure (retryable): $errorMsg")
                    return@withContext Result.failure(Exception("RETRYABLE: $errorMsg"))
                } else {
                    Log.e(TAG, "Hard failure (not retryable): $errorMsg", e)
                    return@withContext Result.failure(e)
                }
            }

            // Parse JSON response: {"pingId":"...","wireBytes":"..."}
            val pingId: String
            val wireBytes: String
            try {
                val json = org.json.JSONObject(pingResponse)
                pingId = json.getString("pingId")
                wireBytes = json.getString("wireBytes")
                Log.i(TAG, "Ping sent successfully (ID: ${pingId.take(8)}...)")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse sendPing response JSON", e)
                return@withContext Result.failure(e)
            }

            // Store wire bytes for resendPingWithWireBytes (backup retry method)
            if (message.pingWireBytes == null) {
                withContext(kotlinx.coroutines.NonCancellable) {
                    // CRITICAL: Use partial update to avoid overwriting delivery status
                    // (fixes race where MESSAGE_ACK sets delivered=true between read and write)
                    database.messageDao().updatePingWireBytes(message.id, wireBytes)
                    Log.d(TAG, "Stored wire bytes for backup retry")

                    // VERIFY the update persisted (fix for race condition)
                    val verifyMessage = database.messageDao().getMessageByPingId(message.pingId ?: "")
                    if (verifyMessage?.pingWireBytes != null) {
                        Log.d(TAG, "VERIFIED wire bytes persisted to database for pingId=${message.pingId?.take(8)}")
                    } else {
                        Log.w(TAG, "WARNING: Wire bytes NOT persisted to database! Fallback to SharedPreferences may occur")
                    }
                }
            }

            // Outgoing ping tracking handled by ping_inbox DB on receiver side
            // Pong lookup uses ping_inbox.contactId — no SharedPrefs needed
            Log.i(TAG, "Outgoing Ping sent: contact_id=${contact.id}, ping_id=$pingId")

            Log.i(TAG, "Ping sent successfully: $pingId (waiting for PING_ACK from receiver)")
            Result.success(pingId)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send Ping", e)
            // Note: Peer connection failures (SOCKS error 5) are normal when peer is offline
            // Don't report as Tor failure - only restart Tor when Tor daemon itself is broken
            Result.failure(e)
        }
    }

    /**
     * Poll for Pongs and send message blobs (Phase 3: Async Pong handling)
     * Checks all messages with STATUS_PING_SENT to see if their Pongs have arrived
     * If Pong found, sends the message blob and updates status
     */
    suspend fun pollForPongsAndSendMessages(): Result<Int> = withContext(Dispatchers.IO) {
        try {
            // Quick gate check for background poll — don't block long
            TorService.getTransportGate()?.awaitOpen(com.securelegion.network.TransportGate.TIMEOUT_QUICK_MS)

            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Get all messages waiting for Pong
            val pendingMessages = database.messageDao().getMessagesAwaitingPong()

            if (pendingMessages.isEmpty()) {
                return@withContext Result.success(0)
            }

            Log.d(TAG, "Polling for Pongs: ${pendingMessages.size} messages waiting")

            var sentCount = 0

            for (message in pendingMessages) {
                val pingId = message.pingId ?: continue

                // Skip if message already delivered to receiver (ACK received)
                if (message.messageDelivered) {
                    Log.d(TAG, "Message ${message.messageId} already delivered - skipping (no ghost message)")
                    continue
                }

                Log.d(TAG, "Checking for Pong with Ping ID: $pingId (message: ${message.messageId}, contact: ${message.contactId})")

                // Check if Pong has arrived (non-blocking)
                val pongReceived = RustBridge.pollForPong(pingId)
                Log.d(TAG, "pollForPong($pingId) returned: $pongReceived")

                if (pongReceived) {
                    Log.i(TAG, "Pong received for Ping ID $pingId! Sending PONG_ACK and message blob...")

                    // Get contact for .onion address
                    val contact = database.contactDao().getContactById(message.contactId)
                    if (contact == null) {
                        Log.e(TAG, "Contact not found for message ${message.id}")
                        continue
                    }

                    // CRITICAL FIX: Send PONG_ACK BEFORE MESSAGE (ordering milestone)
                    // Protocol: Sender receives PONG → sends PONG_ACK → then sends MESSAGE
                    // Make this async so it doesn't block the polling loop, but enforce ordering with retries
                    kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
                        try {
                            val pongAckSent = sendPongAckWithRetry(
                                itemId = pingId,
                                contact = contact,
                                maxRetries = 3
                            )

                            if (pongAckSent) {
                                // Update persistent state: mark PONG_ACK as sent
                                // CRITICAL: Use partial update to avoid overwriting delivery status
                                // (fixes race where MESSAGE_ACK sets delivered=true between read and write)
                                database.messageDao().updatePongDelivered(message.id, true)
                                Log.i(TAG, "Marked PONG_ACK sent for message ${message.messageId}")

                                // NOW send message blob (after PONG_ACK confirmed)
                                sendMessageBlobAfterPongAck(message, contact, pingId)
                            } else {
                                Log.w(TAG, "Failed to send PONG_ACK for message ${message.messageId}, MESSAGE send skipped (will retry)")
                                // MessageRetryWorker will retry the entire flow
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Exception in PONG_ACK sequence: ${e.message}")
                        }
                    }
                }
            }

            Log.d(TAG, "Pong polling complete: $sentCount messages sent")
            Result.success(sentCount)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to poll for Pongs", e)
            Result.failure(e)
        }
    }

    /**
     * Retry a specific message immediately (user-triggered via "Resend" button)
     * Bypasses WorkManager delay and runs on current coroutine scope
     *
     * @param messageId The database ID of the message to retry
     */
    suspend fun retryMessageNow(messageId: Long): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)
            val message = database.messageDao().getMessageById(messageId)

            if (message == null) {
                Log.e(TAG, "Message $messageId not found for retry")
                return@withContext Result.failure(Exception("Message not found"))
            }

            if (!message.isSentByMe) {
                Log.e(TAG, "Cannot retry incoming message $messageId")
                return@withContext Result.failure(Exception("Cannot retry incoming message"))
            }

            Log.i(TAG, "User-triggered immediate retry for message ${message.messageId} (id=$messageId)")

            // Reset status to PING_SENT to allow retry
            database.messageDao().updateMessageStatus(messageId, com.securelegion.database.entities.Message.STATUS_PING_SENT)

            // Check if we have a PONG already (phase 2: need to send message blob)
            val hasPong = try {
                message.pingId?.let { pingId ->
                    com.securelegion.crypto.RustBridge.pollForPong(pingId)
                } ?: false
            } catch (e: Exception) {
                Log.w(TAG, "Error checking for pong: ${e.message}")
                false
            }

            if (hasPong) {
                // Phase 2: Pong already received, just retry sending message blob
                Log.d(TAG, "Pong already received for ${message.messageId}, retrying message blob send")
                pollForPongsAndSendMessages()
            } else {
                // Phase 1: Need to retry PING
                Log.d(TAG, "No pong yet for ${message.messageId}, retrying PING")
                val contact = database.contactDao().getContactById(message.contactId)

                if (contact == null) {
                    Log.e(TAG, "Cannot resend - contact not found")
                    database.messageDao().updateMessageStatus(messageId, com.securelegion.database.entities.Message.STATUS_FAILED)
                    return@withContext Result.failure(Exception("Contact not found"))
                }

                if (message.pingWireBytes != null) {
                    // Resend PING using stored wire bytes (fast path)
                    val success = com.securelegion.crypto.RustBridge.resendPingWithWireBytes(
                        message.pingWireBytes!!,
                        contact.messagingOnion ?: contact.torOnionAddress ?: ""
                    )
                    if (success) {
                        Log.i(TAG, "Ping resent successfully for ${message.messageId}")
                    } else {
                        Log.e(TAG, "Failed to resend Ping for ${message.messageId}")
                        database.messageDao().updateMessageStatus(messageId, com.securelegion.database.entities.Message.STATUS_FAILED)
                        return@withContext Result.failure(Exception("Failed to resend PING"))
                    }
                } else {
                    // Fallback: pingWireBytes missing (old message or race condition)
                    // Recreate PING using existing encrypted payload
                    Log.w(TAG, "pingWireBytes missing for ${message.messageId}, recreating PING from existing payload")

                    if (message.encryptedPayload == null) {
                        Log.e(TAG, "Cannot resend - no encrypted payload stored")
                        database.messageDao().updateMessageStatus(messageId, com.securelegion.database.entities.Message.STATUS_FAILED)
                        return@withContext Result.failure(Exception("No encrypted payload"))
                    }

                    // Get contact keys
                    val recipientEd25519PubKey = Base64.decode(contact.publicKeyBase64, Base64.NO_WRAP)
                    val recipientX25519PubKey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)
                    val onionAddress = contact.messagingOnion ?: contact.torOnionAddress ?: ""

                    // Use existing pingId and timestamp from the message
                    val pingId = message.pingId ?: run {
                        Log.e(TAG, "Cannot resend - no pingId stored")
                        database.messageDao().updateMessageStatus(messageId, com.securelegion.database.entities.Message.STATUS_FAILED)
                        return@withContext Result.failure(Exception("No pingId"))
                    }

                    // Decode the Base64 encrypted payload to bytes
                    val encryptedBytes = Base64.decode(message.encryptedPayload!!, Base64.NO_WRAP)

                    // Convert message type to wire protocol type byte
                    val messageTypeByte: Byte = when (message.messageType) {
                        com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE -> 0x04.toByte()
                        com.securelegion.database.entities.Message.MESSAGE_TYPE_IMAGE -> 0x09.toByte()
                        com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_REQUEST -> 0x0A.toByte()
                        com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_SENT -> 0x0B.toByte()
                        com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_ACCEPTED -> 0x0C.toByte()
                        com.securelegion.database.entities.Message.MESSAGE_TYPE_PROFILE_UPDATE -> 0x0F.toByte()
                        else -> 0x03.toByte() // TEXT (default)
                    }

                    // Recreate PING using RustBridge.sendPing with existing encrypted payload
                    val pingResponse = try {
                        com.securelegion.crypto.RustBridge.sendPing(
                            recipientEd25519PubKey,
                            recipientX25519PubKey,
                            onionAddress,
                            encryptedBytes,
                            messageTypeByte,
                            pingId,
                            message.timestamp
                        )
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to recreate PING", e)
                        database.messageDao().updateMessageStatus(messageId, com.securelegion.database.entities.Message.STATUS_FAILED)
                        return@withContext Result.failure(e)
                    }

                    if (pingResponse == null) {
                        Log.e(TAG, "sendPing returned null")
                        database.messageDao().updateMessageStatus(messageId, com.securelegion.database.entities.Message.STATUS_FAILED)
                        return@withContext Result.failure(Exception("sendPing returned null"))
                    }

                    // Parse JSON response to get wire bytes
                    val wireBytes = try {
                        val json = org.json.JSONObject(pingResponse)
                        json.getString("wireBytes")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to parse sendPing response", e)
                        database.messageDao().updateMessageStatus(messageId, com.securelegion.database.entities.Message.STATUS_FAILED)
                        return@withContext Result.failure(e)
                    }

                    // Store wire bytes for future retries
                    // CRITICAL: Use partial update to avoid overwriting delivery status
                    // (fixes race where MESSAGE_ACK sets delivered=true between read and write)
                    database.messageDao().updatePingWireBytes(message.id, wireBytes)
                    Log.i(TAG, "Recreated PING and stored wire bytes for future retries")
                }
            }

            Result.success(Unit)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to retry message $messageId", e)
            Result.failure(e)
        }
    }

    /**
     * Process buffered out-of-order messages after successfully decrypting a message
     * This recursively processes buffered messages that are now in sequence
     *
     * @param contactId The contact whose messages to process
     * @param database Database instance
     */
    private suspend fun processBufferedMessages(contactId: Long, database: SecureLegionDatabase) {
        val contactBuffer = messageBuffer[contactId] ?: return

        // Get current expected sequence number
        val keyChain = KeyChainManager.getKeyChain(context, contactId) ?: return
        val expectedSeq = keyChain.receiveCounter

        // Check if we have the next sequential message buffered
        val buffered = contactBuffer.remove(expectedSeq) ?: return

        Log.d(TAG, "Processing buffered message seq=$expectedSeq (buffer size: ${contactBuffer.size})")

        // Recursively process this buffered message
        try {
            val result = receiveMessage(
                encryptedData = buffered.encryptedData,
                senderPublicKey = buffered.senderPublicKey,
                senderOnionAddress = buffered.senderOnionAddress,
                messageType = buffered.messageType,
                voiceDuration = buffered.voiceDuration,
                selfDestructAt = buffered.selfDestructAt,
                requiresReadReceipt = buffered.requiresReadReceipt,
                pingId = buffered.pingId
            )

            if (result.isSuccess) {
                Log.d(TAG, "Buffered message seq=$expectedSeq processed successfully")
                // processBufferedMessages will be called recursively from receiveMessage
            } else {
                Log.w(TAG, "Failed to process buffered message seq=$expectedSeq: ${result.exceptionOrNull()?.message}")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing buffered message seq=$expectedSeq", e)
        }

        // Clean up empty buffers
        if (contactBuffer.isEmpty()) {
            messageBuffer.remove(contactId)
        }
    }

    /**
     * Send PONG_ACK with bounded retry (similar to AckWorker pattern)
     * This is called asynchronously to avoid blocking message sending
     *
     * @return true if PONG_ACK was successfully sent, false if all retries failed
     */
    private suspend fun sendPongAckWithRetry(
        itemId: String,
        contact: com.securelegion.database.entities.Contact,
        maxRetries: Int = 3
    ): Boolean {
        repeat(maxRetries) { attempt ->
            try {
                val success = com.securelegion.crypto.RustBridge.sendDeliveryAck(
                    itemId = itemId,
                    ackType = "PONG_ACK",
                    recipientEd25519Pubkey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP),
                    recipientX25519Pubkey = android.util.Base64.decode(contact.x25519PublicKeyBase64, android.util.Base64.NO_WRAP),
                    recipientOnion = contact.messagingOnion ?: contact.torOnionAddress ?: ""
                )

                if (success) {
                    Log.i(TAG, "Sent PONG_ACK for itemId=${itemId.take(8)}...")
                    return true
                }

                if (attempt < maxRetries - 1) {
                    kotlinx.coroutines.delay(1000L * (attempt + 1))
                }

            } catch (e: Exception) {
                Log.e(TAG, "Exception sending PONG_ACK (attempt ${attempt + 1}/$maxRetries): ${e.message}")
                if (attempt < maxRetries - 1) {
                    kotlinx.coroutines.delay(1000L * (attempt + 1))
                }
            }
        }

        return false
    }

    /**
     * Send message blob after PONG_ACK has been confirmed
     * This is extracted as a helper to keep the main loop clean
     *
     * @param message The message to send
     * @param contact The recipient contact
     * @param pingId The ping ID (for session cleanup)
     */
    private suspend fun sendMessageBlobAfterPongAck(
        message: com.securelegion.database.entities.Message,
        contact: com.securelegion.database.entities.Contact,
        pingId: String
    ) {
        try {
            // Quick gate check for blob send — message already ACKd, best-effort delivery
            Log.d(TAG, "Waiting for transport gate before sending message blob...")
            TorService.getTransportGate()?.awaitOpen(com.securelegion.network.TransportGate.TIMEOUT_QUICK_MS)
            Log.d(TAG, "Transport gate check done - proceeding with message blob send")

            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Get stored encrypted payload
            val encryptedPayload = message.encryptedPayload
            if (encryptedPayload == null) {
                Log.e(TAG, "No encrypted payload stored for message ${message.id}")
                return
            }

            // Decode Base64 payload
            val encryptedBytes = android.util.Base64.decode(encryptedPayload, android.util.Base64.NO_WRAP)

            // Convert message type to wire protocol type byte
            val messageTypeByte: Byte = when (message.messageType) {
                com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE -> 0x04.toByte() // VOICE
                com.securelegion.database.entities.Message.MESSAGE_TYPE_IMAGE -> 0x09.toByte() // IMAGE
                com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_REQUEST -> 0x0A.toByte() // PAYMENT_REQUEST
                com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_SENT -> 0x0B.toByte() // PAYMENT_SENT
                com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_ACCEPTED -> 0x0C.toByte() // PAYMENT_ACCEPTED
                com.securelegion.database.entities.Message.MESSAGE_TYPE_PROFILE_UPDATE -> 0x0F.toByte() // PROFILE_UPDATE
                else -> 0x03.toByte() // TEXT (default)
            }

            // Send message blob
            val success = try {
                com.securelegion.crypto.RustBridge.sendMessageBlob(
                    contact.messagingOnion ?: contact.torOnionAddress ?: "",
                    encryptedBytes,
                    messageTypeByte
                )
            } catch (e: Exception) {
                Log.e(TAG, "sendMessageBlob threw exception", e)
                false
            } finally {
                // CRITICAL: ALWAYS clean up Pong session (success OR failure)
                // This prevents session leaks that cause all future messages to fail
                try {
                    com.securelegion.crypto.RustBridge.removePongSession(pingId)
                    Log.d(TAG, "Cleaned up Rust Pong session for pingId=${pingId.take(8)}...")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to clean up Pong session (non-critical)", e)
                }
            }

            if (success) {
                // Update message status to SENT
                database.messageDao().updateMessageStatus(message.id, com.securelegion.database.entities.Message.STATUS_SENT)
                Log.i(TAG, "Message blob sent successfully: ${message.messageId}")
            } else {
                Log.e(TAG, "Failed to send message blob for ${message.messageId}")

                // IMPORTANT: Mark as FAILED so UI shows accurate state and resend can work
                database.messageDao().updateMessageStatus(message.id, com.securelegion.database.entities.Message.STATUS_FAILED)

                // CRITICAL: Use partial update to avoid overwriting delivery status
                // (fixes race where MESSAGE_ACK sets delivered=true between read and write)
                database.messageDao().updateRetryState(
                    message.id,
                    message.retryCount + 1,
                    System.currentTimeMillis()
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error sending message blob after PONG_ACK: ${e.message}", e)
        }
    }
}
