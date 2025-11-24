package com.securelegion.services

import android.content.Context
import android.util.Base64
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Message
import com.securelegion.workers.ImmediateRetryWorker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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

            // Generate unique message ID
            val messageId = UUID.randomUUID().toString()

            // Get our keypair for signing
            val ourPublicKey = keyManager.getSigningPublicKey()
            val ourPrivateKey = keyManager.getSigningKeyBytes()

            // Get recipient's X25519 public key (for encryption)
            val recipientX25519PublicKey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)

            // Encrypt the audio bytes
            Log.d(TAG, "Encrypting voice message...")
            Log.d(TAG, "  Audio bytes: ${audioBytes.size} bytes")
            Log.d(TAG, "  Duration: ${durationSeconds}s")

            val encryptedBytes = RustBridge.encryptMessage(
                String(audioBytes, Charsets.ISO_8859_1), // Convert bytes to string for encryption
                recipientX25519PublicKey
            )
            Log.d(TAG, "  Encrypted: ${encryptedBytes.size} bytes")

            // Prepend message type byte: 0x01 for VOICE, followed by duration (4 bytes, big-endian)
            val durationBytes = ByteArray(4)
            durationBytes[0] = (durationSeconds shr 24).toByte()
            durationBytes[1] = (durationSeconds shr 16).toByte()
            durationBytes[2] = (durationSeconds shr 8).toByte()
            durationBytes[3] = durationSeconds.toByte()
            val encryptedWithMetadata = byteArrayOf(0x01) + durationBytes + encryptedBytes
            val encryptedBase64 = Base64.encodeToString(encryptedWithMetadata, Base64.NO_WRAP)

            Log.d(TAG, "  Metadata: 1 byte type + 4 bytes duration")
            Log.d(TAG, "  Total payload: ${encryptedWithMetadata.size} bytes (${encryptedBase64.length} Base64 chars)")

            // Generate nonce (first 24 bytes of encrypted data)
            val nonce = encryptedBytes.take(24).toByteArray()
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

            // Generate Ping ID for persistent messaging
            val pingId = UUID.randomUUID().toString()
            Log.d(TAG, "Generated Ping ID: $pingId")

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
                status = Message.STATUS_PING_SENT,
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
                selfDestructAt = selfDestructAt,
                requiresReadReceipt = false, // Voice messages don't need read receipts
                pingId = pingId,
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
                sendPingForMessage(savedMessage)
                Log.d(TAG, "Ping sent immediately, will poll for Pong later")
            } catch (e: Exception) {
                Log.w(TAG, "Immediate Ping send failed, retry worker will retry: ${e.message}")
            }

            // Schedule fast retry worker for this message (5s intervals)
            ImmediateRetryWorker.scheduleForMessage(context, messageId)
            Log.d(TAG, "Scheduled immediate retry worker for message $messageId")

            Result.success(savedMessage)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send voice message", e)
            Result.failure(e)
        }
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

            // Generate unique message ID
            val messageId = UUID.randomUUID().toString()

            // Get our keypair for signing
            val ourPublicKey = keyManager.getSigningPublicKey()
            val ourPrivateKey = keyManager.getSigningKeyBytes()

            // Get recipient's X25519 public key (for encryption)
            val recipientX25519PublicKey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)

            // Encrypt the message
            Log.d(TAG, "Encrypting message...")
            val encryptedBytes = RustBridge.encryptMessage(plaintext, recipientX25519PublicKey)

            // NOTE: Type byte is added by android.rs sendPing(), not here
            // encryptedBytes format: [Our X25519 Public Key - 32 bytes][Encrypted Message]
            val encryptedBase64 = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)

            // Generate nonce (first 24 bytes of encrypted data)
            val nonce = encryptedBytes.take(24).toByteArray()
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // Sign the message
            Log.d(TAG, "Signing message...")
            val messageData = (messageId + plaintext + System.currentTimeMillis()).toByteArray()
            val signature = RustBridge.signData(messageData, ourPrivateKey)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            // Calculate self-destruct timestamp if custom duration provided
            val currentTime = System.currentTimeMillis()
            val selfDestructAt = selfDestructDurationMs?.let { currentTime + it }

            // Generate Ping ID for persistent messaging
            val pingId = UUID.randomUUID().toString()
            Log.d(TAG, "Generated Ping ID: $pingId")

            // Create message entity with PING_SENT status for persistent queue
            val message = Message(
                contactId = contactId,
                messageId = messageId,
                encryptedContent = plaintext, // Store plaintext for now (will encrypt in future)
                isSentByMe = true,
                timestamp = currentTime,
                status = Message.STATUS_PING_SENT, // Changed: Start as PING_SENT, not PENDING
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
                selfDestructAt = selfDestructAt,
                requiresReadReceipt = enableReadReceipt,
                pingId = pingId,                    // NEW: Store Ping ID for matching Pongs
                encryptedPayload = encryptedBase64, // NEW: Store encrypted payload to send after Pong
                retryCount = 0,                     // NEW: Initialize retry counter
                lastRetryTimestamp = currentTime   // NEW: Track when we last attempted
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
                sendPingForMessage(savedMessage)
                Log.d(TAG, "Ping sent immediately, will poll for Pong later")
            } catch (e: Exception) {
                // Silent failure - retry worker will handle it
                Log.w(TAG, "Immediate Ping send failed, retry worker will retry: ${e.message}")
            }

            // Schedule fast retry worker for this message (5s intervals)
            ImmediateRetryWorker.scheduleForMessage(context, messageId)
            Log.d(TAG, "Scheduled immediate retry worker for message $messageId")

            Result.success(savedMessage)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send message", e)
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

            // Get database instance
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Find contact by Tor address
            val contact = database.contactDao().getContactByOnionAddress(senderOnionAddress)
                ?: return@withContext Result.failure(Exception("Unknown sender: $senderOnionAddress"))

            Log.d(TAG, "Message from: ${contact.displayName}")

            // Decrypt message
            val encryptedBytes = Base64.decode(encryptedData, Base64.NO_WRAP)
            val ourPrivateKey = keyManager.getSigningKeyBytes()
            val decryptedData = RustBridge.decryptMessage(encryptedBytes, senderPublicKey, ourPrivateKey)
                ?: return@withContext Result.failure(Exception("Failed to decrypt message"))

            // Extract nonce
            val nonce = encryptedBytes.take(24).toByteArray()
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // Handle based on message type
            val message = if (messageType == Message.MESSAGE_TYPE_VOICE) {
                // Voice message: decryptedData is audio bytes
                val audioBytes = decryptedData.toByteArray(Charsets.ISO_8859_1)

                // Save audio to local storage
                val voiceRecorder = com.securelegion.utils.VoiceRecorder(context)
                val voiceFilePath = voiceRecorder.saveVoiceMessage(audioBytes, voiceDuration ?: 0)

                // Generate message ID from voice file hash + sender (for deduplication)
                // NOTE: Don't use nonce - each retry has a new nonce but same content
                val messageId = generateMessageId(android.util.Base64.encodeToString(audioBytes, android.util.Base64.NO_WRAP), senderOnionAddress)

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
                    selfDestructAt = selfDestructAt,
                    requiresReadReceipt = requiresReadReceipt,
                    pingId = pingId
                )
            } else {
                // Text message
                val plaintext = decryptedData

                // Generate message ID from content + sender (for deduplication)
                // NOTE: Don't use nonce - each retry has a new nonce but same content
                val messageId = generateMessageId(plaintext, senderOnionAddress)

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
                    selfDestructAt = selfDestructAt,
                    requiresReadReceipt = requiresReadReceipt,
                    pingId = pingId
                )
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
            Result.success(message.copy(id = savedMessageId))

        } catch (e: Exception) {
            Log.e(TAG, "Failed to receive message", e)
            Result.failure(e)
        }
    }

    /**
     * Load all messages for a contact
     */
    suspend fun getMessagesForContact(contactId: Long): List<Message> = withContext(Dispatchers.IO) {
        try {
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)
            database.messageDao().getMessagesForContact(contactId)
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
                Log.d(TAG, "Sending to Tor hidden service: $onionAddress")
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
                Message.MESSAGE_TYPE_VOICE -> 0x04.toByte()  // VOICE
                else -> 0x03.toByte()                         // TEXT (default)
            }
            Log.d(TAG, "Message type: ${message.messageType} → wire byte: 0x${messageTypeByte.toString(16).padStart(2, '0')}")

            // Send Ping via Rust bridge (with message for instant mode)
            Log.d(TAG, "Calling RustBridge.sendPing to ${contact.torOnionAddress}...")
            val pingResponse = RustBridge.sendPing(
                recipientEd25519PubKey,
                recipientX25519PubKey,
                contact.torOnionAddress,
                encryptedBytes,
                messageTypeByte
            )

            // Parse JSON response: {"pingId":"...","wireBytes":"..."}
            val pingId: String
            val wireBytes: String
            try {
                val json = org.json.JSONObject(pingResponse)
                pingId = json.getString("pingId")
                wireBytes = json.getString("wireBytes")
                Log.i(TAG, "✓ RustBridge.sendPing returned Ping ID: $pingId (wire bytes stored for retry)")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse sendPing response JSON", e)
                return@withContext Result.failure(e)
            }

            Log.d(TAG, "Original message Ping ID (UUID): ${message.pingId}")
            Log.d(TAG, "Rust-returned Ping ID (hex nonce): $pingId")

            // Update message with the ACTUAL Ping ID and wire bytes from Rust
            // CRITICAL: Use NonCancellable to ensure database update completes even if job is cancelled
            if (pingId != message.pingId || message.pingWireBytes == null) {
                if (pingId != message.pingId) {
                    Log.w(TAG, "⚠️  PING ID MISMATCH DETECTED!")
                    Log.w(TAG, "   Database has: ${message.pingId}")
                    Log.w(TAG, "   Rust returned: $pingId")
                }
                Log.i(TAG, "Updating database with Ping ID and wire bytes from Rust...")

                withContext(kotlinx.coroutines.NonCancellable) {
                    val updatedMessage = message.copy(pingId = pingId, pingWireBytes = wireBytes)
                    database.messageDao().updateMessage(updatedMessage)
                    Log.i(TAG, "✓ Database updated with Ping ID: $pingId and wire bytes (waiting for PING_ACK)")
                }
            }

            // CRITICAL FIX: Save outgoing Ping to SharedPreferences so Pong can be matched!
            // Without this, incoming Pongs fail with "No contact_id found" error
            // KEY FORMAT: ping_<PING_ID>_contact_id (indexed by Ping ID for Pong lookup)
            withContext(kotlinx.coroutines.NonCancellable) {
                val prefs = context.getSharedPreferences("pending_pings", Context.MODE_PRIVATE)
                prefs.edit().apply {
                    // PONG LOOKUP FORMAT: Indexed by ping_id (not contact_id!)
                    putString("ping_${pingId}_contact_id", contact.id.toString())
                    putString("ping_${pingId}_name", contact.displayName)
                    putLong("ping_${pingId}_timestamp", System.currentTimeMillis())
                    putString("ping_${pingId}_onion", contact.torOnionAddress)

                    // ALSO save in contact-indexed format for OUTGOING tracking (use different prefix to avoid UI confusion)
                    putString("outgoing_ping_${contact.id}_id", pingId)
                    putString("outgoing_ping_${contact.id}_name", contact.displayName)
                    putLong("outgoing_ping_${contact.id}_timestamp", System.currentTimeMillis())
                    putString("outgoing_ping_${contact.id}_onion", contact.torOnionAddress)
                    apply()
                }
                Log.i(TAG, "✓ Saved outgoing Ping to SharedPreferences (both formats): contact_id=${contact.id}, ping_id=$pingId")
            }

            Log.i(TAG, "✓ Ping sent successfully: $pingId (waiting for PING_ACK from receiver)")
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
                    Log.i(TAG, "✓ Pong received for Ping ID $pingId! Sending message blob...")

                    // Get contact for .onion address
                    val contact = database.contactDao().getContactById(message.contactId)
                    if (contact == null) {
                        Log.e(TAG, "Contact not found for message ${message.id}")
                        continue
                    }

                    // Get stored encrypted payload
                    val encryptedPayload = message.encryptedPayload
                    if (encryptedPayload == null) {
                        Log.e(TAG, "No encrypted payload stored for message ${message.id}")
                        continue
                    }

                    // Decode Base64 payload
                    val encryptedBytes = Base64.decode(encryptedPayload, Base64.NO_WRAP)

                    // Convert message type to wire protocol type byte
                    val messageTypeByte: Byte = when (message.messageType) {
                        Message.MESSAGE_TYPE_VOICE -> 0x04.toByte()  // VOICE
                        else -> 0x03.toByte()                         // TEXT (default)
                    }

                    // Send message blob
                    val success = RustBridge.sendMessageBlob(
                        contact.torOnionAddress,
                        encryptedBytes,
                        messageTypeByte
                    )

                    if (success) {
                        // Update message status to SENT
                        database.messageDao().updateMessageStatus(message.id, Message.STATUS_SENT)
                        Log.i(TAG, "Message blob sent successfully: ${message.messageId}")

                        // Clean up Rust Pong session immediately to prevent memory leak
                        try {
                            RustBridge.removePongSession(pingId)
                            Log.d(TAG, "✓ Cleaned up Rust Pong session for pingId: $pingId")
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to clean up Pong session (non-critical)", e)
                        }

                        // Cancel immediate retry worker (message sent successfully)
                        ImmediateRetryWorker.cancelForMessage(context, message.messageId)
                        Log.d(TAG, "Cancelled immediate retry worker for ${message.messageId}")

                        sentCount++
                    } else {
                        Log.e(TAG, "Failed to send message blob for ${message.messageId}")
                        // Increment retry counter
                        val updatedMessage = message.copy(
                            retryCount = message.retryCount + 1,
                            lastRetryTimestamp = System.currentTimeMillis()
                        )
                        database.messageDao().updateMessage(updatedMessage)
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
}
