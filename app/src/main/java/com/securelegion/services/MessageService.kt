package com.securelegion.services

import android.content.Context
import android.content.Intent
import android.util.Base64
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.NLx402Manager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Message
import com.securelegion.database.entities.ed25519PublicKeyBytes
import com.securelegion.database.entities.x25519PublicKeyBytes
import com.securelegion.voice.CallSignaling
import com.securelegion.voice.VoiceCallManager
import com.securelegion.IncomingCallActivity
import com.securelegion.workers.ImmediateRetryWorker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
         * Generate a cryptographically random 24-byte nonce for ping ID
         * Returns hex-encoded string (48 characters)
         * This matches the format Rust PingToken expects
         */
        fun generatePingId(): String {
            val nonce = ByteArray(24)
            java.security.SecureRandom().nextBytes(nonce)
            return nonce.joinToString("") { "%02x".format(it) }
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

            // Generate Ping ID and timestamp ONCE (never changes, prevents ghost pings)
            val pingId = generatePingId()  // 24-byte nonce as hex string
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
                status = Message.STATUS_PING_SENT,
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
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

            // Generate unique message ID
            val messageId = UUID.randomUUID().toString()

            // Get our keypair for signing
            val ourPublicKey = keyManager.getSigningPublicKey()
            val ourPrivateKey = keyManager.getSigningKeyBytes()

            // Get recipient's X25519 public key (for encryption)
            val recipientX25519PublicKey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)

            // Encrypt the image bytes
            Log.d(TAG, "Encrypting image message...")
            val imageBytes = Base64.decode(imageBase64, Base64.NO_WRAP)
            Log.d(TAG, "  Image bytes: ${imageBytes.size} bytes")

            val encryptedBytes = RustBridge.encryptMessage(
                String(imageBytes, Charsets.ISO_8859_1), // Convert bytes to string for encryption
                recipientX25519PublicKey
            )
            Log.d(TAG, "  Encrypted: ${encryptedBytes.size} bytes")

            // Prepend metadata byte (0x02 = IMAGE) AFTER encryption (like VOICE messages)
            val encryptedWithMetadata = byteArrayOf(0x02.toByte()) + encryptedBytes
            Log.d(TAG, "  Total with metadata: ${encryptedWithMetadata.size} bytes (prepended 0x02)")

            // NOTE: Type byte (0x09) is added by android.rs sendPing(), not here
            // encryptedWithMetadata format: [0x02][Our X25519 Public Key - 32 bytes][Encrypted Message]
            val encryptedBase64 = Base64.encodeToString(encryptedWithMetadata, Base64.NO_WRAP)

            Log.d(TAG, "  Total payload: ${encryptedBytes.size} bytes (${encryptedBase64.length} Base64 chars)")

            // Generate nonce (first 24 bytes of encrypted data)
            val nonce = encryptedBytes.take(24).toByteArray()
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
            val pingId = generatePingId()  // 24-byte nonce as hex string
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
                status = Message.STATUS_PING_SENT,
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
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
            Log.e(TAG, "Failed to send image message", e)
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

            // Generate Ping ID and timestamp ONCE (never changes, prevents ghost pings)
            val pingId = generatePingId()  // 24-byte nonce as hex string
            val pingTimestamp = currentTime
            Log.d(TAG, "Generated Ping ID: ${pingId.take(16)}... (timestamp: $pingTimestamp)")

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
                pingId = pingId,                    // Generated ONCE, used for all retries
                pingTimestamp = pingTimestamp,      // Generated ONCE with pingId
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
            Log.i(TAG, "╔════════════════════════════════════════")
            Log.i(TAG, "║ MessageService.sendPaymentRequest()")
            Log.i(TAG, "║ Contact ID: $contactId")
            Log.i(TAG, "║ Quote ID: ${quote.quoteId}")
            Log.i(TAG, "║ Amount: ${quote.formattedAmount}")
            Log.i(TAG, "╚════════════════════════════════════════")

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

            // Get recipient's X25519 public key (for encryption)
            val recipientX25519PublicKey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)

            // Create the payment request payload (JSON with quote)
            val paymentRequestPayload = """{"type":"PAYMENT_REQUEST","quote":${quote.rawJson}}"""

            // Encrypt the payment request
            Log.d(TAG, "Encrypting payment request...")
            val encryptedBytes = RustBridge.encryptMessage(paymentRequestPayload, recipientX25519PublicKey)

            // Prepend metadata byte (0x0A = PAYMENT_REQUEST) so receiver can identify message type
            // This is similar to how VOICE messages prepend 0x01 + duration
            val payloadWithMetadata = ByteArray(1 + encryptedBytes.size)
            payloadWithMetadata[0] = 0x0A.toByte() // PAYMENT_REQUEST type
            System.arraycopy(encryptedBytes, 0, payloadWithMetadata, 1, encryptedBytes.size)
            val encryptedBase64 = Base64.encodeToString(payloadWithMetadata, Base64.NO_WRAP)

            Log.d(TAG, "Payment request encrypted: ${encryptedBytes.size} bytes")

            // Generate nonce (first 24 bytes of encrypted data)
            val nonce = encryptedBytes.take(24).toByteArray()
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // Sign the message
            Log.d(TAG, "Signing payment request...")
            val messageData = (messageId + quote.rawJson + System.currentTimeMillis()).toByteArray()
            val signature = RustBridge.signData(messageData, ourPrivateKey)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            val currentTime = System.currentTimeMillis()

            // Generate Ping ID for persistent messaging
            val pingId = generatePingId()  // 24-byte nonce as hex string
            val pingTimestamp = currentTime
            Log.d(TAG, "Generated Ping ID for payment request: $pingId")

            // Create message entity with PAYMENT_REQUEST type
            val message = Message(
                contactId = contactId,
                messageId = messageId,
                encryptedContent = "Payment Request: ${quote.formattedAmount}", // Display text
                messageType = Message.MESSAGE_TYPE_PAYMENT_REQUEST,
                isSentByMe = true,
                timestamp = currentTime,
                status = Message.STATUS_PING_SENT,
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
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
                sendPingForMessage(savedMessage)
                Log.d(TAG, "Ping sent immediately, will poll for Pong later")
            } catch (e: Exception) {
                Log.w(TAG, "Immediate Ping send failed, retry worker will retry: ${e.message}")
            }

            // Schedule fast retry worker for this message (5s intervals)
            ImmediateRetryWorker.scheduleForMessage(context, messageId)
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

            // Get recipient's X25519 public key (for encryption)
            val recipientX25519PublicKey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)

            // Create the payment confirmation payload
            val paymentConfirmPayload = """{"type":"PAYMENT_SENT","quote_id":"${originalQuote.quoteId}","tx_signature":"$txSignature","amount":${originalQuote.amount},"token":"${originalQuote.token}"}"""

            // Encrypt the payment confirmation
            Log.d(TAG, "Encrypting payment confirmation...")
            val encryptedBytes = RustBridge.encryptMessage(paymentConfirmPayload, recipientX25519PublicKey)

            // Prepend metadata byte (0x0B = PAYMENT_SENT) so receiver can identify message type
            val payloadWithMetadata = ByteArray(1 + encryptedBytes.size)
            payloadWithMetadata[0] = 0x0B.toByte() // PAYMENT_SENT type
            System.arraycopy(encryptedBytes, 0, payloadWithMetadata, 1, encryptedBytes.size)
            val encryptedBase64 = Base64.encodeToString(payloadWithMetadata, Base64.NO_WRAP)

            // Generate nonce
            val nonce = encryptedBytes.take(24).toByteArray()
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // Sign the message
            val messageData = (messageId + txSignature + System.currentTimeMillis()).toByteArray()
            val signature = RustBridge.signData(messageData, ourPrivateKey)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            val currentTime = System.currentTimeMillis()
            val pingId = generatePingId()  // 24-byte nonce as hex string
            val pingTimestamp = currentTime

            // Create message entity with PAYMENT_SENT type
            val message = Message(
                contactId = contactId,
                messageId = messageId,
                encryptedContent = "Paid: ${originalQuote.formattedAmount}", // Display text
                messageType = Message.MESSAGE_TYPE_PAYMENT_SENT,
                isSentByMe = true,
                timestamp = currentTime,
                status = Message.STATUS_PING_SENT,
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
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
            ImmediateRetryWorker.scheduleForMessage(context, messageId)

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

            val messageId = "pay_accept_${originalQuote.quoteId}_${System.currentTimeMillis()}"

            val ourPrivateKey = keyManager.getSigningKeyBytes()
            val recipientX25519PublicKey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)

            // Create the payment acceptance payload with receive address
            val paymentAcceptPayload = """{"type":"PAYMENT_ACCEPTED","quote_id":"${originalQuote.quoteId}","receive_address":"$receiveAddress","amount":${originalQuote.amount},"token":"${originalQuote.token}"}"""

            Log.d(TAG, "Encrypting payment acceptance...")
            val encryptedBytes = RustBridge.encryptMessage(paymentAcceptPayload, recipientX25519PublicKey)

            // Prepend metadata byte (0x0C = PAYMENT_ACCEPTED) so receiver can identify message type
            val payloadWithMetadata = ByteArray(1 + encryptedBytes.size)
            payloadWithMetadata[0] = 0x0C.toByte() // PAYMENT_ACCEPTED type
            System.arraycopy(encryptedBytes, 0, payloadWithMetadata, 1, encryptedBytes.size)
            val encryptedBase64 = Base64.encodeToString(payloadWithMetadata, Base64.NO_WRAP)

            val nonce = encryptedBytes.take(24).toByteArray()
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            val messageData = (messageId + receiveAddress + System.currentTimeMillis()).toByteArray()
            val signature = RustBridge.signData(messageData, ourPrivateKey)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            val currentTime = System.currentTimeMillis()
            val pingId = generatePingId()  // 24-byte nonce as hex string
            val pingTimestamp = currentTime

            val message = Message(
                contactId = contactId,
                messageId = messageId,
                encryptedContent = "Payment accepted: ${originalQuote.formattedAmount}",
                messageType = Message.MESSAGE_TYPE_PAYMENT_ACCEPTED,
                isSentByMe = true,
                timestamp = currentTime,
                status = Message.STATUS_PING_SENT,
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
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

            ImmediateRetryWorker.scheduleForMessage(context, messageId)

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
            val message = when (messageType) {
                Message.MESSAGE_TYPE_VOICE -> {
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
                }
                Message.MESSAGE_TYPE_IMAGE -> {
                    // Image message: decryptedData is image bytes
                    val imageBytes = decryptedData.toByteArray(Charsets.ISO_8859_1)
                    val imageBase64 = Base64.encodeToString(imageBytes, Base64.NO_WRAP)

                    // Generate message ID from image hash + sender (for deduplication)
                    val messageId = generateMessageId(imageBase64, senderOnionAddress)

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
                        selfDestructAt = selfDestructAt,
                        requiresReadReceipt = requiresReadReceipt,
                        pingId = pingId
                    )
                }
                else -> {
                    // Text message (default)
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
            Log.d(TAG, "🔍 handleCallSignaling: Checking if message is call signaling...")
            // Decrypt message to check if it's call signaling
            // Call signaling uses X25519 encryption keys (not Ed25519 signing keys)
            val encryptedBytes = Base64.decode(encryptedData, Base64.NO_WRAP)
            Log.d(TAG, "🔍 handleCallSignaling: Encrypted bytes size: ${encryptedBytes.size}")

            val ourPrivateKey = keyManager.getEncryptionKeyBytes()
            val decryptedData = RustBridge.decryptMessage(encryptedBytes, senderPublicKey, ourPrivateKey)

            if (decryptedData == null) {
                Log.w(TAG, "🔍 handleCallSignaling: Decryption FAILED - not call signaling")
                return@withContext false
            }

            Log.d(TAG, "🔍 handleCallSignaling: Decryption successful, data: ${decryptedData.take(100)}...")

            // Try to parse as call signaling message
            val callMessage = CallSignaling.parseCallMessage(decryptedData)

            if (callMessage == null) {
                Log.w(TAG, "🔍 handleCallSignaling: Parse FAILED - not call signaling JSON")
                return@withContext false
            }

            Log.i(TAG, "✅ handleCallSignaling: Received call signaling message: ${callMessage.javaClass.simpleName}")

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
                Log.d(TAG, "  - [${msg.messageType}] ${msg.encryptedContent.take(30)}... (id=${msg.id}, status=${msg.status})")
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
                Message.MESSAGE_TYPE_VOICE -> 0x04.toByte()           // VOICE
                Message.MESSAGE_TYPE_IMAGE -> 0x09.toByte()           // IMAGE
                Message.MESSAGE_TYPE_PAYMENT_REQUEST -> 0x0A.toByte() // PAYMENT_REQUEST
                Message.MESSAGE_TYPE_PAYMENT_SENT -> 0x0B.toByte()    // PAYMENT_SENT
                Message.MESSAGE_TYPE_PAYMENT_ACCEPTED -> 0x0C.toByte() // PAYMENT_ACCEPTED
                else -> 0x03.toByte()                                  // TEXT (default)
            }
            Log.d(TAG, "Message type: ${message.messageType} → wire byte: 0x${messageTypeByte.toString(16).padStart(2, '0')}")

            // Send Ping via Rust bridge (with message for instant mode)
            Log.d(TAG, "Contact ${contact.displayName} .onion addresses:")
            Log.d(TAG, "  messagingOnion: ${contact.messagingOnion}")
            Log.d(TAG, "  friendRequestOnion: ${contact.friendRequestOnion}")
            Log.d(TAG, "  torOnionAddress (deprecated): ${contact.torOnionAddress}")
            val onionAddress = contact.messagingOnion ?: contact.torOnionAddress ?: ""
            Log.d(TAG, "  → Selected for messaging: $onionAddress")

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
                    message.pingId!!,  // Generated once when message created
                    message.pingTimestamp!!  // Generated once when message created
                )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to send Ping", e)
                return@withContext Result.failure(e)
            }

            // Parse JSON response: {"pingId":"...","wireBytes":"..."}
            val pingId: String
            val wireBytes: String
            try {
                val json = org.json.JSONObject(pingResponse)
                pingId = json.getString("pingId")
                wireBytes = json.getString("wireBytes")
                Log.i(TAG, "✓ Ping sent successfully (ID: ${pingId.take(8)}...)")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to parse sendPing response JSON", e)
                return@withContext Result.failure(e)
            }

            // Store wire bytes for resendPingWithWireBytes (backup retry method)
            if (message.pingWireBytes == null) {
                withContext(kotlinx.coroutines.NonCancellable) {
                    val updatedMessage = message.copy(pingWireBytes = wireBytes)
                    database.messageDao().updateMessage(updatedMessage)
                    Log.d(TAG, "✓ Stored wire bytes for backup retry")
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
                        Message.MESSAGE_TYPE_VOICE -> 0x04.toByte()           // VOICE
                        Message.MESSAGE_TYPE_IMAGE -> 0x09.toByte()           // IMAGE
                        Message.MESSAGE_TYPE_PAYMENT_REQUEST -> 0x0A.toByte() // PAYMENT_REQUEST
                        Message.MESSAGE_TYPE_PAYMENT_SENT -> 0x0B.toByte()    // PAYMENT_SENT
                        Message.MESSAGE_TYPE_PAYMENT_ACCEPTED -> 0x0C.toByte() // PAYMENT_ACCEPTED
                        else -> 0x03.toByte()                                  // TEXT (default)
                    }

                    // Send message blob
                    val success = RustBridge.sendMessageBlob(
                        contact.messagingOnion ?: contact.torOnionAddress ?: "",
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
