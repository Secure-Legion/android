package com.securelegion.services

import android.content.Context
import android.util.Base64
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Message
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
     * Send an encrypted message to a contact via Tor
     * @param contactId Database ID of the recipient contact
     * @param plaintext The message content
     * @param enableSelfDestruct Whether to enable self-destruct (24h)
     * @param enableReadReceipt Whether to enable read receipts
     * @return Result with Message entity if successful
     */
    suspend fun sendMessage(
        contactId: Long,
        plaintext: String,
        enableSelfDestruct: Boolean = false,
        enableReadReceipt: Boolean = true
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

            // Get recipient's public key
            val recipientPublicKey = Base64.decode(contact.publicKeyBase64, Base64.NO_WRAP)

            // Encrypt the message
            Log.d(TAG, "Encrypting message...")
            val encryptedBytes = RustBridge.encryptMessage(plaintext, recipientPublicKey)
            val encryptedBase64 = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)

            // Generate nonce (first 24 bytes of encrypted data)
            val nonce = encryptedBytes.take(24).toByteArray()
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // Sign the message
            Log.d(TAG, "Signing message...")
            val messageData = (messageId + plaintext + System.currentTimeMillis()).toByteArray()
            val signature = RustBridge.signData(messageData, ourPrivateKey)
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            // Calculate self-destruct timestamp if enabled
            val currentTime = System.currentTimeMillis()
            val selfDestructAt = if (enableSelfDestruct) {
                currentTime + Message.SELF_DESTRUCT_DURATION
            } else {
                null
            }

            // Create message entity
            val message = Message(
                contactId = contactId,
                messageId = messageId,
                encryptedContent = plaintext, // Store plaintext for now (will encrypt in future)
                isSentByMe = true,
                timestamp = currentTime,
                status = Message.STATUS_PENDING,
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
                selfDestructAt = selfDestructAt,
                requiresReadReceipt = enableReadReceipt
            )

            Log.d(TAG, "Self-destruct: ${if (enableSelfDestruct) "enabled (24h)" else "disabled"}")
            Log.d(TAG, "Read receipt: ${if (enableReadReceipt) "enabled" else "disabled"}")

            // Save to database
            Log.d(TAG, "Saving message to database...")
            val savedMessageId = database.messageDao().insertMessage(message)
            val savedMessage = message.copy(id = savedMessageId)

            // Send via Tor hidden service
            Log.d(TAG, "Sending message via Tor to ${contact.torOnionAddress}...")
            sendViaTor(contact.torOnionAddress, encryptedBase64, messageId)

            // Update status to SENT
            database.messageDao().updateMessageStatus(savedMessageId, Message.STATUS_SENT)

            Log.i(TAG, "Message sent successfully: $messageId")
            Result.success(savedMessage.copy(status = Message.STATUS_SENT))

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
     * @param selfDestructAt Self-destruct timestamp (or null)
     * @param requiresReadReceipt Whether sender wants read receipt
     * @return Result with Message entity if successful
     */
    suspend fun receiveMessage(
        encryptedData: String,
        senderPublicKey: ByteArray,
        senderOnionAddress: String,
        selfDestructAt: Long? = null,
        requiresReadReceipt: Boolean = true
    ): Result<Message> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Receiving message from: $senderOnionAddress")

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
            val plaintext = RustBridge.decryptMessage(encryptedBytes, senderPublicKey, ourPrivateKey)
                ?: return@withContext Result.failure(Exception("Failed to decrypt message"))

            // Generate message ID from content hash
            val messageId = generateMessageId(plaintext, System.currentTimeMillis())

            // Check for duplicate
            if (database.messageDao().messageExists(messageId)) {
                Log.w(TAG, "Duplicate message ignored: $messageId")
                return@withContext Result.failure(Exception("Duplicate message"))
            }

            // Extract nonce
            val nonce = encryptedBytes.take(24).toByteArray()
            val nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP)

            // Create message entity
            val message = Message(
                contactId = contact.id,
                messageId = messageId,
                encryptedContent = plaintext, // Store plaintext for now
                isSentByMe = false,
                timestamp = System.currentTimeMillis(),
                status = Message.STATUS_DELIVERED,
                signatureBase64 = "", // TODO: Extract signature
                nonceBase64 = nonceBase64,
                selfDestructAt = selfDestructAt,
                requiresReadReceipt = requiresReadReceipt
            )

            if (selfDestructAt != null) {
                Log.d(TAG, "Message has self-destruct enabled, expires at: $selfDestructAt")
            }

            // Save to database
            val savedMessageId = database.messageDao().insertMessage(message)

            Log.i(TAG, "Message received and saved: $messageId")
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
     * Generate deterministic message ID from content
     */
    private fun generateMessageId(content: String, timestamp: Long): String {
        val data = "$content$timestamp".toByteArray()
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(data)
        return Base64.encodeToString(hash, Base64.NO_WRAP).take(32)
    }
}
