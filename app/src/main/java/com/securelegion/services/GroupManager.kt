package com.securelegion.services

import android.content.Context
import android.util.Base64
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.Group
import com.securelegion.database.entities.GroupMember
import com.securelegion.database.entities.GroupMessage
import com.securelegion.database.entities.x25519PublicKeyBytes
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * GroupManager - Handles group messaging operations
 *
 * Features:
 * - Generate AES-256 group keys
 * - Encrypt group key for each member using X25519
 * - Create and manage groups
 * - Send messages to all group members
 * - Encrypt/decrypt group messages
 */
class GroupManager private constructor(private val context: Context) {

    companion object {
        private const val TAG = "GroupManager"

        @Volatile
        private var INSTANCE: GroupManager? = null

        fun getInstance(context: Context): GroupManager {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: GroupManager(context.applicationContext).also {
                    INSTANCE = it
                }
            }
        }
    }

    private val keyManager = KeyManager.getInstance(context)
    private val secureRandom = SecureRandom()

    /**
     * Generate a random AES-256 group key
     * @return 32-byte AES-256 key
     */
    fun generateGroupKey(): ByteArray {
        val groupKey = ByteArray(32) // 256 bits
        secureRandom.nextBytes(groupKey)
        Log.d(TAG, "Generated new AES-256 group key")
        return groupKey
    }

    /**
     * Encrypt the group key for a specific member using their X25519 public key
     * Uses XChaCha20-Poly1305 with X25519 ECDH
     * @param groupKey The 32-byte AES-256 group key
     * @param memberX25519PublicKey The member's X25519 public key (32 bytes)
     * @return Encrypted group key (Base64)
     */
    fun encryptGroupKeyForMember(groupKey: ByteArray, memberX25519PublicKey: ByteArray): String {
        // Convert group key to hex string for encryption
        val groupKeyHex = groupKey.joinToString("") { "%02x".format(it) }
        // Use RustBridge.encryptMessage with X25519 ECDH
        val encryptedWire = RustBridge.encryptMessage(groupKeyHex, memberX25519PublicKey)
        return Base64.encodeToString(encryptedWire, Base64.NO_WRAP)
    }

    /**
     * Decrypt a group key that was encrypted for us
     * @param encryptedGroupKeyBase64 Encrypted group key (Base64)
     * @param senderX25519PublicKey The public key of who encrypted it (not used, for API compat)
     * @return Decrypted 32-byte AES-256 group key
     */
    fun decryptGroupKey(encryptedGroupKeyBase64: String, senderX25519PublicKey: ByteArray): ByteArray {
        val wireMessage = Base64.decode(encryptedGroupKeyBase64, Base64.NO_WRAP)
        // RustBridge.decryptMessage extracts sender key from wire message
        val groupKeyHex = RustBridge.decryptMessage(wireMessage, senderX25519PublicKey, ByteArray(32))
            ?: throw Exception("Failed to decrypt group key")
        // Convert hex string back to bytes
        return groupKeyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    /**
     * Encrypt group key for local storage
     * Database is already encrypted with SQLCipher AES-256, so just Base64 encode
     * @param groupKey The 32-byte AES-256 group key
     * @return Encrypted group key (Base64) for database storage
     */
    fun encryptGroupKeyForStorage(groupKey: ByteArray): String {
        // Database is already encrypted with SQLCipher AES-256
        return Base64.encodeToString(groupKey, Base64.NO_WRAP)
    }

    /**
     * Decrypt group key from local storage
     * @param encryptedGroupKeyBase64 Encrypted group key from database
     * @return Decrypted 32-byte AES-256 group key
     */
    fun decryptGroupKeyFromStorage(encryptedGroupKeyBase64: String): ByteArray {
        // Database is already encrypted, just decode Base64
        return Base64.decode(encryptedGroupKeyBase64, Base64.NO_WRAP)
    }

    /**
     * Create a new group
     * @param groupName Name of the group
     * @param groupPin 6-digit PIN for group verification
     * @param members List of contacts to add as members
     * @param groupIcon Optional icon/emoji
     * @return Group ID
     */
    suspend fun createGroup(
        groupName: String,
        groupPin: String,
        members: List<Contact>,
        groupIcon: String? = null
    ): Result<String> {
        return try {
            // Step 1: Generate unique group ID
            val groupId = UUID.randomUUID().toString()
            Log.i(TAG, "Creating group: $groupName (ID: $groupId)")

            // Step 2: Generate AES-256 group key
            val groupKey = generateGroupKey()

            // Step 3: Encrypt group key for local storage
            val encryptedGroupKey = encryptGroupKeyForStorage(groupKey)

            // Step 4: Create group entity
            val timestamp = System.currentTimeMillis()
            val group = Group(
                groupId = groupId,
                name = groupName,
                encryptedGroupKeyBase64 = encryptedGroupKey,
                groupPin = groupPin,
                groupIcon = groupIcon,
                createdAt = timestamp,
                lastActivityTimestamp = timestamp,
                isAdmin = true
            )

            // Step 5: Store group in database
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)
            database.groupDao().insertGroup(group)
            Log.i(TAG, "Group stored in database")

            // Step 6: Add members to group
            val groupMembers = members.map { contact ->
                GroupMember(
                    groupId = groupId,
                    contactId = contact.id,
                    isAdmin = false,
                    addedAt = timestamp
                )
            }
            database.groupMemberDao().insertGroupMembers(groupMembers)
            Log.i(TAG, "Added ${members.size} members to group")

            // Step 7: Send encrypted group key to each member via Tor
            val groupMessagingService = GroupMessagingService.getInstance(context)
            members.forEach { member ->
                try {
                    // Encrypt group key for this member using their X25519 public key
                    val memberX25519Key = member.x25519PublicKeyBytes
                    val encryptedKeyForMember = encryptGroupKeyForMember(groupKey, memberX25519Key)

                    // Send group invite via Tor
                    val result = groupMessagingService.sendGroupInvite(
                        groupId = groupId,
                        contact = member,
                        encryptedGroupKey = encryptedKeyForMember,
                        groupName = groupName,
                        groupPin = groupPin
                    )

                    if (result.isSuccess) {
                        Log.i(TAG, "Group invite sent to: ${member.displayName}")
                    } else {
                        Log.e(TAG, "Failed to send invite to: ${member.displayName}")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error sending invite to ${member.displayName}", e)
                }
            }
            Log.i(TAG, "Sent group invites to ${members.size} members via Tor")

            // Step 8: Create system message: "Group created"
            val systemMessage = createSystemMessage(
                groupId = groupId,
                messageText = "Group created by you",
                timestamp = timestamp
            )
            database.groupMessageDao().insertGroupMessage(systemMessage)

            Log.i(TAG, "Group created successfully: $groupName")
            Result.success(groupId)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to create group", e)
            Result.failure(e)
        }
    }

    /**
     * Encrypt a message with the group key using AES-256-GCM
     * @param message Plain text message
     * @param groupKey 32-byte AES-256 group key
     * @return Pair of (encrypted message Base64, nonce Base64)
     */
    fun encryptGroupMessage(message: String, groupKey: ByteArray): Pair<String, String> {
        try {
            // Generate random nonce (12 bytes for AES-GCM)
            val nonce = ByteArray(12)
            secureRandom.nextBytes(nonce)

            // Encrypt message with AES-256-GCM
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(groupKey, "AES")
            val gcmSpec = GCMParameterSpec(128, nonce) // 128-bit authentication tag
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

            val encrypted = cipher.doFinal(message.toByteArray(Charsets.UTF_8))

            return Pair(
                Base64.encodeToString(encrypted, Base64.NO_WRAP),
                Base64.encodeToString(nonce, Base64.NO_WRAP)
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to encrypt group message", e)
            throw Exception("Encryption failed: ${e.message}", e)
        }
    }

    /**
     * Decrypt a group message using AES-256-GCM
     * @param encryptedMessageBase64 Encrypted message (Base64)
     * @param nonceBase64 Nonce (Base64)
     * @param groupKey 32-byte AES-256 group key
     * @return Decrypted plain text message
     */
    fun decryptGroupMessage(
        encryptedMessageBase64: String,
        nonceBase64: String,
        groupKey: ByteArray
    ): String {
        try {
            val encrypted = Base64.decode(encryptedMessageBase64, Base64.NO_WRAP)
            val nonce = Base64.decode(nonceBase64, Base64.NO_WRAP)

            // Decrypt with AES-256-GCM
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(groupKey, "AES")
            val gcmSpec = GCMParameterSpec(128, nonce)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

            val decrypted = cipher.doFinal(encrypted)
            return String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt group message", e)
            throw Exception("Decryption failed: ${e.message}", e)
        }
    }

    /**
     * Send a message to a group
     * @param groupId Group ID
     * @param messageText Message text
     * @return Message ID
     */
    suspend fun sendGroupMessage(groupId: String, messageText: String): Result<String> {
        return try {
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Get group and decrypt group key
            val group = database.groupDao().getGroupById(groupId)
                ?: return Result.failure(Exception("Group not found"))

            val groupKey = decryptGroupKeyFromStorage(group.encryptedGroupKeyBase64)

            // Encrypt message
            val (encryptedMessage, nonce) = encryptGroupMessage(messageText, groupKey)

            // Sign message
            val signature = keyManager.signData(messageText.toByteArray(Charsets.UTF_8))
            val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

            // Create message entity
            val messageId = UUID.randomUUID().toString()
            val timestamp = System.currentTimeMillis()
            val myUsername = keyManager.getUsername() ?: "You"

            val groupMessage = GroupMessage(
                groupId = groupId,
                senderContactId = null, // null = sent by us
                senderName = myUsername,
                messageId = messageId,
                encryptedContent = encryptedMessage,
                isSentByMe = true,
                timestamp = timestamp,
                status = GroupMessage.STATUS_PENDING,
                signatureBase64 = signatureBase64,
                nonceBase64 = nonce,
                messageType = GroupMessage.MESSAGE_TYPE_TEXT
            )

            // Store message
            database.groupMessageDao().insertGroupMessage(groupMessage)

            // Update group last activity
            database.groupDao().updateLastActivity(groupId, timestamp)

            Log.i(TAG, "Group message created: $messageId")

            // Send message to all group members via Tor
            val groupMessagingService = GroupMessagingService.getInstance(context)
            val sendResult = groupMessagingService.sendGroupMessage(groupMessage)

            if (sendResult.isSuccess) {
                val successfulSends = sendResult.getOrNull() ?: emptyList()
                Log.i(TAG, "Message sent to ${successfulSends.size} members via Tor")
            } else {
                Log.e(TAG, "Failed to send message via Tor: ${sendResult.exceptionOrNull()?.message}")
                // Don't fail the whole operation - message is stored locally
            }

            Result.success(messageId)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send group message", e)
            Result.failure(e)
        }
    }

    /**
     * Create a system message (e.g., "Alice added Bob")
     */
    private fun createSystemMessage(groupId: String, messageText: String, timestamp: Long): GroupMessage {
        return GroupMessage(
            groupId = groupId,
            senderContactId = null,
            senderName = "System",
            messageId = UUID.randomUUID().toString(),
            encryptedContent = Base64.encodeToString(messageText.toByteArray(), Base64.NO_WRAP),
            isSentByMe = false,
            timestamp = timestamp,
            status = GroupMessage.STATUS_SENT,
            signatureBase64 = "",
            nonceBase64 = "",
            messageType = GroupMessage.MESSAGE_TYPE_SYSTEM
        )
    }
}
