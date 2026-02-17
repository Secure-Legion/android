package com.securelegion.services

import android.content.Context
import android.util.Base64
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.GroupMessage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID

/**
 * Service for sending and receiving group messages via Tor
 *
 * Handles:
 * - Sending group invites with encrypted group keys
 * - Broadcasting group messages to all members
 * - Receiving group messages from members
 * - Message acknowledgments and delivery status
 */
class GroupMessagingService private constructor(private val context: Context) {

    companion object {
        private const val TAG = "GroupMessagingService"

        // Message type bytes for wire protocol
        private const val TYPE_GROUP_INVITE: Byte = 0x20 // Group invite with encrypted key
        private const val TYPE_GROUP_MESSAGE: Byte = 0x21 // Regular group message
        private const val TYPE_GROUP_ACK: Byte = 0x22 // Group message acknowledgment

        @Volatile
        private var INSTANCE: GroupMessagingService? = null

        fun getInstance(context: Context): GroupMessagingService {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: GroupMessagingService(context.applicationContext).also {
                    INSTANCE = it
                }
            }
        }
    }

    private val keyManager = KeyManager.getInstance(context)
    private val groupManager = GroupManager.getInstance(context)

    /**
     * Send group invite to a member with encrypted group key
     *
     * @param groupId Group ID
     * @param contact Contact to invite
     * @param encryptedGroupKey Encrypted group key for this member
     * @param groupName Group name
     * @param groupPin Group PIN
     */
    suspend fun sendGroupInvite(
        groupId: String,
        contact: Contact,
        encryptedGroupKey: String,
        groupName: String,
        groupPin: String
    ): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            Log.i(TAG, "Sending group invite to ${contact.displayName} for group: $groupName")

            // Build invite payload: groupId|groupName|groupPin|encryptedGroupKey
            val invitePayload = "$groupId|$groupName|$groupPin|$encryptedGroupKey"

            // Encrypt invite with member's X25519 public key
            val recipientX25519PubKey = Base64.decode(contact.x25519PublicKeyBase64, Base64.NO_WRAP)
            val encryptedInvite = RustBridge.encryptMessage(invitePayload, recipientX25519PubKey)
            val encryptedInviteBase64 = Base64.encodeToString(encryptedInvite, Base64.NO_WRAP)

            // Send via Tor using Ping-Pong protocol
            val onionAddress = contact.messagingOnion ?: contact.torOnionAddress ?: ""
            val recipientEd25519PubKey = Base64.decode(contact.publicKeyBase64, Base64.NO_WRAP)

            // Generate Ping ID and timestamp
            val pingId = generatePingId()
            val pingTimestamp = System.currentTimeMillis()

            Log.d(TAG, "Sending group invite Ping")
            val pingResponse = RustBridge.sendPing(
                recipientEd25519PubKey,
                recipientX25519PubKey,
                onionAddress,
                encryptedInvite,
                TYPE_GROUP_INVITE,
                pingId,
                pingTimestamp
            )

            Log.i(TAG, "Group invite sent to ${contact.displayName}")
            Result.success(Unit)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send group invite to ${contact.displayName}", e)
            Result.failure(e)
        }
    }

    /**
     * Send group message to all members
     *
     * @param groupMessage The group message to send
     * @return Result with list of successful sends
     */
    suspend fun sendGroupMessage(groupMessage: GroupMessage): Result<List<String>> = withContext(Dispatchers.IO) {
        try {
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Get group
            val group = database.groupDao().getGroupById(groupMessage.groupId)
                ?: return@withContext Result.failure(Exception("Group not found"))

            // Get all group members
            val members = database.groupMemberDao().getContactsForGroup(groupMessage.groupId)
            Log.i(TAG, "Broadcasting message to ${members.size} members in group: ${group.name}")

            if (members.isEmpty()) {
                Log.w(TAG, "No members in group ${group.name}")
                return@withContext Result.success(emptyList())
            }

            // Build group message payload
            // Format: messageId|groupId|senderName|encryptedContent|nonceBase64|signatureBase64|timestamp
            val payload = buildString {
                append(groupMessage.messageId)
                append("|")
                append(groupMessage.groupId)
                append("|")
                append(groupMessage.senderName)
                append("|")
                append(groupMessage.encryptedContent)
                append("|")
                append(groupMessage.nonceBase64)
                append("|")
                append(groupMessage.signatureBase64)
                append("|")
                append(groupMessage.timestamp)
                append("|")
                append(groupMessage.messageType)
            }

            val successfulSends = mutableListOf<String>()
            val failedSends = mutableListOf<String>()

            // Send to each member
            members.forEach { member ->
                try {
                    // Encrypt payload with member's X25519 key
                    val recipientX25519PubKey = Base64.decode(member.x25519PublicKeyBase64, Base64.NO_WRAP)
                    val encryptedPayload = RustBridge.encryptMessage(payload, recipientX25519PubKey)

                    // Send via Tor
                    val onionAddress = member.messagingOnion ?: member.torOnionAddress ?: ""
                    val recipientEd25519PubKey = Base64.decode(member.publicKeyBase64, Base64.NO_WRAP)

                    val pingId = generatePingId()
                    val pingTimestamp = System.currentTimeMillis()

                    Log.d(TAG, "Sending group message to ${member.displayName}")
                    val pingResponse = RustBridge.sendPing(
                        recipientEd25519PubKey,
                        recipientX25519PubKey,
                        onionAddress,
                        encryptedPayload,
                        TYPE_GROUP_MESSAGE,
                        pingId,
                        pingTimestamp
                    )

                    successfulSends.add(member.displayName)
                    Log.d(TAG, "Sent to ${member.displayName}")

                } catch (e: Exception) {
                    Log.e(TAG, "Failed to send to ${member.displayName}", e)
                    failedSends.add(member.displayName)
                }
            }

            // Update message status based on results
            val newStatus = when {
                successfulSends.size == members.size -> GroupMessage.STATUS_SENT
                successfulSends.isNotEmpty() -> GroupMessage.STATUS_SENT // Partial success
                else -> GroupMessage.STATUS_FAILED
            }

            withContext(Dispatchers.IO) {
                database.groupMessageDao().updateMessageStatus(groupMessage.id, newStatus)
            }

            if (failedSends.isNotEmpty()) {
                Log.w(TAG, "Failed to send to ${failedSends.size} members: ${failedSends.joinToString()}")
            }

            Log.i(TAG, "Group message sent to ${successfulSends.size}/${members.size} members")
            Result.success(successfulSends)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send group message", e)
            Result.failure(e)
        }
    }

    /**
     * Process received group message from Tor network
     * Called by TorService when TYPE_GROUP_MESSAGE is received
     *
     * @param encryptedPayload The encrypted group message payload
     * @param senderPublicKey Sender's Ed25519 public key
     * @return Result with message ID if successful
     */
    suspend fun processReceivedGroupMessage(
        encryptedPayload: ByteArray,
        senderPublicKey: ByteArray
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Processing received group message")

            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Find sender by Ed25519 public key
            val senderPublicKeyBase64 = Base64.encodeToString(senderPublicKey, Base64.NO_WRAP)
            val sender = database.contactDao().getContactByPublicKey(senderPublicKeyBase64)
                ?: return@withContext Result.failure(Exception("Unknown sender"))

            Log.d(TAG, "Message from: ${sender.displayName}")

            // Decrypt payload
            val decryptedPayload = try {
                RustBridge.decryptMessage(encryptedPayload, senderPublicKey, ByteArray(32))
                    ?: return@withContext Result.failure(Exception("Failed to decrypt group message"))
            } catch (e: Exception) {
                Log.e(TAG, "Decryption failed", e)
                return@withContext Result.failure(e)
            }

            // Parse payload: messageId|groupId|senderName|encryptedContent|nonceBase64|signatureBase64|timestamp|messageType
            val parts = decryptedPayload.split("|")
            if (parts.size < 8) {
                return@withContext Result.failure(Exception("Invalid group message format"))
            }

            val messageId = parts[0]
            val groupId = parts[1]
            val senderName = parts[2]
            val encryptedContent = parts[3]
            val nonceBase64 = parts[4]
            val signatureBase64 = parts[5]
            val timestamp = parts[6].toLongOrNull() ?: System.currentTimeMillis()
            val messageType = parts.getOrNull(7) ?: GroupMessage.MESSAGE_TYPE_TEXT

            Log.d(TAG, "Group message: ID=$messageId, Group=$groupId, Sender=$senderName")

            // Check if we're a member of this group
            val group = database.groupDao().getGroupById(groupId)
            if (group == null) {
                Log.w(TAG, "Received message for unknown group: $groupId")
                return@withContext Result.failure(Exception("Not a member of group"))
            }

            // Check for duplicate message
            if (database.groupMessageDao().messageExists(messageId)) {
                Log.d(TAG, "Duplicate message $messageId, ignoring")
                return@withContext Result.success(messageId)
            }

            // Create group message entity
            val groupMessage = GroupMessage(
                groupId = groupId,
                senderContactId = sender.id,
                senderName = senderName,
                messageId = messageId,
                encryptedContent = encryptedContent,
                isSentByMe = false,
                timestamp = timestamp,
                status = GroupMessage.STATUS_DELIVERED,
                signatureBase64 = signatureBase64,
                nonceBase64 = nonceBase64,
                messageType = messageType
            )

            // Save to database
            database.groupMessageDao().insertGroupMessage(groupMessage)
            Log.i(TAG, "Group message saved: $messageId")

            // Update group last activity
            database.groupDao().updateLastActivity(groupId, timestamp)

            // Broadcast to update UI
            val intent = android.content.Intent("com.securelegion.NEW_GROUP_MESSAGE")
            intent.setPackage(context.packageName)
            intent.putExtra("GROUP_ID", groupId)
            intent.putExtra("MESSAGE_ID", messageId)
            context.sendBroadcast(intent)
            Log.d(TAG, "Sent NEW_GROUP_MESSAGE broadcast")

            Result.success(messageId)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to process received group message", e)
            Result.failure(e)
        }
    }

    /**
     * Process received group invite from Tor network
     *
     * @param encryptedPayload The encrypted group invite payload
     * @param senderPublicKey Sender's Ed25519 public key
     * @return Result with group ID if successful
     */
    suspend fun processReceivedGroupInvite(
        encryptedPayload: ByteArray,
        senderPublicKey: ByteArray
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Processing received group invite")

            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Find sender by Ed25519 public key
            val senderPublicKeyBase64 = Base64.encodeToString(senderPublicKey, Base64.NO_WRAP)
            val sender = database.contactDao().getContactByPublicKey(senderPublicKeyBase64)
                ?: return@withContext Result.failure(Exception("Unknown sender"))

            Log.d(TAG, "Invite from: ${sender.displayName}")

            // Decrypt invite
            val decryptedInvite = try {
                RustBridge.decryptMessage(encryptedPayload, senderPublicKey, ByteArray(32))
                    ?: return@withContext Result.failure(Exception("Failed to decrypt invite"))
            } catch (e: Exception) {
                Log.e(TAG, "Decryption failed", e)
                return@withContext Result.failure(e)
            }

            // Parse invite: groupId|groupName|groupPin|encryptedGroupKey
            val parts = decryptedInvite.split("|")
            if (parts.size < 4) {
                return@withContext Result.failure(Exception("Invalid invite format"))
            }

            val groupId = parts[0]
            val groupName = parts[1]
            val groupPin = parts[2]
            val encryptedGroupKey = parts[3]

            Log.i(TAG, "Group invite: $groupName (ID: $groupId)")

            // Store invite in SharedPreferences for user to accept
            val prefs = context.getSharedPreferences("pending_group_invites", Context.MODE_PRIVATE)
            prefs.edit().apply {
                putString("invite_$groupId", "$groupName|$groupPin|$encryptedGroupKey|${sender.displayName}")
                // Add to set for easy listing
                val invites = prefs.getStringSet("invites", mutableSetOf()) ?: mutableSetOf()
                invites.add(groupId)
                putStringSet("invites", invites)
                apply()
            }

            Log.i(TAG, "Group invite stored: $groupName from ${sender.displayName}")

            // Broadcast to update UI
            val intent = android.content.Intent("com.securelegion.GROUP_INVITE_RECEIVED")
            intent.setPackage(context.packageName)
            intent.putExtra("GROUP_ID", groupId)
            intent.putExtra("GROUP_NAME", groupName)
            intent.putExtra("SENDER_NAME", sender.displayName)
            context.sendBroadcast(intent)
            Log.d(TAG, "Sent GROUP_INVITE_RECEIVED broadcast")

            Result.success(groupId)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to process group invite", e)
            Result.failure(e)
        }
    }

    /**
     * Generate a random Ping ID (24-byte nonce as hex string)
     */
    private fun generatePingId(): String {
        val random = java.security.SecureRandom()
        val bytes = ByteArray(24)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
