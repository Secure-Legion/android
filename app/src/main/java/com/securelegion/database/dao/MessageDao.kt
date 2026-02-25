package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.Message
import kotlinx.coroutines.flow.Flow

data class UnreadCountResult(
    @ColumnInfo(name = "contactId") val contactId: Long,
    @ColumnInfo(name = "cnt") val cnt: Int
)

/**
 * Lightweight projection for thread delete operations.
 * Only fetches the 4 small columns needed for cleanup (voice wipe, ACK clear, dedup clear).
 * Never touches attachmentData/encryptedPayload — immune to CursorWindow overflow.
 */
data class MessageDeleteInfo(
    @ColumnInfo(name = "messageId") val messageId: String,
    @ColumnInfo(name = "messageType") val messageType: String,
    @ColumnInfo(name = "voiceFilePath") val voiceFilePath: String?,
    @ColumnInfo(name = "pingId") val pingId: String?
)

/**
 * Data Access Object for Message operations
 * All queries run on background thread via coroutines
 *
 * ==================== CURSORWINDOW SAFETY ====================
 * All SELECT queries returning Message objects use [LITE_COLS] which:
 * - Excludes encryptedPayload entirely (NULL AS) — loaded on-demand via [getEncryptedPayload]
 * - Excludes large attachmentData (>100KB via CASE) — loaded on-demand via [getAttachmentData]
 * - Keeps small attachmentData (sticker asset paths ~50 bytes, etc.)
 *
 * This prevents SQLiteBlobTooBigException on rows with multi-MB base64 image blobs.
 * CursorWindow has a ~2MB per-row limit; a 6MB GIF blob caused the original crash.
 */
@Dao
interface MessageDao {

    companion object {
        /**
         * Explicit column list for CursorWindow-safe queries.
         *
         * ALWAYS NULL: encryptedPayload (only needed by retry path, loaded on-demand)
         * CONDITIONALLY NULL: attachmentData > 1.8MB (safety net for legacy inline base64;
         *   new images are stored as files so attachmentData is just a tiny path string)
         *
         * Why 1.8MB? CursorWindow has a ~2MB per-row limit. With ~34 small columns (~20KB)
         * plus 1.8MB attachmentData, each row is ~1.82MB — under the limit.
         * New images store file paths (~100 bytes), so this CASE only fires for legacy data.
         */
        const val LITE_COLS = """id, contactId, messageId, encryptedContent, isSentByMe, timestamp, status,
            signatureBase64, nonceBase64, messageNonce, messageType, voiceDuration, voiceFilePath,
            attachmentType,
            CASE WHEN attachmentData IS NOT NULL AND length(attachmentData) > 1800000
                 THEN NULL ELSE attachmentData END AS attachmentData,
            isRead, selfDestructAt, requiresReadReceipt, pingId, pingTimestamp,
            NULL AS encryptedPayload,
            retryCount, lastRetryTimestamp, nextRetryAtMs, lastError,
            pingDelivered, messageDelivered, tapDelivered, pongDelivered,
            pingWireBytes, paymentQuoteJson, paymentStatus, txSignature, paymentToken, paymentAmount,
            correlationId, isPinned"""
    }

    /**
     * Insert a new message. Returns row ID, or -1 if ignored (duplicate messageId/pingId).
     * IGNORE prevents REPLACE from silently deleting existing rows and resetting
     * delivery state (pingDelivered, messageDelivered) and auto-increment IDs.
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertMessage(message: Message): Long

    /**
     * Insert multiple messages (bulk operation). Duplicates are silently ignored.
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertMessages(messages: List<Message>)

    /**
     * Update existing message
     */
    @Update
    suspend fun updateMessage(message: Message)

    /**
     * Delete message
     */
    @Delete
    suspend fun deleteMessage(message: Message)

    /**
     * Delete message by ID
     */
    @Query("DELETE FROM messages WHERE id = :messageId")
    suspend fun deleteMessageById(messageId: Long)

    /**
     * Pin or unpin a message locally
     */
    @Query("UPDATE messages SET isPinned = :pinned WHERE id = :messageId")
    suspend fun setPinned(messageId: Long, pinned: Boolean)

    /**
     * Get pinned messages for a contact (most recent first)
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE contactId = :contactId AND isPinned = 1 ORDER BY timestamp DESC")
    suspend fun getPinnedMessages(contactId: Long): List<Message>

    /**
     * Get message by ID (CursorWindow-safe: large columns excluded)
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE id = :messageId")
    suspend fun getMessageById(messageId: Long): Message?

    /**
     * Get message by unique message ID (CursorWindow-safe: large columns excluded)
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE messageId = :messageId")
    suspend fun getMessageByMessageId(messageId: String): Message?

    /**
     * Get all messages for a contact (ordered by timestamp)
     * Returns Flow for reactive updates
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE contactId = :contactId AND messageType != 'PROFILE_UPDATE' ORDER BY timestamp ASC")
    fun getMessagesForContactFlow(contactId: Long): Flow<List<Message>>

    /**
     * Get all messages for a contact (one-shot query)
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE contactId = :contactId AND messageType != 'PROFILE_UPDATE' ORDER BY timestamp ASC")
    suspend fun getMessagesForContact(contactId: Long): List<Message>

    /**
     * Get image messages for a contact (for media gallery)
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE contactId = :contactId AND messageType = 'IMAGE' ORDER BY timestamp DESC")
    suspend fun getImageMessagesForContact(contactId: Long): List<Message>

    /**
     * Get voice messages for a contact (for voice clips gallery)
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE contactId = :contactId AND messageType = 'VOICE' ORDER BY timestamp DESC")
    suspend fun getVoiceMessagesForContact(contactId: Long): List<Message>

    /**
     * Get recent messages for a contact (limit N)
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE contactId = :contactId AND messageType != 'PROFILE_UPDATE' ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecentMessages(contactId: Long, limit: Int): List<Message>

    /**
     * Get unread message count for a contact
     */
    @Query("SELECT COUNT(*) FROM messages WHERE contactId = :contactId AND isSentByMe = 0 AND isRead = 0")
    suspend fun getUnreadCount(contactId: Long): Int

    /**
     * Get total unread message count (all contacts)
     */
    @Query("SELECT COUNT(*) FROM messages WHERE isSentByMe = 0 AND isRead = 0")
    suspend fun getTotalUnreadCount(): Int

    /**
     * Mark message as read
     */
    @Query("UPDATE messages SET isRead = 1 WHERE id = :messageId")
    suspend fun markAsRead(messageId: Long)

    /**
     * Mark all messages from a contact as read
     */
    @Query("UPDATE messages SET isRead = 1 WHERE contactId = :contactId AND isSentByMe = 0")
    suspend fun markAllAsRead(contactId: Long)

    /**
     * Update message status
     */
    @Query("UPDATE messages SET status = :status WHERE id = :messageId")
    suspend fun updateMessageStatus(messageId: Long, status: Int)

    /**
     * Update message status by messageId (for acknowledgments)
     */
    @Query("UPDATE messages SET status = :status WHERE messageId = :messageId")
    suspend fun updateMessageStatusByMessageId(messageId: String, status: Int)

    /**
     * Update retry fields only (prevents race condition with delivery status updates)
     * CRITICAL: Use this instead of updateMessage() when only updating retry state
     * This ensures messageDelivered, pingDelivered, status etc. are never overwritten by stale data
     */
    @Query("UPDATE messages SET retryCount = :retryCount, lastRetryTimestamp = :lastRetryTimestamp WHERE id = :messageId")
    suspend fun updateRetryState(messageId: Long, retryCount: Int, lastRetryTimestamp: Long)

    @Query("UPDATE messages SET retryCount = :retryCount, lastRetryTimestamp = :lastRetryTimestamp, nextRetryAtMs = :nextRetryAtMs WHERE id = :messageId")
    suspend fun updateRetrySchedule(messageId: Long, retryCount: Int, lastRetryTimestamp: Long, nextRetryAtMs: Long)

    /**
     * Update retry fields with next retry time and error (for MessageRetryWorker)
     * CRITICAL: Partial update to avoid overwriting delivery status with stale data
     */
    @Query("UPDATE messages SET retryCount = :retryCount, lastRetryTimestamp = :lastRetryTimestamp, nextRetryAtMs = :nextRetryAtMs, lastError = :lastError WHERE id = :messageId")
    suspend fun updateRetryStateWithError(messageId: Long, retryCount: Int, lastRetryTimestamp: Long, nextRetryAtMs: Long, lastError: String?)

    @Query("UPDATE messages SET lastError = :error WHERE id = :messageId")
    suspend fun updateLastError(messageId: Long, error: String?)

    /**
     * Update pingWireBytes only (prevents race condition with delivery status updates)
     * CRITICAL: Use this instead of updateMessage() when only storing wire bytes for retry
     */
    @Query("UPDATE messages SET pingWireBytes = :pingWireBytes WHERE id = :messageId")
    suspend fun updatePingWireBytes(messageId: Long, pingWireBytes: String)

    /**
     * Update pingDelivered and status only (prevents race condition with retry state updates)
     * CRITICAL: Use instead of updateMessage() in PING_ACK handler
     */
    @Query("UPDATE messages SET pingDelivered = :pingDelivered, status = :status WHERE id = :messageId")
    suspend fun updatePingDeliveredStatus(messageId: Long, pingDelivered: Boolean, status: Int)

    /**
     * Update messageDelivered and status only (prevents race with retry state)
     * CRITICAL: Use instead of updateMessage() in MESSAGE_ACK handler
     */
    @Query("UPDATE messages SET messageDelivered = :messageDelivered, status = :status WHERE id = :messageId")
    suspend fun updateMessageDeliveredStatus(messageId: Long, messageDelivered: Boolean, status: Int)

    /**
     * Update tapDelivered only (prevents race condition with delivery status updates)
     */
    @Query("UPDATE messages SET tapDelivered = :tapDelivered WHERE id = :messageId")
    suspend fun updateTapDelivered(messageId: Long, tapDelivered: Boolean)

    /**
     * Update payment status and tx signature only (prevents race condition with delivery status)
     * CRITICAL: Use this instead of updateMessage() for payment updates
     */
    @Query("UPDATE messages SET paymentStatus = :paymentStatus, txSignature = :txSignature WHERE id = :messageId")
    suspend fun updatePaymentFields(messageId: Long, paymentStatus: String, txSignature: String)

    /**
     * Get last message for a contact
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE contactId = :contactId AND messageType != 'PROFILE_UPDATE' ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLastMessage(contactId: Long): Message?

    /**
     * Get last message for ALL contacts in one query.
     * Uses subquery to find latest message IDs, then selects LITE_COLS for those IDs.
     */
    @Query("""
        SELECT $LITE_COLS FROM messages
        WHERE id IN (
            SELECT m2.id FROM messages m2
            INNER JOIN (
                SELECT contactId, MAX(timestamp) as maxTs FROM messages WHERE messageType != 'PROFILE_UPDATE' GROUP BY contactId
            ) latest ON m2.contactId = latest.contactId AND m2.timestamp = latest.maxTs
        )
    """)
    suspend fun getLastMessagePerContact(): List<Message>

    /**
     * Get unread counts grouped by contact in one query
     */
    @Query("SELECT contactId, COUNT(*) as cnt FROM messages WHERE isSentByMe = 0 AND isRead = 0 GROUP BY contactId")
    suspend fun getUnreadCountsGrouped(): List<UnreadCountResult>

    /**
     * Get pending messages (for retry)
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE status = ${Message.STATUS_PENDING} OR status = ${Message.STATUS_FAILED} ORDER BY timestamp ASC")
    suspend fun getPendingMessages(): List<Message>

    /**
     * Get messages waiting for Pong (STATUS_PING_SENT, sent by us, with pingId)
     * Used by retryAllPendingMessages() to poll Rust for PONG arrivals
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE isSentByMe = 1 AND status = ${Message.STATUS_PING_SENT} AND pingId IS NOT NULL ORDER BY timestamp ASC")
    suspend fun getMessagesAwaitingPong(): List<Message>

    /**
     * Get messages ready for blob send (STATUS_PONG_RECEIVED, sent by us)
     * Protocol v2: PONG handler transitions STATUS_PING_SENT → STATUS_PONG_RECEIVED,
     * then sendPendingMessagesForContact() picks these up and sends the blob
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE contactId = :contactId AND isSentByMe = 1 AND status = ${Message.STATUS_PONG_RECEIVED} AND pingId IS NOT NULL ORDER BY timestamp ASC")
    suspend fun getMessagesPendingBlobSend(contactId: Long): List<Message>

    /**
     * Get distinct contact IDs with STATUS_PONG_RECEIVED messages (ready for blob send)
     * Used by retryAllPendingMessages() to iterate per-contact
     */
    @Query("SELECT DISTINCT contactId FROM messages WHERE isSentByMe = 1 AND status = ${Message.STATUS_PONG_RECEIVED}")
    suspend fun getContactsWithPongReceived(): List<Long>

    /**
     * Get message by Ping ID
     * Used when a Pong arrives to find the corresponding message
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE pingId = :pingId LIMIT 1")
    suspend fun getMessageByPingId(pingId: String): Message?

    /**
     * Get all sent messages with pending Pings for a contact
     * Used to replace SharedPreferences-based PendingPing queue
     * Returns messages that have pingId set and are sent by us (isSentByMe = true)
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE contactId = :contactId AND isSentByMe = 1 AND pingId IS NOT NULL ORDER BY timestamp ASC")
    suspend fun getPendingPingsForContact(contactId: Long): List<Message>

    /**
     * Delete all messages for a contact
     */
    @Query("DELETE FROM messages WHERE contactId = :contactId")
    suspend fun deleteMessagesForContact(contactId: Long)

    /**
     * Delete all messages (for testing or account wipe)
     */
    @Query("DELETE FROM messages")
    suspend fun deleteAllMessages()

    /**
     * Get message count for a contact
     */
    @Query("SELECT COUNT(*) FROM messages WHERE contactId = :contactId")
    suspend fun getMessageCount(contactId: Long): Int

    /**
     * Check if message exists by messageId (for deduplication)
     */
    @Query("SELECT EXISTS(SELECT 1 FROM messages WHERE messageId = :messageId)")
    suspend fun messageExists(messageId: String): Boolean

    /**
     * Get all messages that have expired (self-destruct time has passed)
     * Used by background worker to delete expired messages
     */
    @Query("SELECT $LITE_COLS FROM messages WHERE selfDestructAt IS NOT NULL AND selfDestructAt <= :currentTime")
    suspend fun getExpiredMessages(currentTime: Long = System.currentTimeMillis()): List<Message>

    /**
     * Delete expired self-destruct messages
     * Returns number of messages deleted
     */
    @Query("DELETE FROM messages WHERE selfDestructAt IS NOT NULL AND selfDestructAt <= :currentTime")
    suspend fun deleteExpiredMessages(currentTime: Long = System.currentTimeMillis()): Int

    /**
     * Update payment status and transaction signature
     * Used when receiving payment confirmation messages
     */
    @Query("UPDATE messages SET paymentStatus = :status, txSignature = :txSignature WHERE messageId = :messageId")
    suspend fun updatePaymentStatus(messageId: String, status: String, txSignature: String)

    /**
     * Get messages that need retry (sent by us, not yet delivered, not too old)
     * Used by MessageRetryWorker for periodic retry
     * @param currentTimeMs Current time in milliseconds
     * @param giveupAfterDays Give up on messages older than this many days
     * @return List of messages needing retry
     */
    @Query("""
        SELECT $LITE_COLS FROM messages
        WHERE isSentByMe = 1
        AND status NOT IN (2, 3)
        AND timestamp > :currentTimeMs - (:giveupAfterDays * 24 * 60 * 60 * 1000)
        ORDER BY timestamp ASC
    """)
    suspend fun getMessagesNeedingRetry(currentTimeMs: Long, giveupAfterDays: Long = 7): List<Message>

    /**
     * Mark PING as delivered when PING_ACK is successfully sent
     * Updates the message status to reflect ACK confirmation
     */
    @Query("UPDATE messages SET status = 2 WHERE pingId = :pingId")
    suspend fun markPingDelivered(pingId: String)

    // ==================== CURSORWINDOW-SAFE HELPERS ====================

    /**
     * Lightweight projection for thread deletion.
     * Returns only the 4 small columns needed for cleanup:
     * - messageId: for ACK state clearing and dedup cleanup
     * - messageType: to identify VOICE messages needing file wipe
     * - voiceFilePath: the file to securely wipe
     * - pingId: for ReceivedId cleanup
     *
     * NEVER touches attachmentData/encryptedPayload — immune to CursorWindow overflow.
     */
    @Query("SELECT messageId, messageType, voiceFilePath, pingId FROM messages WHERE contactId = :contactId")
    suspend fun getDeleteInfoForContact(contactId: Long): List<MessageDeleteInfo>

    /**
     * Get message count for a contact (CursorWindow-safe alternative to getMessagesForContact().size)
     */
    @Query("SELECT COUNT(*) FROM messages WHERE contactId = :contactId AND messageType != 'PROFILE_UPDATE'")
    suspend fun getMessageCountForContact(contactId: Long): Int

    /**
     * On-demand loader for attachmentData (single row, single column).
     * Used when the CASE-limited bulk query excluded the value (>100KB).
     * For image messages with multi-MB base64 blobs.
     */
    @Query("SELECT attachmentData FROM messages WHERE id = :messageId LIMIT 1")
    suspend fun getAttachmentData(messageId: Long): String?

    /**
     * On-demand loader for encryptedPayload (single row, single column).
     * Used by retry path since bulk queries always exclude encryptedPayload.
     */
    @Query("SELECT encryptedPayload FROM messages WHERE id = :messageId LIMIT 1")
    suspend fun getEncryptedPayload(messageId: Long): String?

}
