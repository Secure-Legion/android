package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.Message
import kotlinx.coroutines.flow.Flow

data class UnreadCountResult(
    @ColumnInfo(name = "contactId") val contactId: Long,
    @ColumnInfo(name = "cnt") val cnt: Int
)

/**
 * Data Access Object for Message operations
 * All queries run on background thread via coroutines
 */
@Dao
interface MessageDao {

    /**
     * Insert a new message
     * @return ID of inserted message
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertMessage(message: Message): Long

    /**
     * Insert multiple messages (bulk operation)
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
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
     * Get message by ID
     */
    @Query("SELECT * FROM messages WHERE id = :messageId")
    suspend fun getMessageById(messageId: Long): Message?

    /**
     * Get message by unique message ID
     */
    @Query("SELECT * FROM messages WHERE messageId = :messageId")
    suspend fun getMessageByMessageId(messageId: String): Message?

    /**
     * Get all messages for a contact (ordered by timestamp)
     * Returns Flow for reactive updates
     */
    @Query("SELECT * FROM messages WHERE contactId = :contactId ORDER BY timestamp ASC")
    fun getMessagesForContactFlow(contactId: Long): Flow<List<Message>>

    /**
     * Get all messages for a contact (one-shot query)
     */
    @Query("SELECT * FROM messages WHERE contactId = :contactId ORDER BY timestamp ASC")
    suspend fun getMessagesForContact(contactId: Long): List<Message>

    /**
     * Get recent messages for a contact (limit N)
     */
    @Query("SELECT * FROM messages WHERE contactId = :contactId ORDER BY timestamp DESC LIMIT :limit")
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

    /**
     * Update retry fields with next retry time and error (for MessageRetryWorker)
     * CRITICAL: Partial update to avoid overwriting delivery status with stale data
     */
    @Query("UPDATE messages SET retryCount = :retryCount, lastRetryTimestamp = :lastRetryTimestamp, nextRetryAtMs = :nextRetryAtMs, lastError = :lastError WHERE id = :messageId")
    suspend fun updateRetryStateWithError(messageId: Long, retryCount: Int, lastRetryTimestamp: Long, nextRetryAtMs: Long, lastError: String?)

    /**
     * Update pingWireBytes only (prevents race condition with delivery status updates)
     * CRITICAL: Use this instead of updateMessage() when only storing wire bytes for retry
     */
    @Query("UPDATE messages SET pingWireBytes = :pingWireBytes WHERE id = :messageId")
    suspend fun updatePingWireBytes(messageId: Long, pingWireBytes: String)

    /**
     * Update pongDelivered only (prevents race condition with delivery status updates)
     * CRITICAL: Use this instead of updateMessage() when marking PONG_ACK sent
     */
    @Query("UPDATE messages SET pongDelivered = :pongDelivered WHERE id = :messageId")
    suspend fun updatePongDelivered(messageId: Long, pongDelivered: Boolean)

    /**
     * Update payment status and tx signature only (prevents race condition with delivery status)
     * CRITICAL: Use this instead of updateMessage() for payment updates
     */
    @Query("UPDATE messages SET paymentStatus = :paymentStatus, txSignature = :txSignature WHERE id = :messageId")
    suspend fun updatePaymentFields(messageId: Long, paymentStatus: String, txSignature: String)

    /**
     * Get last message for a contact
     */
    @Query("SELECT * FROM messages WHERE contactId = :contactId ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLastMessage(contactId: Long): Message?

    /**
     * Get last message for ALL contacts in one query
     */
    @Query("""
        SELECT m.* FROM messages m
        INNER JOIN (
            SELECT contactId, MAX(timestamp) as maxTs FROM messages GROUP BY contactId
        ) latest ON m.contactId = latest.contactId AND m.timestamp = latest.maxTs
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
    @Query("SELECT * FROM messages WHERE status = ${Message.STATUS_PENDING} OR status = ${Message.STATUS_FAILED} ORDER BY timestamp ASC")
    suspend fun getPendingMessages(): List<Message>

    /**
     * Get messages waiting for Pong (STATUS_PING_SENT)
     * Used by Pong polling worker to check for Pong arrivals
     */
    @Query("SELECT * FROM messages WHERE status = ${Message.STATUS_PING_SENT} ORDER BY timestamp ASC")
    suspend fun getMessagesAwaitingPong(): List<Message>

    /**
     * Get message by Ping ID
     * Used when a Pong arrives to find the corresponding message
     */
    @Query("SELECT * FROM messages WHERE pingId = :pingId LIMIT 1")
    suspend fun getMessageByPingId(pingId: String): Message?

    /**
     * Get all sent messages with pending Pings for a contact
     * Used to replace SharedPreferences-based PendingPing queue
     * Returns messages that have pingId set and are sent by us (isSentByMe = true)
     */
    @Query("SELECT * FROM messages WHERE contactId = :contactId AND isSentByMe = 1 AND pingId IS NOT NULL ORDER BY timestamp ASC")
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
    @Query("SELECT * FROM messages WHERE selfDestructAt IS NOT NULL AND selfDestructAt <= :currentTime")
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
        SELECT * FROM messages
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

}
