package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.Message
import kotlinx.coroutines.flow.Flow

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
     * Get last message for a contact
     */
    @Query("SELECT * FROM messages WHERE contactId = :contactId ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLastMessage(contactId: Long): Message?

    /**
     * Get pending messages (for retry)
     */
    @Query("SELECT * FROM messages WHERE status = ${Message.STATUS_PENDING} OR status = ${Message.STATUS_FAILED} ORDER BY timestamp ASC")
    suspend fun getPendingMessages(): List<Message>

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
}
