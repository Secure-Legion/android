package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.GroupMessage
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for GroupMessage operations
 * All queries run on background thread via coroutines
 */
@Dao
interface GroupMessageDao {

    /**
     * Insert a new group message
     * @return ID of inserted message
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertGroupMessage(message: GroupMessage): Long

    /**
     * Insert multiple group messages (bulk operation)
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertGroupMessages(messages: List<GroupMessage>)

    /**
     * Update existing group message
     */
    @Update
    suspend fun updateGroupMessage(message: GroupMessage)

    /**
     * Delete group message
     */
    @Delete
    suspend fun deleteGroupMessage(message: GroupMessage)

    /**
     * Delete group message by ID
     */
    @Query("DELETE FROM group_messages WHERE id = :messageId")
    suspend fun deleteGroupMessageById(messageId: Long)

    /**
     * Get group message by ID
     */
    @Query("SELECT * FROM group_messages WHERE id = :messageId")
    suspend fun getGroupMessageById(messageId: Long): GroupMessage?

    /**
     * Get group message by unique message ID
     */
    @Query("SELECT * FROM group_messages WHERE messageId = :messageId")
    suspend fun getGroupMessageByMessageId(messageId: String): GroupMessage?

    /**
     * Get all messages for a group (ordered by timestamp)
     * Returns Flow for reactive updates
     */
    @Query("SELECT * FROM group_messages WHERE groupId = :groupId ORDER BY timestamp ASC")
    fun getMessagesForGroupFlow(groupId: String): Flow<List<GroupMessage>>

    /**
     * Get all messages for a group (one-shot query)
     */
    @Query("SELECT * FROM group_messages WHERE groupId = :groupId ORDER BY timestamp ASC")
    suspend fun getMessagesForGroup(groupId: String): List<GroupMessage>

    /**
     * Get recent messages for a group (limit N)
     */
    @Query("SELECT * FROM group_messages WHERE groupId = :groupId ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecentMessages(groupId: String, limit: Int): List<GroupMessage>

    /**
     * Get last message for a group
     */
    @Query("SELECT * FROM group_messages WHERE groupId = :groupId ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLastMessage(groupId: String): GroupMessage?

    /**
     * Update message status
     */
    @Query("UPDATE group_messages SET status = :status WHERE id = :messageId")
    suspend fun updateMessageStatus(messageId: Long, status: Int)

    /**
     * Update message status by messageId (for acknowledgments)
     */
    @Query("UPDATE group_messages SET status = :status WHERE messageId = :messageId")
    suspend fun updateMessageStatusByMessageId(messageId: String, status: Int)

    /**
     * Get pending messages (for retry)
     */
    @Query("SELECT * FROM group_messages WHERE status = ${GroupMessage.STATUS_PENDING} OR status = ${GroupMessage.STATUS_FAILED} ORDER BY timestamp ASC")
    suspend fun getPendingMessages(): List<GroupMessage>

    /**
     * Get message count for a group
     */
    @Query("SELECT COUNT(*) FROM group_messages WHERE groupId = :groupId")
    suspend fun getMessageCount(groupId: String): Int

    /**
     * Check if message exists by messageId (for deduplication)
     */
    @Query("SELECT EXISTS(SELECT 1 FROM group_messages WHERE messageId = :messageId)")
    suspend fun messageExists(messageId: String): Boolean

    /**
     * Delete all messages for a group
     */
    @Query("DELETE FROM group_messages WHERE groupId = :groupId")
    suspend fun deleteMessagesForGroup(groupId: String)

    /**
     * Delete all group messages (for testing or account wipe)
     */
    @Query("DELETE FROM group_messages")
    suspend fun deleteAllGroupMessages()

    /**
     * Get all messages that have expired (self-destruct time has passed)
     */
    @Query("SELECT * FROM group_messages WHERE selfDestructSeconds IS NOT NULL AND (timestamp + (selfDestructSeconds * 1000)) <= :currentTime")
    suspend fun getExpiredMessages(currentTime: Long = System.currentTimeMillis()): List<GroupMessage>

    /**
     * Delete expired self-destruct messages
     * Returns number of messages deleted
     */
    @Query("DELETE FROM group_messages WHERE selfDestructSeconds IS NOT NULL AND (timestamp + (selfDestructSeconds * 1000)) <= :currentTime")
    suspend fun deleteExpiredMessages(currentTime: Long = System.currentTimeMillis()): Int

    /**
     * Get messages from a specific sender in a group
     */
    @Query("SELECT * FROM group_messages WHERE groupId = :groupId AND senderContactId = :senderContactId ORDER BY timestamp ASC")
    suspend fun getMessagesFromSender(groupId: String, senderContactId: Long): List<GroupMessage>

    /**
     * Get system messages for a group (member added, removed, etc.)
     */
    @Query("SELECT * FROM group_messages WHERE groupId = :groupId AND messageType = '${GroupMessage.MESSAGE_TYPE_SYSTEM}' ORDER BY timestamp ASC")
    suspend fun getSystemMessages(groupId: String): List<GroupMessage>
}
