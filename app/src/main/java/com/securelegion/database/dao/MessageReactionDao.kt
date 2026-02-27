package com.securelegion.database.dao

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.securelegion.database.entities.MessageReaction

data class MessageReactionAggregate(
    @ColumnInfo(name = "targetMessageId") val targetMessageId: String,
    @ColumnInfo(name = "emoji") val emoji: String,
    @ColumnInfo(name = "count") val count: Int,
    @ColumnInfo(name = "mine") val mine: Int
)

@Dao
interface MessageReactionDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(reaction: MessageReaction): Long

    @Query(
        """
        SELECT targetMessageId, emoji, COUNT(*) AS count,
               MAX(CASE WHEN reactorPubKey = :myPubKey THEN 1 ELSE 0 END) AS mine
        FROM message_reactions
        WHERE contactId = :contactId AND isRemoved = 0
        GROUP BY targetMessageId, emoji
        ORDER BY MAX(updatedAt) ASC
        """
    )
    suspend fun getAggregatesForContact(contactId: Long, myPubKey: String): List<MessageReactionAggregate>

    @Query(
        """
        SELECT emoji FROM message_reactions
        WHERE contactId = :contactId
          AND targetMessageId = :targetMessageId
          AND reactorPubKey = :myPubKey
          AND isRemoved = 0
        LIMIT 1
        """
    )
    suspend fun getMyReaction(contactId: Long, targetMessageId: String, myPubKey: String): String?
}
