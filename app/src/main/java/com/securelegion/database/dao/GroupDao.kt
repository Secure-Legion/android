package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.Group
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for Group operations
 * All queries run on background thread via coroutines
 */
@Dao
interface GroupDao {

    /**
     * Insert a new group
     * @return ID of inserted group
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertGroup(group: Group): Long

    /**
     * Update existing group
     */
    @Update
    suspend fun updateGroup(group: Group)

    /**
     * Delete group
     */
    @Delete
    suspend fun deleteGroup(group: Group)

    /**
     * Delete group by ID
     */
    @Query("DELETE FROM groups WHERE groupId = :groupId")
    suspend fun deleteGroupById(groupId: String)

    /**
     * Get group by ID
     */
    @Query("SELECT * FROM groups WHERE groupId = :groupId")
    suspend fun getGroupById(groupId: String): Group?

    /**
     * Get all groups (ordered by last activity)
     * Returns Flow for reactive updates
     */
    @Query("SELECT * FROM groups ORDER BY lastActivityTimestamp DESC")
    fun getAllGroupsFlow(): Flow<List<Group>>

    /**
     * Get all groups (one-shot query)
     */
    @Query("SELECT * FROM groups ORDER BY lastActivityTimestamp DESC")
    suspend fun getAllGroups(): List<Group>

    /**
     * Update group name
     */
    @Query("UPDATE groups SET name = :newName WHERE groupId = :groupId")
    suspend fun updateGroupName(groupId: String, newName: String)

    /**
     * Update group icon
     */
    @Query("UPDATE groups SET groupIcon = :icon WHERE groupId = :groupId")
    suspend fun updateGroupIcon(groupId: String, icon: String)

    /**
     * Update group PIN
     */
    @Query("UPDATE groups SET groupPin = :newPin WHERE groupId = :groupId")
    suspend fun updateGroupPin(groupId: String, newPin: String)

    /**
     * Update last activity timestamp
     */
    @Query("UPDATE groups SET lastActivityTimestamp = :timestamp WHERE groupId = :groupId")
    suspend fun updateLastActivity(groupId: String, timestamp: Long)

    /**
     * Toggle mute status
     */
    @Query("UPDATE groups SET isMuted = :isMuted WHERE groupId = :groupId")
    suspend fun setMuted(groupId: String, isMuted: Boolean)

    /**
     * Update admin status
     */
    @Query("UPDATE groups SET isAdmin = :isAdmin WHERE groupId = :groupId")
    suspend fun setAdmin(groupId: String, isAdmin: Boolean)

    /**
     * Get group count
     */
    @Query("SELECT COUNT(*) FROM groups")
    suspend fun getGroupCount(): Int

    /**
     * Check if group exists by ID
     */
    @Query("SELECT EXISTS(SELECT 1 FROM groups WHERE groupId = :groupId)")
    suspend fun groupExists(groupId: String): Boolean

    /**
     * Delete all groups (for testing or account wipe)
     */
    @Query("DELETE FROM groups")
    suspend fun deleteAllGroups()
}
