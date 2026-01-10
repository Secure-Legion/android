package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.GroupMember
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for GroupMember operations
 * All queries run on background thread via coroutines
 */
@Dao
interface GroupMemberDao {

    /**
     * Insert a new group member
     * @return ID of inserted group member
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertGroupMember(groupMember: GroupMember): Long

    /**
     * Insert multiple group members (bulk operation)
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertGroupMembers(groupMembers: List<GroupMember>)

    /**
     * Update existing group member
     */
    @Update
    suspend fun updateGroupMember(groupMember: GroupMember)

    /**
     * Delete group member
     */
    @Delete
    suspend fun deleteGroupMember(groupMember: GroupMember)

    /**
     * Remove member from group
     */
    @Query("DELETE FROM group_members WHERE groupId = :groupId AND contactId = :contactId")
    suspend fun removeMemberFromGroup(groupId: String, contactId: Long)

    /**
     * Get all members for a group
     */
    @Query("SELECT * FROM group_members WHERE groupId = :groupId ORDER BY addedAt ASC")
    suspend fun getMembersForGroup(groupId: String): List<GroupMember>

    /**
     * Get all members for a group with contact details (join query)
     */
    @Query("""
        SELECT contacts.* FROM contacts
        INNER JOIN group_members ON contacts.id = group_members.contactId
        WHERE group_members.groupId = :groupId
        ORDER BY group_members.addedAt ASC
    """)
    suspend fun getContactsForGroup(groupId: String): List<Contact>

    /**
     * Get all members for a group (reactive)
     */
    @Query("SELECT * FROM group_members WHERE groupId = :groupId ORDER BY addedAt ASC")
    fun getMembersForGroupFlow(groupId: String): Flow<List<GroupMember>>

    /**
     * Get member count for a group
     */
    @Query("SELECT COUNT(*) FROM group_members WHERE groupId = :groupId")
    suspend fun getMemberCount(groupId: String): Int

    /**
     * Check if contact is a member of group
     */
    @Query("SELECT EXISTS(SELECT 1 FROM group_members WHERE groupId = :groupId AND contactId = :contactId)")
    suspend fun isMember(groupId: String, contactId: Long): Boolean

    /**
     * Check if contact is an admin of group
     */
    @Query("SELECT isAdmin FROM group_members WHERE groupId = :groupId AND contactId = :contactId")
    suspend fun isAdmin(groupId: String, contactId: Long): Boolean?

    /**
     * Set admin status for a member
     */
    @Query("UPDATE group_members SET isAdmin = :isAdmin WHERE groupId = :groupId AND contactId = :contactId")
    suspend fun setAdminStatus(groupId: String, contactId: Long, isAdmin: Boolean)

    /**
     * Get all admin members for a group
     */
    @Query("SELECT * FROM group_members WHERE groupId = :groupId AND isAdmin = 1")
    suspend fun getAdminsForGroup(groupId: String): List<GroupMember>

    /**
     * Delete all members for a group (when deleting group)
     */
    @Query("DELETE FROM group_members WHERE groupId = :groupId")
    suspend fun deleteAllMembersForGroup(groupId: String)

    /**
     * Get all groups a contact is a member of
     */
    @Query("SELECT groupId FROM group_members WHERE contactId = :contactId")
    suspend fun getGroupsForContact(contactId: Long): List<String>

    /**
     * Delete all group members (for testing or account wipe)
     */
    @Query("DELETE FROM group_members")
    suspend fun deleteAllGroupMembers()
}
