package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * GroupMember entity - junction table for Group ↔ Contact many-to-many relationship
 * Tracks which contacts are members of which groups
 */
@Entity(
    tableName = "group_members",
    foreignKeys = [
        ForeignKey(
            entity = Group::class,
            parentColumns = ["groupId"],
            childColumns = ["groupId"],
            onDelete = ForeignKey.CASCADE
        ),
        ForeignKey(
            entity = Contact::class,
            parentColumns = ["id"],
            childColumns = ["contactId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index(value = ["groupId"]),
        Index(value = ["contactId"]),
        Index(value = ["groupId", "contactId"], unique = true)
    ]
)
data class GroupMember(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /**
     * ID of the group
     */
    val groupId: String,

    /**
     * ID of the contact who is a member
     */
    val contactId: Long,

    /**
     * Whether this member is an admin
     * Admins can add/remove members and change group settings
     */
    val isAdmin: Boolean = false,

    /**
     * Unix timestamp when this member was added (milliseconds)
     */
    val addedAt: Long,

    /**
     * ID of the contact who added this member
     * Null if they were added during group creation
     */
    val addedBy: Long? = null
)
