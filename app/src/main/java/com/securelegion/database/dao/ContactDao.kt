package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.Contact
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for Contact operations
 * All queries run on background thread via coroutines
 */
@Dao
interface ContactDao {

    /**
     * Insert a new contact
     * @return ID of inserted contact
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertContact(contact: Contact): Long

    /**
     * Update existing contact
     */
    @Update
    suspend fun updateContact(contact: Contact)

    /**
     * Delete contact
     */
    @Delete
    suspend fun deleteContact(contact: Contact)

    /**
     * Get contact by ID
     */
    @Query("SELECT * FROM contacts WHERE id = :contactId")
    suspend fun getContactById(contactId: Long): Contact?

    /**
     * Get contact by Solana address
     */
    @Query("SELECT * FROM contacts WHERE solanaAddress = :solanaAddress")
    suspend fun getContactBySolanaAddress(solanaAddress: String): Contact?

    /**
     * Get contact by Tor onion address (checks both friend-request and messaging onions)
     */
    @Query("SELECT * FROM contacts WHERE torOnionAddress = :onionAddress OR messagingOnion = :onionAddress")
    suspend fun getContactByOnionAddress(onionAddress: String): Contact?

    /**
     * Get contact by Ed25519 public key (Base64)
     */
    @Query("SELECT * FROM contacts WHERE publicKeyBase64 = :publicKeyBase64")
    fun getContactByPublicKey(publicKeyBase64: String): Contact?

    /**
     * Get contact by X25519 public key (Base64)
     * Used for tap identification
     */
    @Query("SELECT * FROM contacts WHERE x25519PublicKeyBase64 = :x25519PublicKeyBase64")
    fun getContactByX25519PublicKey(x25519PublicKeyBase64: String): Contact?

    /**
     * Get contacts by a list of IDs (batch lookup).
     * Used by MessageRetryWorker to avoid N+1 getContactById() per message.
     */
    @Query("SELECT * FROM contacts WHERE id IN (:ids)")
    suspend fun getContactsByIds(ids: List<Long>): List<Contact>

    /**
     * Get all contacts ordered by most recent contact
     * Returns Flow for reactive updates
     */
    @Query("SELECT * FROM contacts ORDER BY lastContactTimestamp DESC")
    fun getAllContactsFlow(): Flow<List<Contact>>

    /**
     * Get all contacts (one-shot query)
     */
    @Query("SELECT * FROM contacts ORDER BY displayName ASC")
    suspend fun getAllContacts(): List<Contact>

    /**
     * Search contacts by display name
     */
    @Query("SELECT * FROM contacts WHERE displayName LIKE '%' || :query || '%' ORDER BY displayName ASC")
    suspend fun searchContacts(query: String): List<Contact>

    /**
     * Update last contact timestamp
     */
    @Query("UPDATE contacts SET lastContactTimestamp = :timestamp WHERE id = :contactId")
    suspend fun updateLastContactTime(contactId: Long, timestamp: Long)

    /**
     * Update trust level
     */
    @Query("UPDATE contacts SET trustLevel = :trustLevel WHERE id = :contactId")
    suspend fun updateTrustLevel(contactId: Long, trustLevel: Int)

    /**
     * Update contact display name
     */
    @Query("UPDATE contacts SET displayName = :displayName WHERE id = :contactId")
    suspend fun updateContactDisplayName(contactId: Long, displayName: String)

    /**
     * Update distress contact status
     */
    @Query("UPDATE contacts SET isDistressContact = :isDistressContact WHERE id = :contactId")
    suspend fun updateDistressContactStatus(contactId: Long, isDistressContact: Boolean)

    /**
     * Update blocked status
     */
    @Query("UPDATE contacts SET isBlocked = :isBlocked WHERE id = :contactId")
    suspend fun updateBlockedStatus(contactId: Long, isBlocked: Boolean)

    /**
     * Update contact profile photo
     */
    @Query("UPDATE contacts SET profilePictureBase64 = :photoBase64 WHERE id = :contactId")
    suspend fun updateContactPhoto(contactId: Long, photoBase64: String?)

    /**
     * Get all distress contacts
     */
    @Query("SELECT * FROM contacts WHERE isDistressContact = 1 ORDER BY displayName ASC")
    suspend fun getDistressContacts(): List<Contact>

    /**
     * Get contact count
     */
    @Query("SELECT COUNT(*) FROM contacts")
    suspend fun getContactCount(): Int

    /**
     * Delete all contacts (for testing or account wipe)
     */
    @Query("DELETE FROM contacts")
    suspend fun deleteAllContacts()

    /**
     * Check if contact exists by Solana address
     */
    @Query("SELECT EXISTS(SELECT 1 FROM contacts WHERE solanaAddress = :solanaAddress)")
    suspend fun contactExists(solanaAddress: String): Boolean

    /**
     * Get all contacts that need TAP sync (needsTapSync = true)
     * Used by TapSyncWorker to send "I'm online" signals
     * @return List of contacts needing TAP synchronization
     */
    @Query("SELECT * FROM contacts WHERE needsTapSync = 1 AND isBlocked = 0")
    suspend fun getContactsNeedingTapSync(): List<Contact>

    /**
     * Mark TAP as sent for a contact (set needsTapSync to false)
     * Called after successfully sending TAP to the contact
     * @param contactId The contact ID
     */
    @Query("UPDATE contacts SET needsTapSync = 0 WHERE id = :contactId")
    suspend fun markTapSent(contactId: Long)

    /**
     * Get all pinned contacts
     */
    @Query("SELECT * FROM contacts WHERE isPinned = 1 ORDER BY displayName ASC")
    suspend fun getPinnedContacts(): List<Contact>

    /**
     * Toggle pin status for a contact
     */
    @Query("UPDATE contacts SET isPinned = :isPinned WHERE id = :contactId")
    suspend fun setPinned(contactId: Long, isPinned: Boolean)
}
