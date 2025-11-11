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
     * Get contact by Tor onion address
     */
    @Query("SELECT * FROM contacts WHERE torOnionAddress = :onionAddress")
    suspend fun getContactByOnionAddress(onionAddress: String): Contact?

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
}
