package com.securelegion.database.dao

import androidx.room.*
import com.securelegion.database.entities.ContactKeyChain

/**
 * Data Access Object for ContactKeyChain operations
 * Manages progressive ephemeral key evolution state for each contact
 */
@Dao
interface ContactKeyChainDao {

    /**
     * Insert a new key chain for a contact
     * This happens when a contact is added or when initializing key evolution
     *
     * @param keyChain Key chain to insert
     * @return ID of inserted key chain
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertKeyChain(keyChain: ContactKeyChain): Long

    /**
     * Update existing key chain
     * Used after evolving keys for each message
     */
    @Update
    suspend fun updateKeyChain(keyChain: ContactKeyChain)

    /**
     * Delete key chain for a contact
     * Called when contact is deleted (also handled by CASCADE)
     */
    @Delete
    suspend fun deleteKeyChain(keyChain: ContactKeyChain)

    /**
     * Get key chain by contact ID
     * Returns null if key chain doesn't exist (not initialized yet)
     *
     * @param contactId Contact ID
     * @return Key chain or null
     */
    @Query("SELECT * FROM contact_key_chains WHERE contactId = :contactId LIMIT 1")
    suspend fun getKeyChainByContactId(contactId: Long): ContactKeyChain?

    /**
     * Update send chain key after sending a message
     * Atomically updates send chain key, send counter, and evolution timestamp
     *
     * @param contactId Contact ID
     * @param newSendChainKeyBase64 Evolved send chain key (Base64)
     * @param newSendCounter Incremented send counter
     * @param timestamp Evolution timestamp
     */
    @Query("""
        UPDATE contact_key_chains
        SET sendChainKeyBase64 = :newSendChainKeyBase64,
            sendCounter = :newSendCounter,
            lastEvolutionTimestamp = :timestamp
        WHERE contactId = :contactId
    """)
    suspend fun updateSendChainKey(
        contactId: Long,
        newSendChainKeyBase64: String,
        newSendCounter: Long,
        timestamp: Long
    )

    /**
     * Update receive chain key after receiving a message
     * Atomically updates receive chain key, receive counter, and evolution timestamp
     *
     * @param contactId Contact ID
     * @param newReceiveChainKeyBase64 Evolved receive chain key (Base64)
     * @param newReceiveCounter Incremented receive counter
     * @param timestamp Evolution timestamp
     */
    @Query("""
        UPDATE contact_key_chains
        SET receiveChainKeyBase64 = :newReceiveChainKeyBase64,
            receiveCounter = :newReceiveCounter,
            lastEvolutionTimestamp = :timestamp
        WHERE contactId = :contactId
    """)
    suspend fun updateReceiveChainKey(
        contactId: Long,
        newReceiveChainKeyBase64: String,
        newReceiveCounter: Long,
        timestamp: Long
    )

    /**
     * Get all key chains (for debugging/diagnostics)
     */
    @Query("SELECT * FROM contact_key_chains")
    suspend fun getAllKeyChains(): List<ContactKeyChain>

    /**
     * Check if key chain exists for contact
     *
     * @param contactId Contact ID
     * @return True if key chain exists
     */
    @Query("SELECT EXISTS(SELECT 1 FROM contact_key_chains WHERE contactId = :contactId)")
    suspend fun keyChainExists(contactId: Long): Boolean

    /**
     * Delete all key chains (for testing or account wipe)
     */
    @Query("DELETE FROM contact_key_chains")
    suspend fun deleteAllKeyChains()

    /**
     * Get key chain count (for diagnostics)
     */
    @Query("SELECT COUNT(*) FROM contact_key_chains")
    suspend fun getKeyChainCount(): Int

    /**
     * Reset both send and receive counters to 0 for a contact
     * Used to fix key chain desynchronization issues
     * WARNING: Both parties must reset at the same time!
     */
    @Query("""
        UPDATE contact_key_chains
        SET sendCounter = 0,
            receiveCounter = 0,
            lastEvolutionTimestamp = :timestamp
        WHERE contactId = :contactId
    """)
    suspend fun resetCounters(contactId: Long, timestamp: Long)
}
