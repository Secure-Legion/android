package com.securelegion.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.securelegion.database.entities.PendingPing

/**
 * DAO for pending ping signer expectations.
 *
 * Methods are BLOCKING (not suspend) because Rust calls them synchronously via JNI
 * from non-coroutine threads (listener thread, send thread).
 */
@Dao
interface PendingPingDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun upsert(entity: PendingPing)

    @Query("SELECT signerPubKey FROM pending_pings WHERE pingId = :id LIMIT 1")
    fun getSigner(id: String): ByteArray?

    @Query("DELETE FROM pending_pings WHERE pingId = :id")
    fun delete(id: String)

    @Query("DELETE FROM pending_pings WHERE expiresAtElapsed < :now")
    fun purgeExpired(now: Long)

    @Query("SELECT COUNT(*) FROM pending_pings")
    fun count(): Int
}
