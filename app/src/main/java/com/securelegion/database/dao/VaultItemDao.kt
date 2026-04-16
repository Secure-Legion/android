package com.securelegion.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.securelegion.database.entities.VaultItem

@Dao
interface VaultItemDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(item: VaultItem)

    /**
     * Fetch all vault items, optionally filtered by type.
     * Pass null to fetch all types.
     */
    @Query("SELECT * FROM vault_items ORDER BY createdAtMs DESC")
    suspend fun fetchAll(): List<VaultItem>

    @Query("SELECT * FROM vault_items WHERE type = :type ORDER BY createdAtMs DESC")
    suspend fun fetchByType(type: String): List<VaultItem>

    @Query("DELETE FROM vault_items WHERE id = :id")
    suspend fun delete(id: String): Int

    @Query("DELETE FROM vault_items")
    suspend fun deleteAll()

    @Query("SELECT COUNT(*) FROM vault_items")
    suspend fun count(): Int
}
