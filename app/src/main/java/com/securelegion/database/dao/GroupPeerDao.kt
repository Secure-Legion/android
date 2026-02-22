package com.securelegion.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.securelegion.database.entities.GroupPeer

/**
 * DAO for group peer routing entries.
 *
 * GroupPeer stores onion addresses for group members who may not be in the
 * Contact (friend) table. All methods are suspend (called from coroutines).
 */
@Dao
interface GroupPeerDao {

    @Query("SELECT * FROM group_peers WHERE groupId = :groupId AND pubkeyHex = :pubkeyHex LIMIT 1")
    suspend fun getByGroupAndPubkey(groupId: String, pubkeyHex: String): GroupPeer?

    @Query("SELECT * FROM group_peers WHERE groupId = :groupId AND x25519PubkeyHex = :x25519Hex LIMIT 1")
    suspend fun getByGroupAndX25519(groupId: String, x25519Hex: String): GroupPeer?

    @Query("SELECT * FROM group_peers WHERE groupId = :groupId")
    suspend fun getPeersForGroup(groupId: String): List<GroupPeer>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertPeer(peer: GroupPeer)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertPeers(peers: List<GroupPeer>)

    @Query("DELETE FROM group_peers WHERE groupId = :groupId AND pubkeyHex = :pubkeyHex")
    suspend fun deletePeer(groupId: String, pubkeyHex: String)

    @Query("DELETE FROM group_peers WHERE groupId = :groupId")
    suspend fun deletePeersForGroup(groupId: String)

    @Query("SELECT DISTINCT groupId FROM group_peers WHERE messagingOnion = :onionAddress")
    suspend fun getGroupIdsForPeer(onionAddress: String): List<String>
}
