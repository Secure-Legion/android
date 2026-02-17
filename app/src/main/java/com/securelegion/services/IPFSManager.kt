package com.securelegion.services

import android.content.Context
import android.util.Log
import com.securelegion.crypto.RustBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * IPFS Auto-Pinning Mesh Manager (v5 Architecture)
 *
 * Manages local pinning of friends' contact cards to create P2P backup redundancy.
 *
 * Key Features:
 * - Auto-pin friend's contact card when adding them
 * - Local storage of pinned contact cards (encrypted by their PIN)
 * - Organic redundancy mesh: more friends = more backups
 * - Contact list recovery from IPFS mesh
 *
 * Architecture:
 * - Contact cards are served via .onion HTTP server (primary distribution)
 * - This manager pins them locally for redundancy and recovery
 * - Each user stores their friends' cards = distributed P2P mesh
 * - No external IPFS services (Crust/Pinata) needed
 *
 * Storage Format:
 * - Files stored in: {app_data}/ipfs_pins/{cid}
 * - Each file contains the encrypted contact card (same format as served via .onion)
 * - Metadata tracked in: ipfs_pins.json
 */
class IPFSManager private constructor(private val context: Context) {

    companion object {
        private const val TAG = "IPFSManager"
        private const val PINS_DIR = "ipfs_pins"
        private const val METADATA_FILE = "ipfs_pins.json"

        @Volatile
        private var instance: IPFSManager? = null

        fun getInstance(context: Context): IPFSManager {
            return instance ?: synchronized(this) {
                instance ?: IPFSManager(context.applicationContext).also { instance = it }
            }
        }
    }

    // Directory for storing pinned contact cards
    private val pinsDirectory: File by lazy {
        File(context.filesDir, PINS_DIR).apply {
            if (!exists()) {
                mkdirs()
                Log.d(TAG, "Created IPFS pins directory: $absolutePath")
            }
        }
    }

    // Metadata file for tracking pins
    private val metadataFile: File by lazy {
        File(context.filesDir, METADATA_FILE)
    }

    /**
     * Pin metadata - tracks what's pinned and when
     */
    data class PinMetadata(
        val cid: String,
        val displayName: String,
        val pinnedTimestamp: Long,
        val size: Int
    )

    /**
     * Initialize IPFS Manager
     * Sets up local storage for pinned contact cards
     */
    suspend fun initialize(): Result<Unit> {
        return withContext(Dispatchers.IO) {
            try {
                // Ensure pins directory exists
                if (!pinsDirectory.exists()) {
                    pinsDirectory.mkdirs()
                }

                // Initialize metadata if not exists
                if (!metadataFile.exists()) {
                    metadataFile.writeText("{\"pins\":[]}")
                }

                Log.i(TAG, "IPFS Manager initialized")
                Log.i(TAG, "Pins directory: ${pinsDirectory.absolutePath}")

                Result.success(Unit)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to initialize IPFS Manager", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Pin a contact card to local IPFS storage
     * This creates a local backup copy of the friend's encrypted contact card
     *
     * @param cid IPFS CID of the contact card
     * @param encryptedCard Encrypted contact card data (PIN-encrypted)
     * @param displayName Friend's display name (for logging/tracking)
     * @return Result indicating success or failure
     */
    suspend fun pinContactCard(
        cid: String,
        encryptedCard: ByteArray,
        displayName: String
    ): Result<Unit> {
        return withContext(Dispatchers.IO) {
            try {
                // Check if already pinned
                if (isPinned(cid)) {
                    Log.d(TAG, "Contact card already pinned: $cid ($displayName)")
                    return@withContext Result.success(Unit)
                }

                // Save encrypted contact card to local storage
                val pinFile = File(pinsDirectory, cid)
                pinFile.writeBytes(encryptedCard)

                // Update metadata
                val metadata = PinMetadata(
                    cid = cid,
                    displayName = displayName,
                    pinnedTimestamp = System.currentTimeMillis(),
                    size = encryptedCard.size
                )
                addPinMetadata(metadata)

                Log.i(TAG, "Pinned contact card: $cid ($displayName, ${encryptedCard.size} bytes)")
                Log.i(TAG, "Total pins: ${getPinnedCIDs().size}")

                Result.success(Unit)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to pin contact card: $cid", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Unpin a contact card (remove from local storage)
     * Used when removing a friend
     *
     * @param cid IPFS CID to unpin
     * @return Result indicating success or failure
     */
    suspend fun unpinContactCard(cid: String): Result<Unit> {
        return withContext(Dispatchers.IO) {
            try {
                val pinFile = File(pinsDirectory, cid)
                if (pinFile.exists()) {
                    pinFile.delete()
                    removePinMetadata(cid)
                    Log.i(TAG, "Unpinned contact card: $cid")
                    Log.i(TAG, "Total pins: ${getPinnedCIDs().size}")
                }

                Result.success(Unit)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to unpin contact card: $cid", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Get a pinned contact card from local storage
     *
     * @param cid IPFS CID to retrieve
     * @return Encrypted contact card bytes, or null if not pinned
     */
    suspend fun getPinnedContactCard(cid: String): ByteArray? {
        return withContext(Dispatchers.IO) {
            try {
                val pinFile = File(pinsDirectory, cid)
                if (pinFile.exists()) {
                    pinFile.readBytes()
                } else {
                    null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to read pinned contact card: $cid", e)
                null
            }
        }
    }

    /**
     * Check if a CID is pinned locally
     */
    fun isPinned(cid: String): Boolean {
        val pinFile = File(pinsDirectory, cid)
        return pinFile.exists()
    }

    /**
     * Get list of all pinned CIDs
     */
    fun getPinnedCIDs(): List<String> {
        return pinsDirectory.listFiles()?.map { it.name } ?: emptyList()
    }

    /**
     * Get pinning statistics
     */
    data class PinningStats(
        val totalPins: Int,
        val totalSize: Long,
        val pinnedContacts: List<PinMetadata>
    )

    suspend fun getPinningStats(): PinningStats {
        return withContext(Dispatchers.IO) {
            val pins = getPinMetadata()
            val totalSize = pins.sumOf { it.size.toLong() }

            PinningStats(
                totalPins = pins.size,
                totalSize = totalSize,
                pinnedContacts = pins
            )
        }
    }

    /**
     * Add pin metadata
     */
    private fun addPinMetadata(metadata: PinMetadata) {
        try {
            val pins = getPinMetadata().toMutableList()

            // Remove existing entry if present (update case)
            pins.removeAll { it.cid == metadata.cid }

            // Add new entry
            pins.add(metadata)

            // Save to file
            val json = org.json.JSONObject()
            val pinsArray = org.json.JSONArray()
            for (pin in pins) {
                val pinObj = org.json.JSONObject()
                pinObj.put("cid", pin.cid)
                pinObj.put("displayName", pin.displayName)
                pinObj.put("pinnedTimestamp", pin.pinnedTimestamp)
                pinObj.put("size", pin.size)
                pinsArray.put(pinObj)
            }
            json.put("pins", pinsArray)

            metadataFile.writeText(json.toString())
        } catch (e: Exception) {
            Log.e(TAG, "Failed to add pin metadata", e)
        }
    }

    /**
     * Remove pin metadata
     */
    private fun removePinMetadata(cid: String) {
        try {
            val pins = getPinMetadata().toMutableList()
            pins.removeAll { it.cid == cid }

            // Save to file
            val json = org.json.JSONObject()
            val pinsArray = org.json.JSONArray()
            for (pin in pins) {
                val pinObj = org.json.JSONObject()
                pinObj.put("cid", pin.cid)
                pinObj.put("displayName", pin.displayName)
                pinObj.put("pinnedTimestamp", pin.pinnedTimestamp)
                pinObj.put("size", pin.size)
                pinsArray.put(pinObj)
            }
            json.put("pins", pinsArray)

            metadataFile.writeText(json.toString())
        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove pin metadata", e)
        }
    }

    /**
     * Get all pin metadata
     */
    private fun getPinMetadata(): List<PinMetadata> {
        return try {
            if (!metadataFile.exists()) {
                return emptyList()
            }

            val jsonText = metadataFile.readText()
            val json = org.json.JSONObject(jsonText)
            val pinsArray = json.getJSONArray("pins")

            val pins = mutableListOf<PinMetadata>()
            for (i in 0 until pinsArray.length()) {
                val pinObj = pinsArray.getJSONObject(i)
                pins.add(
                    PinMetadata(
                        cid = pinObj.getString("cid"),
                        displayName = pinObj.getString("displayName"),
                        pinnedTimestamp = pinObj.getLong("pinnedTimestamp"),
                        size = pinObj.getInt("size")
                    )
                )
            }

            pins
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read pin metadata", e)
            emptyList()
        }
    }

    /**
     * Cleanup orphaned pins (pins without metadata)
     */
    suspend fun cleanupOrphanedPins(): Result<Int> {
        return withContext(Dispatchers.IO) {
            try {
                val metadata = getPinMetadata()
                val metadataCIDs = metadata.map { it.cid }.toSet()
                val fileCIDs = pinsDirectory.listFiles()?.map { it.name } ?: emptyList()

                var cleaned = 0
                for (fileCID in fileCIDs) {
                    if (fileCID !in metadataCIDs) {
                        File(pinsDirectory, fileCID).delete()
                        cleaned++
                        Log.d(TAG, "Cleaned orphaned pin: $fileCID")
                    }
                }

                Log.i(TAG, "Cleaned $cleaned orphaned pins")
                Result.success(cleaned)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to cleanup orphaned pins", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Export pinned contact cards for recovery
     * Used when recovering account from seed phrase
     *
     * @return List of all pinned contact cards with their CIDs
     */
    suspend fun exportPinnedCards(): List<Pair<String, ByteArray>> {
        return withContext(Dispatchers.IO) {
            val pins = getPinMetadata()
            pins.mapNotNull { metadata ->
                val card = getPinnedContactCard(metadata.cid)
                if (card != null) {
                    Pair(metadata.cid, card)
                } else {
                    null
                }
            }
        }
    }

    // ==================== CONTACT LIST BACKUP (v5 Architecture) ====================

    /**
     * Store user's own contact list at deterministic CID (v5)
     * This is the user's complete contact list, encrypted and stored locally
     * Friends will pin this when they add the user
     *
     * @param cid Deterministic contact list CID (derived from seed)
     * @param encryptedList Encrypted contact list JSON
     * @return Result indicating success or failure
     */
    suspend fun storeContactList(cid: String, encryptedList: ByteArray): Result<Unit> {
        return withContext(Dispatchers.IO) {
            try {
                // Save encrypted contact list to local storage
                val listFile = File(pinsDirectory, cid)
                listFile.writeBytes(encryptedList)

                // Update metadata
                val metadata = PinMetadata(
                    cid = cid,
                    displayName = "My Contact List", // User's own list
                    pinnedTimestamp = System.currentTimeMillis(),
                    size = encryptedList.size
                )
                addPinMetadata(metadata)

                // Serve contact list via HTTP server (v5 architecture)
                RustBridge.serveContactList(cid, encryptedList, encryptedList.size)

                Log.i(TAG, "Stored and served contact list: $cid (${encryptedList.size} bytes)")
                Result.success(Unit)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to store contact list: $cid", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Fetch contact list from friend's .onion address via Tor HTTP (v5 architecture)
     *
     * @param onionAddress Friend's .onion address (friend request or messaging)
     * @param contactListCID Friend's contact list CID
     * @return Encrypted contact list bytes, or null if fetch failed
     */
    suspend fun fetchContactListViaTor(onionAddress: String, contactListCID: String): ByteArray? {
        return withContext(Dispatchers.IO) {
            try {
                // Construct URL: http://[onion].onion/contact-list/[cid]
                val url = "http://$onionAddress/contact-list/$contactListCID"
                Log.d(TAG, "Fetching contact list via Tor from: $url")

                // Fetch via Tor SOCKS5 proxy using RustBridge
                val response = RustBridge.httpGetViaTor(url)

                if (response != null) {
                    // Response is the raw bytes (base64 encoded by Rust)
                    val bytes = android.util.Base64.decode(response, android.util.Base64.DEFAULT)
                    Log.i(TAG, "Fetched contact list via Tor: $contactListCID (${bytes.size} bytes)")
                    bytes
                } else {
                    Log.w(TAG, "Failed to fetch contact list via Tor: $url")
                    null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error fetching contact list via Tor", e)
                null
            }
        }
    }

    /**
     * Pin a friend's contact list to local storage (v5)
     * This creates redundancy - user contributes to friend's backup mesh
     *
     * @param friendCID Friend's contact list CID
     * @param displayName Friend's display name (for tracking)
     * @param friendOnion Friend's .onion address for fetching (optional)
     * @return Result indicating success or failure
     */
    suspend fun pinFriendContactList(friendCID: String, displayName: String, friendOnion: String? = null): Result<Unit> {
        return withContext(Dispatchers.IO) {
            try {
                // Try to fetch friend's contact list via their .onion address
                if (friendOnion != null) {
                    val listData = fetchContactListViaTor(friendOnion, friendCID)

                    if (listData != null) {
                        // Store the friend's contact list locally
                        val listFile = File(pinsDirectory, friendCID)
                        listFile.writeBytes(listData)

                        // Update metadata
                        val metadata = PinMetadata(
                            cid = friendCID,
                            displayName = "$displayName's Contact List",
                            pinnedTimestamp = System.currentTimeMillis(),
                            size = listData.size
                        )
                        addPinMetadata(metadata)

                        Log.i(TAG, "Pinned $displayName's contact list: $friendCID (${listData.size} bytes)")
                        return@withContext Result.success(Unit)
                    } else {
                        Log.w(TAG, "Could not fetch $displayName's contact list from .onion")
                    }
                }

                // If fetch failed or no .onion provided, just mark intent
                Log.d(TAG, "Marked friend's contact list for pinning: $friendCID ($displayName)")
                Result.success(Unit)

            } catch (e: Exception) {
                Log.e(TAG, "Failed to pin friend's contact list: $friendCID", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Get a contact list from local storage (v5)
     * Used during account recovery to restore contacts from IPFS mesh
     *
     * @param cid Contact list CID to retrieve
     * @return Encrypted contact list bytes, or null if not found
     */
    suspend fun getContactList(cid: String): ByteArray? {
        return withContext(Dispatchers.IO) {
            try {
                val listFile = File(pinsDirectory, cid)
                if (listFile.exists()) {
                    val data = listFile.readBytes()
                    Log.i(TAG, "Retrieved contact list: $cid (${data.size} bytes)")
                    data
                } else {
                    Log.d(TAG, "Contact list not found locally: $cid")
                    null
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to read contact list: $cid", e)
                null
            }
        }
    }

    /**
     * Unpin a friend's contact list (v5)
     * Called when removing a friend from contacts
     *
     * @param friendCID Friend's contact list CID to unpin
     * @return Result indicating success or failure
     */
    suspend fun unpinFriendContactList(friendCID: String): Result<Unit> {
        return withContext(Dispatchers.IO) {
            try {
                val listFile = File(pinsDirectory, friendCID)
                if (listFile.exists()) {
                    listFile.delete()
                    removePinMetadata(friendCID)
                    Log.i(TAG, "Unpinned friend's contact list: $friendCID")
                }

                Result.success(Unit)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to unpin friend's contact list: $friendCID", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Get statistics for contact list mesh (v5)
     */
    data class ContactListMeshStats(
        val ownListSize: Long,
        val friendListsCount: Int,
        val totalMeshSize: Long,
        val redundancyFactor: Int // How many friends are backing up user's list
    )

    suspend fun getContactListMeshStats(): ContactListMeshStats? {
        return withContext(Dispatchers.IO) {
            try {
                val pins = getPinMetadata()

                // Find user's own list (marked as "My Contact List")
                val ownList = pins.firstOrNull { it.displayName == "My Contact List" }
                val friendLists = pins.filter { it.displayName != "My Contact List" }

                ContactListMeshStats(
                    ownListSize = ownList?.size?.toLong() ?: 0L,
                    friendListsCount = friendLists.size,
                    totalMeshSize = pins.sumOf { it.size.toLong() },
                    redundancyFactor = friendLists.size // Each friend should be pinning user's list
                )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to get contact list mesh stats", e)
                null
            }
        }
    }
}
