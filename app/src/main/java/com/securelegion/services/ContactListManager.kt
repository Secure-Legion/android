package com.securelegion.services

import android.content.Context
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * ContactListManager - Handles IPFS Contact List Backup Mesh (v5 Architecture)
 *
 * Key Features:
 * - Export entire contact list to encrypted JSON
 * - Store at deterministic CID (derived from seed phrase)
 * - Friends auto-pin each other's complete contact lists
 * - Recovery: Query IPFS mesh → Download → Decrypt → Restore all contacts
 *
 * Storage Efficiency:
 * - Old way (v4): 50 friends × 50 cards each = 2500 files
 * - New way (v5): 50 friends × 1 list each = 50 files
 *
 * Redundancy:
 * - With 50 friends, your contact list is backed up 51 times (you + 50 friends)
 * - Any friend's device can provide your full contact list during recovery
 */
class ContactListManager private constructor(private val context: Context) {

    companion object {
        private const val TAG = "ContactListManager"
        private const val CONTACT_LIST_VERSION = 1

        @Volatile
        private var instance: ContactListManager? = null

        fun getInstance(context: Context): ContactListManager {
            return instance ?: synchronized(this) {
                instance ?: ContactListManager(context.applicationContext).also { instance = it }
            }
        }
    }

    /**
     * Contact List JSON Format:
     * {
     * "version": 1,
     * "timestamp": 1234567890,
     * "totalContacts": 50,
     * "contacts": [
     * {
     * "displayName": "Alice",
     * "onionAddress": "abc123...onion",
     * "publicKey": "...",
     * "profilePictureHash": "...",
     * "isDistressContact": false,
     * "isBlocked": false,
     * "ipfsCid": "Qm...",
     * "addedTimestamp": 1234567890
     * },
     * ...
     * ]
     * }
     */

    /**
     * Export all contacts from database to encrypted JSON
     *
     * @return Encrypted contact list as ByteArray, or null on error
     */
    suspend fun exportContactList(): Result<ByteArray> {
        return try {
            val keyManager = KeyManager.getInstance(context)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Get all contacts from database
            val contacts = database.contactDao().getAllContacts()
            Log.d(TAG, "Exporting ${contacts.size} contacts to JSON")

            // Build JSON
            val json = JSONObject().apply {
                put("version", CONTACT_LIST_VERSION)
                put("timestamp", System.currentTimeMillis())
                put("totalContacts", contacts.size)

                val contactsArray = JSONArray()
                contacts.forEach { contact ->
                    val contactJson = JSONObject().apply {
                        put("displayName", contact.displayName)
                        put("solanaAddress", contact.solanaAddress)
                        put("publicKeyBase64", contact.publicKeyBase64)
                        put("x25519PublicKeyBase64", contact.x25519PublicKeyBase64)
                        put("friendRequestOnion", contact.friendRequestOnion)
                        put("messagingOnion", contact.messagingOnion ?: "")
                        put("isDistressContact", contact.isDistressContact)
                        put("isBlocked", contact.isBlocked)
                        put("ipfsCid", contact.ipfsCid ?: "")
                        put("contactPin", contact.contactPin ?: "")
                        put("addedTimestamp", contact.addedTimestamp)
                    }
                    contactsArray.put(contactJson)
                }
                put("contacts", contactsArray)
            }

            // Derive PIN from seed for contact list encryption (v5 architecture)
            // This is different from the contact card PIN
            val seedPhrase = keyManager.getMainWalletSeedForZcash()
                ?: throw IllegalStateException("Seed phrase not found")
            val pin = keyManager.deriveContactPinFromSeed(seedPhrase)
            val encryptedData = encryptContactList(json.toString(), pin)

            Log.i(TAG, "Contact list exported and encrypted (${encryptedData.size} bytes)")
            Result.success(encryptedData)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to export contact list", e)
            Result.failure(e)
        }
    }

    /**
     * Import contact list from encrypted JSON
     *
     * @param encryptedData Encrypted contact list
     * @param pin PIN for decryption (derived from seed)
     * @return Number of contacts imported
     */
    suspend fun importContactList(encryptedData: ByteArray, pin: String): Result<Int> {
        return try {
            // Decrypt contact list
            val decryptedJson = decryptContactList(encryptedData, pin)
            val json = JSONObject(decryptedJson)

            // Validate version
            val version = json.getInt("version")
            if (version != CONTACT_LIST_VERSION) {
                throw IllegalArgumentException("Unsupported contact list version: $version")
            }

            val totalContacts = json.getInt("totalContacts")
            Log.d(TAG, "Importing contact list with $totalContacts contacts")

            // Parse contacts
            val contactsArray = json.getJSONArray("contacts")
            val contacts = mutableListOf<Contact>()

            for (i in 0 until contactsArray.length()) {
                val contactJson = contactsArray.getJSONObject(i)
                val contact = Contact(
                    id = 0, // Will be auto-generated
                    displayName = contactJson.getString("displayName"),
                    solanaAddress = contactJson.getString("solanaAddress"),
                    publicKeyBase64 = contactJson.getString("publicKeyBase64"),
                    x25519PublicKeyBase64 = contactJson.getString("x25519PublicKeyBase64"),
                    friendRequestOnion = contactJson.getString("friendRequestOnion"),
                    messagingOnion = contactJson.optString("messagingOnion", null),
                    isDistressContact = contactJson.optBoolean("isDistressContact", false),
                    isBlocked = contactJson.optBoolean("isBlocked", false),
                    ipfsCid = contactJson.optString("ipfsCid", null),
                    contactPin = contactJson.optString("contactPin", null),
                    addedTimestamp = contactJson.getLong("addedTimestamp")
                )
                contacts.add(contact)
            }

            // Insert into database
            val keyManager = KeyManager.getInstance(context)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            // Clear existing contacts (we're doing a full restore)
            database.contactDao().deleteAllContacts()

            // Insert all contacts
            contacts.forEach { contact ->
                database.contactDao().insertContact(contact)
            }

            Log.i(TAG, "Contact list imported: ${contacts.size} contacts restored")
            Result.success(contacts.size)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to import contact list", e)
            Result.failure(e)
        }
    }

    /**
     * Backup contact list to IPFS mesh
     *
     * This should be called whenever:
     * - A new friend is added
     * - A friend is removed
     * - Contact details are updated (display name, etc.)
     */
    suspend fun backupToIPFS(): Result<String> {
        return try {
            // Export contact list
            val exportResult = exportContactList()
            if (exportResult.isFailure) {
                return Result.failure(exportResult.exceptionOrNull()!!)
            }

            val encryptedData = exportResult.getOrThrow()

            // Get deterministic CID
            val keyManager = KeyManager.getInstance(context)
            val contactListCID = keyManager.deriveContactListCID()

            // Store in local IPFS
            val ipfsManager = IPFSManager.getInstance(context)
            val storeResult = ipfsManager.storeContactList(contactListCID, encryptedData)

            if (storeResult.isSuccess) {
                Log.i(TAG, "Contact list backed up to IPFS: $contactListCID")
                Result.success(contactListCID)
            } else {
                Result.failure(storeResult.exceptionOrNull()!!)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to backup contact list to IPFS", e)
            Result.failure(e)
        }
    }

    /**
     * Recover contact list from IPFS mesh
     *
     * Called during account restoration from seed phrase.
     * Queries IPFS mesh for user's contact list, downloads from any friend's node,
     * decrypts, and restores all contacts to database.
     *
     * @param seedPhrase User's BIP39 seed phrase
     * @return Number of contacts recovered, or null if not found
     */
    suspend fun recoverFromIPFS(seedPhrase: String): Result<Int?> {
        return try {
            val keyManager = KeyManager.getInstance(context)

            // Derive contact list CID from seed (deterministic)
            val contactListCID = keyManager.deriveContactListCIDFromSeed(seedPhrase)
            Log.d(TAG, "Attempting to recover contact list from IPFS: $contactListCID")

            // Query IPFS mesh for contact list
            val ipfsManager = IPFSManager.getInstance(context)
            val encryptedData = ipfsManager.getContactList(contactListCID)

            if (encryptedData == null) {
                Log.w(TAG, "Contact list not found in IPFS mesh")
                return Result.success(null)
            }

            Log.i(TAG, "Contact list found in IPFS mesh (${encryptedData.size} bytes)")

            // Derive PIN from seed
            val pin = keyManager.deriveContactPinFromSeed(seedPhrase)

            // Import and restore contacts
            val importResult = importContactList(encryptedData, pin)
            if (importResult.isFailure) {
                return Result.failure(importResult.exceptionOrNull()!!)
            }

            val contactsRestored = importResult.getOrThrow()
            Log.i(TAG, "Contact list recovered from IPFS: $contactsRestored contacts restored")

            // Re-pin all friends' contact lists (restore mesh participation)
            repinFriendsContactLists()

            Result.success(contactsRestored)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to recover contact list from IPFS", e)
            Result.failure(e)
        }
    }

    /**
     * Re-pin all friends' contact lists
     *
     * Called after recovering from seed to restore participation in IPFS mesh.
     * Ensures user contributes backup redundancy to all friends.
     */
    private suspend fun repinFriendsContactLists() {
        try {
            val keyManager = KeyManager.getInstance(context)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            val contacts = database.contactDao().getAllContacts()
            val ipfsManager = IPFSManager.getInstance(context)

            Log.d(TAG, "Re-pinning ${contacts.size} friends' contact lists...")

            contacts.forEach { contact ->
                if (contact.ipfsCid != null) {
                    // Pin friend's contact list (not individual card - that's old v4 architecture)
                    // In v5, each friend has a contact list CID stored in ipfsCid field
                    val pinResult = ipfsManager.pinFriendContactList(contact.ipfsCid, contact.displayName)
                    if (pinResult.isSuccess) {
                        Log.d(TAG, "Re-pinned ${contact.displayName}'s contact list")
                    }
                }
            }

            Log.i(TAG, "Re-pinned all friends' contact lists")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to re-pin friends' contact lists", e)
        }
    }

    /**
     * Encrypt contact list with PIN
     *
     * Uses AES-256-GCM for authenticated encryption.
     * Key derived from PIN using PBKDF2 with 100,000 iterations.
     *
     * Format: [16-byte salt][12-byte IV][encrypted data + 16-byte auth tag]
     */
    private fun encryptContactList(plaintext: String, pin: String): ByteArray {
        try {
            // Generate random salt for PBKDF2
            val salt = ByteArray(16)
            java.security.SecureRandom().nextBytes(salt)

            // Derive key from PIN using PBKDF2
            val spec = PBEKeySpec(pin.toCharArray(), salt, 100000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val keyBytes = factory.generateSecret(spec).encoded
            val key = SecretKeySpec(keyBytes, "AES")

            // Generate random IV
            val iv = ByteArray(12)
            java.security.SecureRandom().nextBytes(iv)

            // Encrypt with AES-GCM
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            val encrypted = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

            // Return: salt || IV || encrypted data (includes auth tag)
            return salt + iv + encrypted

        } catch (e: Exception) {
            Log.e(TAG, "Encryption failed", e)
            throw e
        }
    }

    /**
     * Decrypt contact list with PIN
     *
     * @param ciphertext Encrypted data (format: salt || IV || encrypted data)
     * @param pin PIN for decryption
     * @return Decrypted JSON string
     */
    private fun decryptContactList(ciphertext: ByteArray, pin: String): String {
        try {
            // Extract salt, IV, and encrypted data
            val salt = ciphertext.sliceArray(0 until 16)
            val iv = ciphertext.sliceArray(16 until 28)
            val encrypted = ciphertext.sliceArray(28 until ciphertext.size)

            // Derive key from PIN
            val spec = PBEKeySpec(pin.toCharArray(), salt, 100000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val keyBytes = factory.generateSecret(spec).encoded
            val key = SecretKeySpec(keyBytes, "AES")

            // Decrypt with AES-GCM
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            val decrypted = cipher.doFinal(encrypted)

            return String(decrypted, Charsets.UTF_8)

        } catch (e: Exception) {
            Log.e(TAG, "Decryption failed", e)
            throw e
        }
    }
}
