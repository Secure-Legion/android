package com.securelegion.crypto

import android.content.Context
import android.util.Base64
import android.util.Log
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.ContactKeyChain
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Manages progressive ephemeral key evolution for contacts
 * Provides per-message forward secrecy using symmetric key chains
 */
object KeyChainManager {
    private const val TAG = "KeyChainManager"
    private const val ROOT_KEY_INFO = "SecureLegion-RootKey-v1"

    /**
     * Derive outgoing direction chain key from root key using HMAC-SHA256
     * This is one of two directional keys - both parties derive the same key for ONE direction
     */
    private fun deriveOutgoingChainKey(rootKey: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(rootKey, "HmacSHA256"))
        return mac.doFinal(byteArrayOf(0x03))  // HMAC(root_key, 0x03)
    }

    /**
     * Derive incoming direction chain key from root key using HMAC-SHA256
     * This is the other directional key - both parties derive the same key for the OTHER direction
     */
    private fun deriveIncomingChainKey(rootKey: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(rootKey, "HmacSHA256"))
        return mac.doFinal(byteArrayOf(0x04))  // HMAC(root_key, 0x04)
    }

    /**
     * Compare two byte arrays lexicographically
     * Returns negative if a < b, zero if equal, positive if a > b
     */
    private fun compareByteArrays(a: ByteArray, b: ByteArray): Int {
        val minLen = minOf(a.size, b.size)
        for (i in 0 until minLen) {
            val cmp = a[i].toInt().and(0xFF) - b[i].toInt().and(0xFF)
            if (cmp != 0) return cmp
        }
        return a.size - b.size
    }

    /**
     * Initialize key chain for a newly added contact
     * This must be called after the contact is inserted into the database
     *
     * @param context Application context
     * @param contactId Contact database ID
     * @param theirX25519PublicKey Their X25519 public key (32 bytes)
     * @param ourMessagingOnion Our messaging .onion address (for deterministic direction mapping)
     * @param theirMessagingOnion Their messaging .onion address (for deterministic direction mapping)
     */
    suspend fun initializeKeyChain(
        context: Context,
        contactId: Long,
        theirX25519PublicKey: ByteArray,
        ourMessagingOnion: String,
        theirMessagingOnion: String
    ) {
        withContext(Dispatchers.IO) {
            try {
                Log.i(TAG, "Initializing key chain for contact $contactId")

                // Get our X25519 private key from KeyManager
                val keyManager = KeyManager.getInstance(context)
                val ourX25519PrivateKey = keyManager.getEncryptionKeyBytes()

                // Derive shared secret using X25519 ECDH (via Rust)
                val sharedSecret = RustBridge.deriveSharedSecret(ourX25519PrivateKey, theirX25519PublicKey)

                // Derive root key from shared secret using HKDF-SHA256
                val rootKey = RustBridge.deriveRootKey(sharedSecret, ROOT_KEY_INFO)

                // Derive two directional chain keys from root key
                val outgoingKey = deriveOutgoingChainKey(rootKey)  // HMAC(rootKey, 0x03)
                val incomingKey = deriveIncomingChainKey(rootKey)  // HMAC(rootKey, 0x04)

                // Determine which key is for send vs receive based on messaging onion address comparison
                // This ensures both parties agree on the direction mapping (using persistent identities)
                val (sendChainKey, receiveChainKey) = if (ourMessagingOnion < theirMessagingOnion) {
                    // Our onion address is "smaller" - we use outgoing for send, incoming for receive
                    Pair(outgoingKey, incomingKey)
                } else {
                    // Their onion address is "smaller" - we use incoming for send, outgoing for receive
                    Pair(incomingKey, outgoingKey)
                }

                Log.d(TAG, "Key direction mapping: ourOnion(${ourMessagingOnion.take(10)}...) ${if (ourMessagingOnion < theirMessagingOnion) "<" else ">"} theirOnion(${theirMessagingOnion.take(10)}...)")

                // Create key chain entity
                val keyChain = ContactKeyChain(
                    contactId = contactId,
                    rootKeyBase64 = Base64.encodeToString(rootKey, Base64.NO_WRAP),
                    sendChainKeyBase64 = Base64.encodeToString(sendChainKey, Base64.NO_WRAP),
                    receiveChainKeyBase64 = Base64.encodeToString(receiveChainKey, Base64.NO_WRAP),
                    sendCounter = 0,
                    receiveCounter = 0,
                    createdTimestamp = System.currentTimeMillis(),
                    lastEvolutionTimestamp = System.currentTimeMillis()
                )

                // Insert key chain into database
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(context, dbPassphrase)
                database.contactKeyChainDao().insertKeyChain(keyChain)

                Log.i(TAG, "✓ Key chain initialized for contact $contactId")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to initialize key chain for contact $contactId", e)
                throw e
            }
        }
    }

    /**
     * Get key chain for a contact
     * Returns null if key chain doesn't exist yet
     */
    suspend fun getKeyChain(context: Context, contactId: Long): ContactKeyChain? {
        return withContext(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(context)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(context, dbPassphrase)
                database.contactKeyChainDao().getKeyChainByContactId(contactId)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to get key chain for contact $contactId", e)
                null
            }
        }
    }

    /**
     * Update send chain key after sending a message
     * Atomically evolves the key and increments the counter
     */
    suspend fun evolveSendChainKey(
        context: Context,
        contactId: Long,
        currentSendChainKey: ByteArray,
        currentSendCounter: Long
    ): Pair<ByteArray, Long> {
        return withContext(Dispatchers.IO) {
            try {
                // Evolve chain key forward (one-way function)
                val newSendChainKey = RustBridge.evolveChainKey(currentSendChainKey)
                val newSendCounter = currentSendCounter + 1

                // Update database
                val keyManager = KeyManager.getInstance(context)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

                database.contactKeyChainDao().updateSendChainKey(
                    contactId = contactId,
                    newSendChainKeyBase64 = Base64.encodeToString(newSendChainKey, Base64.NO_WRAP),
                    newSendCounter = newSendCounter,
                    timestamp = System.currentTimeMillis()
                )

                Log.d(TAG, "✓ Send chain key evolved for contact $contactId (seq: $newSendCounter)")
                Pair(newSendChainKey, newSendCounter)

            } catch (e: Exception) {
                Log.e(TAG, "Failed to evolve send chain key for contact $contactId", e)
                throw e
            }
        }
    }

    /**
     * Update receive chain key after receiving a message
     * Atomically evolves the key and increments the counter
     */
    suspend fun evolveReceiveChainKey(
        context: Context,
        contactId: Long,
        currentReceiveChainKey: ByteArray,
        currentReceiveCounter: Long
    ): Pair<ByteArray, Long> {
        return withContext(Dispatchers.IO) {
            try {
                // Evolve chain key forward (one-way function)
                val newReceiveChainKey = RustBridge.evolveChainKey(currentReceiveChainKey)
                val newReceiveCounter = currentReceiveCounter + 1

                // Update database
                val keyManager = KeyManager.getInstance(context)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

                database.contactKeyChainDao().updateReceiveChainKey(
                    contactId = contactId,
                    newReceiveChainKeyBase64 = Base64.encodeToString(newReceiveChainKey, Base64.NO_WRAP),
                    newReceiveCounter = newReceiveCounter,
                    timestamp = System.currentTimeMillis()
                )

                Log.d(TAG, "✓ Receive chain key evolved for contact $contactId (seq: $newReceiveCounter)")
                Pair(newReceiveChainKey, newReceiveCounter)

            } catch (e: Exception) {
                Log.e(TAG, "Failed to evolve receive chain key for contact $contactId", e)
                throw e
            }
        }
    }
}
