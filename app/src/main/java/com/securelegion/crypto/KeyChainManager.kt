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
        return mac.doFinal(byteArrayOf(0x03)) // HMAC(root_key, 0x03)
    }

    /**
     * Derive incoming direction chain key from root key using HMAC-SHA256
     * This is the other directional key - both parties derive the same key for the OTHER direction
     */
    private fun deriveIncomingChainKey(rootKey: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(rootKey, "HmacSHA256"))
        return mac.doFinal(byteArrayOf(0x04)) // HMAC(root_key, 0x04)
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
     * Initialize hybrid post-quantum key chain for a newly added contact
     * Uses X25519 + Kyber-1024 hybrid KEM for quantum-resistant key establishment
     *
     * Security: Protected if EITHER X25519 OR Kyber-1024 remains unbroken
     *
     * @param context Application context
     * @param contactId Contact database ID
     * @param theirX25519PublicKey Their X25519 public key (32 bytes)
     * @param theirKyberPublicKey Their Kyber-1024 public key (1568 bytes)
     * @param ourMessagingOnion Our messaging .onion address (for deterministic direction mapping)
     * @param theirMessagingOnion Their messaging .onion address (for deterministic direction mapping)
     * @param kyberCiphertext Optional hybrid ciphertext (1600 bytes: 32-byte X25519 ephemeral + 1568-byte Kyber ciphertext)
     * - Null = we are initiating (will encapsulate and generate new ciphertext)
     * - Non-null = we are responding (will decapsulate using provided ciphertext)
     */
    suspend fun initializeKeyChain(
        context: Context,
        contactId: Long,
        theirX25519PublicKey: ByteArray,
        theirKyberPublicKey: ByteArray? = null,
        ourMessagingOnion: String,
        theirMessagingOnion: String,
        kyberCiphertext: ByteArray? = null, // Null = we are sender (encapsulate), non-null = we are receiver (decapsulate)
        precomputedSharedSecret: ByteArray? = null // If provided, skip KEM entirely and use this shared secret
    ) {
        withContext(Dispatchers.IO) {
            try {
                // Check if Kyber key is present AND non-zero (legacy cards use zero-filled placeholder)
                val hasValidKyberKey = (theirKyberPublicKey != null && theirKyberPublicKey.any { it != 0.toByte() })
                val isHybridMode = hasValidKyberKey
                val modeDesc = if (isHybridMode) "hybrid post-quantum" else "legacy X25519-only"

                if (theirKyberPublicKey != null && !hasValidKyberKey) {
                    Log.w(TAG, "Contact has zero-filled Kyber key (${theirKyberPublicKey.size} bytes) - falling back to legacy X25519 mode")
                }

                Log.i(TAG, "Initializing $modeDesc key chain for contact $contactId")

                // Get our keys from KeyManager
                val keyManager = KeyManager.getInstance(context)
                val ourX25519PrivateKey = keyManager.getEncryptionKeyBytes()

                // Derive shared secret using Hybrid KEM or legacy X25519 ECDH
                val sharedSecret: ByteArray

                if (precomputedSharedSecret != null) {
                    // PRECOMPUTED MODE: Use shared secret we generated during encapsulation
                    Log.d(TAG, "Using precomputed shared secret (${precomputedSharedSecret.size} bytes) from encapsulation")
                    sharedSecret = precomputedSharedSecret
                } else if (isHybridMode && theirKyberPublicKey != null) {
                    // HYBRID MODE: Use X25519 + Kyber-1024
                    val ourKyberSecretKey = keyManager.getKyberSecretKey()

                    if (kyberCiphertext == null) {
                        // ERROR: This path should NOT be hit anymore!
                        // Both devices should either use precomputedSharedSecret OR kyberCiphertext
                        Log.e(TAG, "WARNING: Hybrid mode with null ciphertext and null precomputed secret - this is the OLD BUG!")
                        Log.e(TAG, "This will generate a DIFFERENT shared secret! Key chain will fail!")
                        // Fallback to legacy mode to avoid crash
                        sharedSecret = RustBridge.deriveSharedSecret(ourX25519PrivateKey, theirX25519PublicKey)
                    } else {
                        // We are the RECEIVER - decapsulate to recover shared secret
                        Log.d(TAG, "Performing hybrid decapsulation (we are receiver)")
                        sharedSecret = RustBridge.hybridDecapsulate(ourX25519PrivateKey, ourKyberSecretKey, kyberCiphertext)
                            ?: throw IllegalStateException("Hybrid decapsulation failed - invalid ciphertext or keys")
                        Log.d(TAG, "Hybrid KEM complete - derived 64-byte combined secret")
                    }
                } else {
                    // LEGACY MODE: Use X25519 ECDH only (for backward compatibility)
                    Log.d(TAG, "Using legacy X25519 ECDH (contact has no Kyber key)")
                    sharedSecret = RustBridge.deriveSharedSecret(ourX25519PrivateKey, theirX25519PublicKey)
                }

                // Derive root key from shared secret using HKDF-SHA256
                val rootKey = RustBridge.deriveRootKey(sharedSecret, ROOT_KEY_INFO)

                // Derive two directional chain keys from root key
                val outgoingKey = deriveOutgoingChainKey(rootKey) // HMAC(rootKey, 0x03)
                val incomingKey = deriveIncomingChainKey(rootKey) // HMAC(rootKey, 0x04)

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

                Log.i(TAG, "Key chain initialized for contact $contactId")

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

                Log.d(TAG, "Send chain key evolved for contact $contactId (seq: $newSendCounter)")
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

                Log.d(TAG, "Receive chain key evolved for contact $contactId (seq: $newReceiveCounter)")
                Pair(newReceiveChainKey, newReceiveCounter)

            } catch (e: Exception) {
                Log.e(TAG, "Failed to evolve receive chain key for contact $contactId", e)
                throw e
            }
        }
    }

    /**
     * Reset key chain counters back to 0 for BOTH send and receive
     * This is used to fix key chain desynchronization issues
     * WARNING: Both parties must reset at the same time!
     */
    suspend fun resetKeyChainCounters(context: Context, contactId: Long) {
        withContext(Dispatchers.IO) {
            try {
                Log.w(TAG, "DEBUG: RESETTING key chain counters to 0 for contact $contactId")

                // Get current key chain state BEFORE reset
                val keyManager = KeyManager.getInstance(context)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

                val keyChainBefore = database.contactKeyChainDao().getKeyChainByContactId(contactId)
                Log.d(TAG, "DEBUG: Key chain BEFORE reset: sendCounter=${keyChainBefore?.sendCounter}, receiveCounter=${keyChainBefore?.receiveCounter}")

                // Reset both counters to 0
                val timestamp = System.currentTimeMillis()
                Log.d(TAG, "DEBUG: Calling database.contactKeyChainDao().resetCounters(contactId=$contactId, timestamp=$timestamp)")
                database.contactKeyChainDao().resetCounters(contactId, timestamp)
                Log.d(TAG, "DEBUG: Database update call completed")

                // Verify counters were actually reset
                val keyChainAfter = database.contactKeyChainDao().getKeyChainByContactId(contactId)
                Log.d(TAG, "DEBUG: Key chain AFTER reset: sendCounter=${keyChainAfter?.sendCounter}, receiveCounter=${keyChainAfter?.receiveCounter}")

                if (keyChainAfter?.sendCounter == 0L && keyChainAfter?.receiveCounter == 0L) {
                    Log.i(TAG, "DEBUG: VERIFIED: Key chain counters successfully reset to 0 for contact $contactId")
                } else {
                    Log.e(TAG, "DEBUG: VERIFICATION FAILED: Counters NOT at 0 after reset!")
                }

            } catch (e: Exception) {
                Log.e(TAG, "DEBUG: Failed to reset key chain counters for contact $contactId", e)
                throw e
            }
        }
    }
}
