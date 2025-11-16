package com.securelegion.models

import org.json.JSONArray
import org.json.JSONObject

/**
 * Contact card for sharing profile information via IPFS
 * Stored encrypted with PIN protection
 *
 * Matches the Rust ContactCard structure for FFI compatibility
 */
data class ContactCard(
    val displayName: String,            // User-facing name (e.g., "John Doe")
    val solanaPublicKey: ByteArray,     // Ed25519 public key for signing (32 bytes)
    val x25519PublicKey: ByteArray,     // X25519 public key for encryption (32 bytes)
    val solanaAddress: String,          // Base58-encoded Solana address
    val torOnionAddress: String,        // .onion:port (REQUIRED for messaging)
    val timestamp: Long                 // Creation timestamp (Unix seconds)
) {
    /**
     * Convert to JSON for Rust FFI / IPFS storage
     */
    fun toJson(): String {
        val json = JSONObject()

        // Convert Ed25519 public key to array
        val pubKeyArray = JSONArray()
        solanaPublicKey.forEach { pubKeyArray.put(it.toInt() and 0xFF) }

        // Convert X25519 public key to array
        val x25519KeyArray = JSONArray()
        x25519PublicKey.forEach { x25519KeyArray.put(it.toInt() and 0xFF) }

        json.put("handle", displayName)
        json.put("public_key", pubKeyArray)
        json.put("x25519_public_key", x25519KeyArray)
        json.put("solana_address", solanaAddress)
        json.put("onion_address", torOnionAddress)
        json.put("timestamp", timestamp)

        // Add empty relay preferences (matches Rust structure)
        val relayPrefs = JSONObject()
        relayPrefs.put("accepts_relay_messages", true)
        relayPrefs.put("preferred_relays", JSONArray())
        json.put("relay_preferences", relayPrefs)

        // Signature added by Rust layer during encryption
        json.put("signature", JSONArray())

        return json.toString()
    }

    companion object {
        /**
         * Parse from JSON (after decryption from IPFS)
         */
        fun fromJson(jsonString: String): ContactCard {
            val json = JSONObject(jsonString)

            // Parse Ed25519 public key from array
            val pubKeyArray = json.getJSONArray("public_key")
            val publicKey = ByteArray(pubKeyArray.length()) { i ->
                pubKeyArray.getInt(i).toByte()
            }

            // Parse X25519 public key from array
            val x25519KeyArray = json.getJSONArray("x25519_public_key")
            val x25519PublicKey = ByteArray(x25519KeyArray.length()) { i ->
                x25519KeyArray.getInt(i).toByte()
            }

            return ContactCard(
                displayName = json.getString("handle"),
                solanaPublicKey = publicKey,
                x25519PublicKey = x25519PublicKey,
                solanaAddress = json.getString("solana_address"),
                torOnionAddress = json.getString("onion_address"),
                timestamp = json.getLong("timestamp")
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ContactCard

        if (displayName != other.displayName) return false
        if (!solanaPublicKey.contentEquals(other.solanaPublicKey)) return false
        if (!x25519PublicKey.contentEquals(other.x25519PublicKey)) return false
        if (solanaAddress != other.solanaAddress) return false
        if (torOnionAddress != other.torOnionAddress) return false
        if (timestamp != other.timestamp) return false

        return true
    }

    override fun hashCode(): Int {
        var result = displayName.hashCode()
        result = 31 * result + solanaPublicKey.contentHashCode()
        result = 31 * result + x25519PublicKey.contentHashCode()
        result = 31 * result + solanaAddress.hashCode()
        result = 31 * result + torOnionAddress.hashCode()
        result = 31 * result + timestamp.hashCode()
        return result
    }
}
