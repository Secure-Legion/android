package com.securelegion.models

import org.json.JSONArray
import org.json.JSONObject

/**
 * Contact card for sharing profile information via IPFS
 * Stored encrypted with PIN protection
 *
 * Version 2.0: Two .onion architecture
 * - friendRequestOnion: Public .onion for friend requests (port 9151)
 * - messagingOnion: Private .onion for encrypted messaging (port 8080)
 *
 * Matches the Rust ContactCard structure for FFI compatibility
 */
data class ContactCard(
    val displayName: String,            // User-facing name (e.g., "John Doe")
    val solanaPublicKey: ByteArray,     // Ed25519 public key for signing (32 bytes)
    val x25519PublicKey: ByteArray,     // X25519 public key for encryption (32 bytes)
    val solanaAddress: String,          // Base58-encoded Solana address

    // NEW - Two .onion addresses (v2.0)
    val friendRequestOnion: String,     // Public .onion for friend requests
    val messagingOnion: String,         // Private .onion for messaging

    // NEW - Additional fields
    val contactPin: String,             // 10-digit PIN (formatted XXX-XXX-XXXX)
    val ipfsCid: String? = null,        // IPFS CID for this card (deterministic)

    val timestamp: Long,                // Creation timestamp (Unix seconds)

    // DEPRECATED - Keep for backward compatibility
    @Deprecated("Use messagingOnion instead", ReplaceWith("messagingOnion"))
    val torOnionAddress: String = messagingOnion
) {
    /**
     * Convert to JSON for Rust FFI / IPFS storage
     * Includes both new fields and legacy field for backward compatibility
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

        // NEW fields (v2.0)
        json.put("friend_request_onion", friendRequestOnion)
        json.put("messaging_onion", messagingOnion)
        json.put("contact_pin", contactPin)
        if (ipfsCid != null) {
            json.put("ipfs_cid", ipfsCid)
        }

        json.put("timestamp", timestamp)

        // DEPRECATED - For backward compatibility with v1.0 clients
        json.put("onion_address", messagingOnion)

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
         * Supports both v1.0 (single .onion) and v2.0 (two .onion) formats
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

            // Parse new fields with fallback to legacy format
            val friendRequestOnion = json.optString("friend_request_onion", "")

            val messagingOnion = if (json.has("messaging_onion")) {
                json.getString("messaging_onion")
            } else {
                // Fallback to v1.0 format (single .onion was used for messaging)
                json.optString("onion_address", "")
            }

            val contactPin = json.optString("contact_pin", "000-000-0000")

            val ipfsCid = if (json.has("ipfs_cid")) {
                json.getString("ipfs_cid")
            } else null

            return ContactCard(
                displayName = json.getString("handle"),
                solanaPublicKey = publicKey,
                x25519PublicKey = x25519PublicKey,
                solanaAddress = json.getString("solana_address"),
                friendRequestOnion = friendRequestOnion,
                messagingOnion = messagingOnion,
                contactPin = contactPin,
                ipfsCid = ipfsCid,
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
        if (friendRequestOnion != other.friendRequestOnion) return false
        if (messagingOnion != other.messagingOnion) return false
        if (contactPin != other.contactPin) return false
        if (timestamp != other.timestamp) return false

        return true
    }

    override fun hashCode(): Int {
        var result = displayName.hashCode()
        result = 31 * result + solanaPublicKey.contentHashCode()
        result = 31 * result + x25519PublicKey.contentHashCode()
        result = 31 * result + solanaAddress.hashCode()
        result = 31 * result + friendRequestOnion.hashCode()
        result = 31 * result + messagingOnion.hashCode()
        result = 31 * result + contactPin.hashCode()
        result = 31 * result + timestamp.hashCode()
        return result
    }
}
