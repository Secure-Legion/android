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
    val kyberPublicKey: ByteArray,      // Kyber-1024 public key for post-quantum KEM (1568 bytes)
    val solanaAddress: String,          // Base58-encoded Solana address

    // NEW - Three .onion addresses (v2.0)
    val friendRequestOnion: String,     // Public .onion for friend requests (port 9151)
    val messagingOnion: String,         // Private .onion for messaging (port 8080)
    val voiceOnion: String? = null,     // Voice calling .onion (port 9152) - nullable if not initialized yet

    // NEW - Additional fields
    val contactPin: String,             // 10-digit PIN (formatted XXX-XXX-XXXX)
    val ipfsCid: String? = null,        // IPFS CID for this card (deterministic)

    // Profile picture (v2.1)
    val profilePictureBase64: String? = null, // Base64-encoded JPEG (max 256KB compressed)

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

        // Convert Kyber-1024 public key to array
        val kyberKeyArray = JSONArray()
        kyberPublicKey.forEach { kyberKeyArray.put(it.toInt() and 0xFF) }

        json.put("handle", displayName)
        json.put("public_key", pubKeyArray)
        json.put("x25519_public_key", x25519KeyArray)
        json.put("kyber_public_key", kyberKeyArray)
        json.put("solana_address", solanaAddress)

        // NEW fields (v2.0)
        json.put("friend_request_onion", friendRequestOnion)
        json.put("messaging_onion", messagingOnion)
        json.put("voice_onion", voiceOnion)
        json.put("contact_pin", contactPin)
        if (ipfsCid != null) {
            json.put("ipfs_cid", ipfsCid)
        }

        // Profile picture (v2.1)
        if (profilePictureBase64 != null) {
            json.put("profile_picture", profilePictureBase64)
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

            // Parse Kyber-1024 public key from array (with fallback for legacy cards)
            val kyberPublicKey = if (json.has("kyber_public_key")) {
                val kyberKeyArray = json.getJSONArray("kyber_public_key")
                ByteArray(kyberKeyArray.length()) { i ->
                    kyberKeyArray.getInt(i).toByte()
                }
            } else {
                // Legacy card without Kyber key - use empty 1568-byte array as placeholder
                ByteArray(1568)
            }

            // Parse new fields with fallback to legacy format
            val friendRequestOnion = json.optString("friend_request_onion", "")

            val messagingOnion = if (json.has("messaging_onion")) {
                json.getString("messaging_onion")
            } else {
                // Fallback to v1.0 format (single .onion was used for messaging)
                json.optString("onion_address", "")
            }

            val voiceOnion = json.optString("voice_onion", "")

            val contactPin = json.optString("contact_pin", "000-000-0000")

            val ipfsCid = if (json.has("ipfs_cid")) {
                json.getString("ipfs_cid")
            } else null

            val profilePictureBase64 = if (json.has("profile_picture")) {
                json.getString("profile_picture")
            } else null

            return ContactCard(
                displayName = json.getString("handle"),
                solanaPublicKey = publicKey,
                x25519PublicKey = x25519PublicKey,
                kyberPublicKey = kyberPublicKey,
                solanaAddress = json.getString("solana_address"),
                friendRequestOnion = friendRequestOnion,
                messagingOnion = messagingOnion,
                voiceOnion = voiceOnion,
                contactPin = contactPin,
                ipfsCid = ipfsCid,
                profilePictureBase64 = profilePictureBase64,
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
        if (!kyberPublicKey.contentEquals(other.kyberPublicKey)) return false
        if (solanaAddress != other.solanaAddress) return false
        if (friendRequestOnion != other.friendRequestOnion) return false
        if (messagingOnion != other.messagingOnion) return false
        if (voiceOnion != other.voiceOnion) return false
        if (contactPin != other.contactPin) return false
        if (timestamp != other.timestamp) return false

        return true
    }

    override fun hashCode(): Int {
        var result = displayName.hashCode()
        result = 31 * result + solanaPublicKey.contentHashCode()
        result = 31 * result + x25519PublicKey.contentHashCode()
        result = 31 * result + kyberPublicKey.contentHashCode()
        result = 31 * result + solanaAddress.hashCode()
        result = 31 * result + friendRequestOnion.hashCode()
        result = 31 * result + messagingOnion.hashCode()
        result = 31 * result + voiceOnion.hashCode()
        result = 31 * result + contactPin.hashCode()
        result = 31 * result + timestamp.hashCode()
        return result
    }
}
