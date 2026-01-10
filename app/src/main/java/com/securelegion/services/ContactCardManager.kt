package com.securelegion.services

import android.content.Context
import android.util.Log
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.PwHash
import com.goterl.lazysodium.interfaces.SecretBox
import com.goterl.lazysodium.utils.Key
import com.securelegion.models.ContactCard
import com.sun.jna.NativeLong
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.nio.charset.StandardCharsets

/**
 * Contact Card Manager
 *
 * Handles encryption, upload, download, and decryption of contact cards.
 * Uses PIN-based encryption (libsodium XSalsa20-Poly1305) for defense in depth:
 * - CID is public (shareable)
 * - PIN is private (shared separately)
 * - Prevents spam/unauthorized access
 */
class ContactCardManager(private val context: Context) {

    companion object {
        private const val TAG = "ContactCardManager"

        // Argon2id parameters (libsodium defaults)
        private val OPSLIMIT = PwHash.OPSLIMIT_INTERACTIVE.toLong()
        private val MEMLIMIT = NativeLong(PwHash.MEMLIMIT_INTERACTIVE.toLong())
        private val ALG = PwHash.Alg.PWHASH_ALG_ARGON2ID13
    }

    private val sodium = LazySodiumAndroid(SodiumAndroid())
    private val solanaService = SolanaService(context)
    private val crustService = CrustService(context, solanaService)

    /**
     * Create and upload encrypted contact card
     * @param contactCard The contact card to upload
     * @param pin 6-digit PIN for encryption
     * @param publicKey User's Solana public key (Base58) for Crust wallet authentication
     * @return Pair of (IPFS CID, encrypted size in bytes)
     */
    suspend fun uploadContactCard(contactCard: ContactCard, pin: String, publicKey: String): Result<Pair<String, Int>> {
        return withContext(Dispatchers.IO) {
            try {
                validatePin(pin)

                // Serialize contact card to JSON
                val jsonString = contactCard.toJson()
                Log.d(TAG, "Contact card JSON: ${jsonString.length} bytes")

                // Encrypt with PIN
                val encrypted = encryptWithPin(jsonString, pin)
                Log.d(TAG, "Encrypted contact card: ${encrypted.size} bytes")

                // Upload to Crust Network (wallet-based storage)
                Log.d(TAG, "Uploading to Crust Network...")
                val result = crustService.uploadContactCard(encrypted, publicKey)

                if (result.isSuccess) {
                    val cid = result.getOrThrow()
                    Log.i(TAG, "Contact card uploaded successfully to Crust Network")
                    Log.i(TAG, "CID: $cid")
                    Log.i(TAG, "PIN: $pin (share this separately!)")
                    Result.success(Pair(cid, encrypted.size))
                } else {
                    Log.e(TAG, "Crust Network upload failed: ${result.exceptionOrNull()?.message}")
                    Result.failure(result.exceptionOrNull()!!)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to upload contact card", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Download and decrypt contact card (v1.0 - IPFS only)
     * @param cid IPFS CID of encrypted contact card
     * @param pin 6-digit PIN for decryption
     * @return Decrypted ContactCard
     */
    suspend fun downloadContactCard(cid: String, pin: String): Result<ContactCard> {
        return withContext(Dispatchers.IO) {
            try {
                validatePin(pin)

                // Download from IPFS gateway (no auth needed)
                Log.d(TAG, "Downloading from IPFS...")
                val downloadResult = crustService.downloadContactCard(cid)

                if (downloadResult.isFailure) {
                    Log.e(TAG, "IPFS download failed: ${downloadResult.exceptionOrNull()?.message}")
                    return@withContext Result.failure(downloadResult.exceptionOrNull()!!)
                }

                val encrypted = downloadResult.getOrThrow()
                Log.d(TAG, "Downloaded encrypted contact card: ${encrypted.size} bytes")

                // Decrypt with PIN
                val decrypted = decryptWithPin(encrypted, pin)
                Log.d(TAG, "Decrypted contact card: ${decrypted.length} bytes")

                // Parse JSON to ContactCard
                val contactCard = ContactCard.fromJson(decrypted)
                Log.i(TAG, "Successfully decrypted contact card for: ${contactCard.displayName}")

                Result.success(contactCard)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to download/decrypt contact card", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Download contact card via Tor .onion address (v2.0)
     * Uses HTTP GET through SOCKS5 to friend request .onion
     * @param friendRequestOnion Friend request .onion address
     * @param pin 6-digit PIN for decryption
     * @return Decrypted ContactCard
     */
    suspend fun downloadContactCardViaTor(friendRequestOnion: String, pin: String): Result<ContactCard> {
        return withContext(Dispatchers.IO) {
            try {
                validatePin(pin)

                Log.d(TAG, "Downloading contact card via Tor from .onion: $friendRequestOnion")

                // Build URL: http://friendrequest.onion:9151/contact-card
                val url = "http://$friendRequestOnion:9151/contact-card"
                Log.d(TAG, "GET $url")

                // Download via Tor SOCKS5
                val response = com.securelegion.crypto.RustBridge.httpGetViaTor(url)
                    ?: throw Exception("HTTP GET failed - no response from .onion address")

                Log.d(TAG, "Received response from .onion (${response.length} bytes)")

                // Parse HTTP response to extract body (encrypted contact card)
                val encrypted = parseHttpResponse(response)
                Log.d(TAG, "Extracted encrypted contact card: ${encrypted.size} bytes")

                // Decrypt with PIN
                val decrypted = decryptWithPin(encrypted, pin)
                Log.d(TAG, "Decrypted contact card: ${decrypted.length} bytes")

                // Parse JSON to ContactCard
                val contactCard = ContactCard.fromJson(decrypted)
                Log.i(TAG, "Successfully downloaded contact card via Tor for: ${contactCard.displayName}")

                Result.success(contactCard)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to download contact card via Tor", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Parse HTTP response to extract binary body (contact card)
     * Handles both text and binary HTTP responses
     */
    private fun parseHttpResponse(response: String): ByteArray {
        // Find double CRLF (end of headers)
        val bodyStart = response.indexOf("\r\n\r\n")
        if (bodyStart == -1) {
            throw Exception("Invalid HTTP response - no headers delimiter")
        }

        // Extract body (everything after headers)
        val body = response.substring(bodyStart + 4)

        // Convert to bytes (contact card is binary encrypted data)
        return body.toByteArray(StandardCharsets.ISO_8859_1)
    }

    /**
     * Encrypt data with PIN using libsodium (XSalsa20-Poly1305)
     * Format: [salt (16 bytes)][nonce (24 bytes)][ciphertext + MAC]
     */
    fun encryptWithPin(plaintext: String, pin: String): ByteArray {
        // Generate random salt for Argon2id
        val salt = sodium.randomBytesBuf(PwHash.SALTBYTES)

        // Derive encryption key from PIN using Argon2id
        val key = ByteArray(SecretBox.KEYBYTES)
        val pinBytes = pin.toByteArray(StandardCharsets.UTF_8)
        val success = sodium.cryptoPwHash(
            key,
            key.size,
            pinBytes,
            pinBytes.size,
            salt,
            OPSLIMIT,
            MEMLIMIT,
            ALG
        )

        if (!success) {
            throw Exception("Key derivation failed")
        }

        // Generate random nonce for XSalsa20-Poly1305
        val nonce = sodium.randomBytesBuf(SecretBox.NONCEBYTES)

        // Encrypt plaintext
        val plaintextBytes = plaintext.toByteArray(StandardCharsets.UTF_8)
        val ciphertext = ByteArray(plaintextBytes.size + SecretBox.MACBYTES)

        val encrypted = sodium.cryptoSecretBoxEasy(
            ciphertext,
            plaintextBytes,
            plaintextBytes.size.toLong(),
            nonce,
            key
        )

        if (!encrypted) {
            throw Exception("Encryption failed")
        }

        // Combine: salt + nonce + ciphertext
        return salt + nonce + ciphertext
    }

    /**
     * Decrypt data with PIN using libsodium (XSalsa20-Poly1305)
     * Format: [salt (16 bytes)][nonce (24 bytes)][ciphertext + MAC]
     */
    fun decryptWithPin(encrypted: ByteArray, pin: String): String {
        // Extract salt, nonce, and ciphertext
        if (encrypted.size < PwHash.SALTBYTES + SecretBox.NONCEBYTES + SecretBox.MACBYTES) {
            throw Exception("Invalid encrypted data: too short")
        }

        val salt = encrypted.copyOfRange(0, PwHash.SALTBYTES)
        val nonce = encrypted.copyOfRange(
            PwHash.SALTBYTES,
            PwHash.SALTBYTES + SecretBox.NONCEBYTES
        )
        val ciphertext = encrypted.copyOfRange(
            PwHash.SALTBYTES + SecretBox.NONCEBYTES,
            encrypted.size
        )

        // Derive encryption key from PIN using Argon2id (same parameters as encryption)
        val key = ByteArray(SecretBox.KEYBYTES)
        val pinBytes = pin.toByteArray(StandardCharsets.UTF_8)
        val success = sodium.cryptoPwHash(
            key,
            key.size,
            pinBytes,
            pinBytes.size,
            salt,
            OPSLIMIT,
            MEMLIMIT,
            ALG
        )

        if (!success) {
            throw Exception("Key derivation failed")
        }

        // Decrypt ciphertext
        val plaintext = ByteArray(ciphertext.size - SecretBox.MACBYTES)
        val decrypted = sodium.cryptoSecretBoxOpenEasy(
            plaintext,
            ciphertext,
            ciphertext.size.toLong(),
            nonce,
            key
        )

        if (!decrypted) {
            throw Exception("Decryption failed: invalid PIN or corrupted data")
        }

        return String(plaintext, StandardCharsets.UTF_8)
    }

    /**
     * Validate PIN format (6 digits)
     */
    private fun validatePin(pin: String) {
        if (!pin.matches(Regex("^\\d{10}$"))) {
            throw IllegalArgumentException("PIN must be exactly 10 digits")
        }
    }

    /**
     * Generate random 10-digit PIN
     */
    fun generateRandomPin(): String {
        val random = sodium.randomBytesBuf(8)

        // Convert to unsigned long and take modulo 10000000000 to get 10 digits
        val value = ((random[0].toLong() and 0xFF) shl 56) or
                    ((random[1].toLong() and 0xFF) shl 48) or
                    ((random[2].toLong() and 0xFF) shl 40) or
                    ((random[3].toLong() and 0xFF) shl 32) or
                    ((random[4].toLong() and 0xFF) shl 24) or
                    ((random[5].toLong() and 0xFF) shl 16) or
                    ((random[6].toLong() and 0xFF) shl 8) or
                    (random[7].toLong() and 0xFF)

        val pin = (Math.abs(value) % 10000000000L).toString().padStart(10, '0')
        return pin
    }
}
