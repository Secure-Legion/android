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
    private val pinataService = PinataService(context)

    /**
     * Create and upload encrypted contact card
     * @param contactCard The contact card to upload
     * @param pin 6-digit PIN for encryption
     * @return Pair of (IPFS CID, encrypted size in bytes)
     */
    suspend fun uploadContactCard(contactCard: ContactCard, pin: String): Result<Pair<String, Int>> {
        return withContext(Dispatchers.IO) {
            try {
                validatePin(pin)

                // Serialize contact card to JSON
                val jsonString = contactCard.toJson()
                Log.d(TAG, "Contact card JSON: ${jsonString.length} bytes")

                // Encrypt with PIN
                val encrypted = encryptWithPin(jsonString, pin)
                Log.d(TAG, "Encrypted contact card: ${encrypted.size} bytes")

                // Upload to IPFS via Pinata
                val result = pinataService.uploadContactCard(encrypted)

                if (result.isSuccess) {
                    val cid = result.getOrThrow()
                    Log.i(TAG, "Contact card uploaded successfully")
                    Log.i(TAG, "CID: $cid")
                    Log.i(TAG, "PIN: $pin (share this separately!)")
                    Result.success(Pair(cid, encrypted.size))
                } else {
                    Result.failure(result.exceptionOrNull()!!)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to upload contact card", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Download and decrypt contact card
     * @param cid IPFS CID of encrypted contact card
     * @param pin 6-digit PIN for decryption
     * @return Decrypted ContactCard
     */
    suspend fun downloadContactCard(cid: String, pin: String): Result<ContactCard> {
        return withContext(Dispatchers.IO) {
            try {
                validatePin(pin)

                // Download from IPFS via Pinata
                val downloadResult = pinataService.downloadContactCard(cid)
                if (downloadResult.isFailure) {
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
     * Encrypt data with PIN using libsodium (XSalsa20-Poly1305)
     * Format: [salt (16 bytes)][nonce (24 bytes)][ciphertext + MAC]
     */
    private fun encryptWithPin(plaintext: String, pin: String): ByteArray {
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
    private fun decryptWithPin(encrypted: ByteArray, pin: String): String {
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
        if (!pin.matches(Regex("^\\d{6}$"))) {
            throw IllegalArgumentException("PIN must be exactly 6 digits")
        }
    }

    /**
     * Generate random 6-digit PIN
     */
    fun generateRandomPin(): String {
        val random = sodium.randomBytesBuf(4)

        // Convert to unsigned int and take modulo 1000000 to get 6 digits
        val value = ((random[0].toInt() and 0xFF) shl 24) or
                    ((random[1].toInt() and 0xFF) shl 16) or
                    ((random[2].toInt() and 0xFF) shl 8) or
                    (random[3].toInt() and 0xFF)

        val pin = (Math.abs(value) % 1000000).toString().padStart(6, '0')
        return pin
    }
}
