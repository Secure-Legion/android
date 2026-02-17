package com.securelegion.voice.crypto

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.AEAD
import com.goterl.lazysodium.interfaces.KeyDerivation
import com.goterl.lazysodium.interfaces.KeyExchange
import com.goterl.lazysodium.utils.Key
import com.goterl.lazysodium.utils.KeyPair
import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * VoiceCallCrypto handles all cryptographic operations for MCP-TV voice calls:
 * - X25519 ephemeral key exchange
 * - HKDF key derivation (master call key + per-circuit keys)
 * - XChaCha20-Poly1305 AEAD encryption/decryption
 *
 * Security properties:
 * - Forward secrecy via ephemeral X25519 keys (new keypair per call)
 * - Per-circuit encryption (each Tor circuit has unique derived key)
 * - AEAD authenticated encryption (prevents tampering)
 * - Nonce derived from call ID + sequence number (no nonce reuse)
 */
class VoiceCallCrypto {
    private val sodium = LazySodiumAndroid(SodiumAndroid())

    companion object {
        // Key sizes
        const val X25519_PUBLIC_KEY_SIZE = 32
        const val X25519_SECRET_KEY_SIZE = 32
        const val SHARED_SECRET_SIZE = 32
        const val MASTER_KEY_SIZE = 32
        const val CIRCUIT_KEY_SIZE = 32
        const val XCHACHA20_NONCE_SIZE = 24
        const val KDF_CONTEXTBYTES = 8 // libsodium KDF context is exactly 8 bytes

        // HKDF context strings
        const val HKDF_MASTER_CONTEXT = "SecureLegion-Voice-Call-Master-Key"
        const val HKDF_CIRCUIT_PREFIX = "SecureLegion-Voice-Circuit-"
    }

    /**
     * Generate ephemeral X25519 keypair for this call
     * This keypair is used once and discarded after the call ends
     */
    fun generateEphemeralKeypair(): KeyPair {
        val publicKey = ByteArray(X25519_PUBLIC_KEY_SIZE)
        val secretKey = ByteArray(X25519_SECRET_KEY_SIZE)

        val success = sodium.cryptoKxKeypair(publicKey, secretKey)
        require(success) { "Failed to generate X25519 keypair" }

        return KeyPair(Key.fromBytes(publicKey), Key.fromBytes(secretKey))
    }

    /**
     * Compute shared secret using X25519 ECDH
     * @param mySecretKey Our ephemeral secret key
     * @param theirPublicKey Their ephemeral public key
     * @return 32-byte shared secret
     */
    fun computeSharedSecret(mySecretKey: ByteArray, theirPublicKey: ByteArray): ByteArray {
        require(mySecretKey.size == X25519_SECRET_KEY_SIZE) {
            "Invalid secret key size: ${mySecretKey.size}"
        }
        require(theirPublicKey.size == X25519_PUBLIC_KEY_SIZE) {
            "Invalid public key size: ${theirPublicKey.size}"
        }

        val sharedSecret = ByteArray(SHARED_SECRET_SIZE)

        // X25519 scalar multiplication: secret * public = shared_secret
        val success = sodium.cryptoScalarMult(sharedSecret, mySecretKey, theirPublicKey)
        require(success) { "X25519 key exchange failed" }

        return sharedSecret
    }

    /**
     * Derive master call key from shared secret using HKDF
     * @param sharedSecret The X25519 shared secret
     * @param callId Unique call identifier
     * @return 32-byte master key for this call
     */
    fun deriveMasterKey(sharedSecret: ByteArray, callId: ByteArray): ByteArray {
        require(sharedSecret.size == SHARED_SECRET_SIZE) {
            "Invalid shared secret size: ${sharedSecret.size}"
        }

        val masterKey = ByteArray(MASTER_KEY_SIZE)

        // Context: "SecureLegion-Voice-Call-Master-Key" + callId
        val context = (HKDF_MASTER_CONTEXT + callId.joinToString("") { "%02x".format(it) })
            .toByteArray()
            .take(KDF_CONTEXTBYTES)
            .toByteArray()

        val success = sodium.cryptoKdfDeriveFromKey(
            masterKey,
            masterKey.size,
            0L, // Subkey ID 0 for master key
            context,
            sharedSecret
        )

        require(success == 0) { "Master key derivation failed" }

        return masterKey
    }

    /**
     * Derive per-circuit key from master key
     * Each Tor circuit gets a unique encryption key
     * @param masterKey Master call key
     * @param circuitIndex Circuit number (0-4)
     * @return 32-byte circuit-specific key
     */
    fun deriveCircuitKey(masterKey: ByteArray, circuitIndex: Int): ByteArray {
        require(masterKey.size == MASTER_KEY_SIZE) {
            "Invalid master key size: ${masterKey.size}"
        }
        require(circuitIndex in 0..255) {
            "Circuit index out of range: $circuitIndex"
        }

        val circuitKey = ByteArray(CIRCUIT_KEY_SIZE)

        // Context: "SecureLegion-Voice-Circuit-<index>"
        val context = (HKDF_CIRCUIT_PREFIX + circuitIndex.toString())
            .toByteArray()
            .take(KDF_CONTEXTBYTES)
            .toByteArray()

        val success = sodium.cryptoKdfDeriveFromKey(
            circuitKey,
            circuitKey.size,
            circuitIndex.toLong() + 1, // Subkey ID 1-N for circuit keys
            context,
            masterKey
        )

        require(success == 0) { "Circuit key derivation failed" }

        return circuitKey
    }

    /**
     * Derive nonce from call ID and sequence number
     * This ensures no nonce reuse (sequence number is monotonic)
     * @param callId Call identifier
     * @param sequenceNumber Frame sequence number
     * @return 24-byte XChaCha20 nonce
     */
    fun deriveNonce(callId: ByteArray, sequenceNumber: Long): ByteArray {
        require(callId.size == 16) { "Call ID must be 16 bytes" }

        val nonce = ByteArray(XCHACHA20_NONCE_SIZE)

        // Nonce = callId (16 bytes) + seqNum (8 bytes)
        System.arraycopy(callId, 0, nonce, 0, 16)

        val seqBytes = ByteBuffer.allocate(8).putLong(sequenceNumber).array()
        System.arraycopy(seqBytes, 0, nonce, 16, 8)

        return nonce
    }

    /**
     * Encrypt Opus frame with XChaCha20-Poly1305 AEAD
     * @param plaintext Raw Opus audio frame
     * @param circuitKey Circuit-specific encryption key
     * @param nonce 24-byte nonce (derived from callId + seqNum)
     * @param aad Additional authenticated data (frame header)
     * @return Encrypted payload (plaintext.size + 16 bytes for Poly1305 tag)
     */
    fun encryptFrame(
        plaintext: ByteArray,
        circuitKey: ByteArray,
        nonce: ByteArray,
        aad: ByteArray
    ): ByteArray {
        require(circuitKey.size == CIRCUIT_KEY_SIZE) {
            "Invalid circuit key size: ${circuitKey.size}"
        }
        require(nonce.size == XCHACHA20_NONCE_SIZE) {
            "Invalid nonce size: ${nonce.size}"
        }

        // Output = plaintext + 16-byte Poly1305 MAC tag
        val ciphertext = ByteArray(plaintext.size + AEAD.XCHACHA20POLY1305_IETF_ABYTES)

        val success = sodium.cryptoAeadXChaCha20Poly1305IetfEncrypt(
            ciphertext,
            null,
            plaintext,
            plaintext.size.toLong(),
            aad,
            aad.size.toLong(),
            null,
            nonce,
            circuitKey
        )

        require(success) { "Frame encryption failed" }

        return ciphertext
    }

    /**
     * Decrypt Opus frame with XChaCha20-Poly1305 AEAD
     * @param ciphertext Encrypted payload (includes 16-byte Poly1305 tag)
     * @param circuitKey Circuit-specific decryption key
     * @param nonce 24-byte nonce (derived from callId + seqNum)
     * @param aad Additional authenticated data (frame header)
     * @return Decrypted Opus frame
     * @throws IllegalStateException if authentication fails (tampered frame)
     */
    fun decryptFrame(
        ciphertext: ByteArray,
        circuitKey: ByteArray,
        nonce: ByteArray,
        aad: ByteArray
    ): ByteArray {
        require(circuitKey.size == CIRCUIT_KEY_SIZE) {
            "Invalid circuit key size: ${circuitKey.size}"
        }
        require(nonce.size == XCHACHA20_NONCE_SIZE) {
            "Invalid nonce size: ${nonce.size}"
        }
        require(ciphertext.size >= AEAD.XCHACHA20POLY1305_IETF_ABYTES) {
            "Ciphertext too small: ${ciphertext.size}"
        }

        // Output = ciphertext - 16-byte Poly1305 MAC tag
        val plaintext = ByteArray(ciphertext.size - AEAD.XCHACHA20POLY1305_IETF_ABYTES)

        val success = sodium.cryptoAeadXChaCha20Poly1305IetfDecrypt(
            plaintext,
            null,
            null,
            ciphertext,
            ciphertext.size.toLong(),
            aad,
            aad.size.toLong(),
            nonce,
            circuitKey
        )

        require(success) { "Frame decryption failed - authentication error (tampered frame?)" }

        return plaintext
    }

    /**
     * Securely wipe key material from memory
     * Call this when the call ends to ensure forward secrecy
     */
    fun wipeKey(key: ByteArray) {
        SecureRandom().nextBytes(key)
        key.fill(0)
    }
}
