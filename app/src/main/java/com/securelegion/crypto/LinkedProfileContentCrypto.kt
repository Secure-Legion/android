package com.securelegion.crypto

import android.content.Context
import android.util.Base64
import java.io.Closeable
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Separate at-rest keys for a seedless linked installation. */
internal class LinkedProfileContentCrypto(context: Context) : Closeable {
    private val databaseKey = LinkedProfileCredentialStore(context).activeDatabaseKey()
        ?: throw IllegalStateException("Linked profile unavailable")
    private var closed = false

    fun encryptText(plain: String): String {
        check(!closed)
        if (plain.isEmpty()) return ""
        val bytes = plain.toByteArray(Charsets.UTF_8)
        try { return "ENC1:" + Base64.encodeToString(encrypt(bytes, "text"), Base64.NO_WRAP) }
        finally { bytes.fill(0) }
    }

    fun decryptText(value: String): String {
        check(!closed)
        if (!value.startsWith("ENC1:")) return value
        val bytes = decrypt(Base64.decode(value.removePrefix("ENC1:"), Base64.NO_WRAP), "text")
        try { return bytes.toString(Charsets.UTF_8) } finally { bytes.fill(0) }
    }

    fun encryptImage(bytes: ByteArray) = encrypt(bytes, "image")
    fun decryptImage(bytes: ByteArray) = decrypt(bytes, "image")
    fun encryptVoice(bytes: ByteArray) = encrypt(bytes, "voice")
    fun decryptVoice(bytes: ByteArray) = decrypt(bytes, "voice")

    private fun encrypt(bytes: ByteArray, purpose: String): ByteArray {
        check(!closed)
        val key = key(purpose)
        try {
            val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"),
                GCMParameterSpec(128, nonce))
            return nonce + cipher.doFinal(bytes)
        } finally { key.fill(0) }
    }

    private fun decrypt(blob: ByteArray, purpose: String): ByteArray {
        check(!closed && blob.size >= 29)
        val key = key(purpose)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"),
                GCMParameterSpec(128, blob.copyOfRange(0, 12)))
            return cipher.doFinal(blob, 12, blob.size - 12)
        } finally { key.fill(0) }
    }

    private fun key(purpose: String): ByteArray = MessageDigest.getInstance("SHA-256")
        .digest("secure-legion-linked-content-v1/$purpose\u0000".toByteArray() + databaseKey)

    override fun close() {
        if (!closed) { databaseKey.fill(0); closed = true }
    }
}
