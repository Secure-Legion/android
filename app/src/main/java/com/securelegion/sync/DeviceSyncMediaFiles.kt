package com.securelegion.sync

import android.content.Context
import android.graphics.BitmapFactory
import com.securelegion.crypto.KeyManager
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

/** Store validated own-device media as encrypted, immutable private files. */
internal class DeviceSyncMediaFiles(
    private val context: Context,
    private val encryptImage: (ByteArray) -> ByteArray,
    private val encryptVoice: (ByteArray) -> ByteArray
) {
    constructor(context: Context, keyManager: KeyManager) : this(context,
        keyManager::encryptImageFile, keyManager::encryptVoiceFile)
    fun store(message: DeviceSyncMessageDelta.Message): String {
        require(message.type == "IMAGE" || message.type == "VOICE")
        val bytes = if (message.type == "IMAGE") {
            val encoded = requireNotNull(message.attachmentData)
            android.util.Base64.decode(encoded, android.util.Base64.NO_WRAP)
        } else requireNotNull(message.voiceData)
        return storeRaw(message.type, message.id, bytes)
    }

    fun storeRaw(type: String, messageId: String, bytes: ByteArray): String {
        require(type == "IMAGE" || type == "VOICE")
        try {
            require(bytes.isNotEmpty())
            if (type == "IMAGE") {
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                require(bounds.outWidth in 1..8192 && bounds.outHeight in 1..8192 &&
                    bounds.outMimeType in setOf("image/jpeg", "image/png", "image/webp",
                        "image/gif", "image/heif", "image/heic"))
            }
            val directory = File(context.filesDir,
                if (type == "IMAGE") "image_messages" else "voice_messages")
            check(directory.isDirectory || directory.mkdirs())
            val filename = "sync_${sha(messageId.toByteArray())}_${sha(bytes)}.enc"
            val target = File(directory, filename)
            if (target.exists()) {
                require(target.isFile && target.length() > 28)
                return target.absolutePath
            }
            val encrypted = if (type == "IMAGE") encryptImage(bytes)
                else encryptVoice(bytes)
            try {
                val temporary = File.createTempFile(".sync_", ".tmp", directory)
                try {
                    FileOutputStream(temporary).use { output ->
                        output.write(encrypted)
                        output.fd.sync()
                    }
                    check(temporary.renameTo(target) || target.exists())
                } finally { temporary.delete() }
            } finally { encrypted.fill(0) }
            return target.absolutePath
        } finally { bytes.fill(0) }
    }

    private fun sha(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
