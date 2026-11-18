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
    private val keyManager: KeyManager
) {
    fun store(message: DeviceSyncMessageDelta.Message): String {
        require(message.type == "IMAGE" || message.type == "VOICE")
        val bytes = if (message.type == "IMAGE") {
            val encoded = requireNotNull(message.attachmentData)
            android.util.Base64.decode(encoded, android.util.Base64.NO_WRAP)
        } else requireNotNull(message.voiceData)
        try {
            require(bytes.isNotEmpty())
            if (message.type == "IMAGE") {
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                require(bounds.outWidth in 1..8192 && bounds.outHeight in 1..8192 &&
                    bounds.outMimeType in setOf("image/jpeg", "image/png", "image/webp",
                        "image/gif", "image/heif", "image/heic"))
            }
            val directory = File(context.filesDir,
                if (message.type == "IMAGE") "image_messages" else "voice_messages")
            check(directory.isDirectory || directory.mkdirs())
            val filename = "sync_${sha(message.id.toByteArray())}_${sha(bytes)}.enc"
            val target = File(directory, filename)
            if (target.exists()) {
                require(target.isFile && target.length() > 28)
                return target.absolutePath
            }
            val encrypted = if (message.type == "IMAGE") keyManager.encryptImageFile(bytes)
                else keyManager.encryptVoiceFile(bytes)
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
