package com.securelegion.utils

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.io.File

/**
 * Process-local, one-time handoff for an imported recovery phrase.
 *
 * Process death intentionally discards the phrase and requires re-entry. This is
 * safer than leaving a second recoverable root secret in SharedPreferences.
 */
object RestoreSeedSession {
    private const val TAG = "RestoreSeedSession"
    private const val LEGACY_PREFS_NAME = "restore_temp"

    private val lock = Any()
    private var encodedPhrase: ByteArray? = null

    fun put(seedPhrase: String) {
        val replacement = seedPhrase.toByteArray(Charsets.UTF_8)
        synchronized(lock) {
            encodedPhrase?.fill(0)
            encodedPhrase = replacement
        }
    }

    fun peek(): String? = synchronized(lock) {
        encodedPhrase?.let { String(it, Charsets.UTF_8) }
    }

    fun clear() {
        synchronized(lock) {
            encodedPhrase?.fill(0)
            encodedPhrase = null
        }
    }

    /**
     * Remove the disk-backed handoff used by releases through v33.
     */
    fun clearLegacyDiskCopy(context: Context) {
        try {
            val masterKey = MasterKey.Builder(context.applicationContext)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            val prefs = EncryptedSharedPreferences.create(
                context.applicationContext,
                LEGACY_PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
            prefs.edit().clear().commit()
        } catch (e: Exception) {
            Log.w(TAG, "Could not open legacy restore preferences; deleting the file", e)
        } finally {
            File(
                context.applicationInfo.dataDir,
                "shared_prefs/$LEGACY_PREFS_NAME.xml"
            ).delete()
        }
    }
}
