package com.securelegion.utils

import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.work.WorkManager
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.services.TorService
import java.io.File
import java.nio.file.Files
import java.security.KeyStore

/**
 * Cryptographically erase account keys, then remove every app-owned data
 * location that can contain messages, Tor state, media, caches, or settings.
 *
 * Flash storage remapping makes overwrite-pass guarantees unreliable. The
 * security boundary is key deletion plus Android file-based encryption, followed
 * by best-effort deletion of all remaining app files.
 */
object SecureWipe {
    private const val TAG = "SecureWipe"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    @Synchronized
    fun wipeAllData(context: Context) {
        val appContext = context.applicationContext
        Log.w(TAG, "Starting cryptographic account wipe")

        bestEffort("mark session locked") {
            SessionManager.setLocked(appContext)
        }
        bestEffort("cancel background work") {
            WorkManager.getInstance(appContext).cancelAllWork()
        }
        bestEffort("stop Tor service") {
            appContext.stopService(Intent(appContext, TorService::class.java))
        }
        bestEffort("stop native listeners") {
            RustBridge.stopIncomingEventPolling()
            RustBridge.stopListeners()
            RustBridge.clearAllEphemeralServices()
            RustBridge.shutdownArti()
        }
        bestEffort("close encrypted database") {
            SecureLegionDatabase.clearInstance()
        }

        // Delete user-authenticated and root-seed keys before deleting ciphertext.
        bestEffort("remove biometric key") {
            BiometricAuthHelper(appContext).disableBiometric()
        }
        bestEffort("clear root keys") {
            KeyManager.getInstance(appContext).wipeAllKeys()
        }
        bestEffort("remove Android Keystore entries") {
            deleteAllKeystoreEntries()
        }

        // Clear live SharedPreferences instances before deleting their XML files.
        bestEffort("clear preferences") {
            clearAllSharedPreferences(appContext)
        }
        bestEffort("remove app-owned files") {
            deleteAppOwnedData(appContext)
        }

        RestoreSeedSession.clear()
        KeyManager.resetInstanceAfterWipe()
        bestEffort("clear notifications") {
            appContext.getSystemService(NotificationManager::class.java)?.cancelAll()
        }

        Log.w(TAG, "Cryptographic account wipe completed")
    }

    /**
     * Compatibility entry point for media/database cleanup. On flash storage,
     * deletion plus platform file-based encryption is more honest than claiming
     * overwrite passes that the storage controller may remap.
     */
    fun secureDeleteFile(file: File) {
        deleteTree(file)
    }

    private fun deleteAllKeystoreEntries() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val aliases = keyStore.aliases().toList()
        aliases.forEach { alias -> keyStore.deleteEntry(alias) }
    }

    private fun clearAllSharedPreferences(context: Context) {
        val prefsDir = File(context.applicationInfo.dataDir, "shared_prefs")
        prefsDir.listFiles()
            ?.filter { it.isFile && it.name.endsWith(".xml") }
            ?.forEach { prefsFile ->
                val prefsName = prefsFile.name.removeSuffix(".xml")
                bestEffort("clear preference file") {
                    context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
                        .edit()
                        .clear()
                        .commit()
                }
            }
    }

    private fun deleteAppOwnedData(context: Context) {
        // Preserve only installed native libraries needed by the running process.
        context.dataDir.listFiles()
            ?.filterNot { it.name == "lib" }
            ?.forEach(::deleteTree)

        context.getExternalFilesDirs(null)
            .filterNotNull()
            .forEach(::deleteTree)
        context.externalCacheDirs
            .filterNotNull()
            .forEach(::deleteTree)
    }

    private fun deleteTree(file: File) {
        try {
            if (Files.isSymbolicLink(file.toPath())) {
                file.delete()
                return
            }
            if (file.isDirectory) {
                file.listFiles()?.forEach(::deleteTree)
            }
            if (file.exists() && !file.delete()) {
                Log.w(TAG, "Could not delete one app-owned path")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to delete one app-owned path", e)
        }
    }

    private inline fun bestEffort(label: String, action: () -> Unit) {
        try {
            action()
        } catch (e: Throwable) {
            Log.w(TAG, "Wipe step failed: " + label, e)
        }
    }
}

class SecureWipeException(message: String, cause: Throwable? = null) : Exception(message, cause)
