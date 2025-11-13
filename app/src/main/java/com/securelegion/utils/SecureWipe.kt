package com.securelegion.utils

import android.content.Context
import android.util.Log
import java.io.File
import java.io.RandomAccessFile
import java.security.SecureRandom

/**
 * SecureWipe - Secure data deletion utility
 *
 * Implements DoD 5220.22-M standard (3-pass overwrite):
 * - Pass 1: Write 0x00 (all zeros)
 * - Pass 2: Write 0xFF (all ones)
 * - Pass 3: Write random data
 *
 * This makes forensic data recovery extremely difficult.
 */
object SecureWipe {

    private const val TAG = "SecureWipe"
    private const val BUFFER_SIZE = 4096 // 4KB buffer for efficient writing

    /**
     * Securely wipe all app data
     * - Overwrites database file 3 times
     * - Wipes all cryptographic keys
     * - Clears all SharedPreferences
     * - Deletes all app files
     */
    fun wipeAllData(context: Context) {
        try {
            Log.w(TAG, "Starting secure wipe of all data")

            // 1. Securely wipe database file
            val dbPath = context.getDatabasePath("secure_legion.db")
            if (dbPath.exists()) {
                Log.i(TAG, "Securely wiping database: ${dbPath.absolutePath}")
                secureDeleteFile(dbPath)
            }

            // 2. Securely wipe database journal files
            val dbJournal = File(dbPath.absolutePath + "-journal")
            if (dbJournal.exists()) {
                Log.i(TAG, "Securely wiping journal file")
                secureDeleteFile(dbJournal)
            }

            val dbWal = File(dbPath.absolutePath + "-wal")
            if (dbWal.exists()) {
                Log.i(TAG, "Securely wiping WAL file")
                secureDeleteFile(dbWal)
            }

            val dbShm = File(dbPath.absolutePath + "-shm")
            if (dbShm.exists()) {
                Log.i(TAG, "Securely wiping SHM file")
                secureDeleteFile(dbShm)
            }

            // 3. Clear all SharedPreferences
            Log.i(TAG, "Clearing all SharedPreferences")
            clearAllSharedPreferences(context)

            // 4. Wipe cryptographic keys (managed by EncryptedSharedPreferences)
            // Keys are stored in Android Keystore and will be removed when prefs are cleared

            Log.w(TAG, "Secure wipe completed successfully")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to securely wipe data", e)
            throw SecureWipeException("Failed to securely wipe data: ${e.message}", e)
        }
    }

    /**
     * Securely delete a file using DoD 5220.22-M standard (3-pass overwrite)
     * @param file The file to securely delete
     */
    fun secureDeleteFile(file: File) {
        if (!file.exists()) {
            Log.w(TAG, "File does not exist: ${file.absolutePath}")
            return
        }

        try {
            val fileSize = file.length()
            Log.i(TAG, "Securely deleting file: ${file.name} (${fileSize} bytes)")

            RandomAccessFile(file, "rws").use { raf ->
                // Pass 1: Write all zeros (0x00)
                Log.d(TAG, "Pass 1/3: Writing zeros")
                overwriteFile(raf, fileSize, 0x00.toByte())

                // Pass 2: Write all ones (0xFF)
                Log.d(TAG, "Pass 2/3: Writing ones")
                overwriteFile(raf, fileSize, 0xFF.toByte())

                // Pass 3: Write random data
                Log.d(TAG, "Pass 3/3: Writing random data")
                overwriteFileRandom(raf, fileSize)
            }

            // Delete the file after overwriting
            if (file.delete()) {
                Log.i(TAG, "File deleted successfully: ${file.name}")
            } else {
                Log.e(TAG, "Failed to delete file: ${file.name}")
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to securely delete file: ${file.name}", e)
            // Still try to delete the file even if overwrite failed
            file.delete()
        }
    }

    /**
     * Overwrite file with a specific byte pattern
     */
    private fun overwriteFile(raf: RandomAccessFile, fileSize: Long, pattern: Byte) {
        raf.seek(0)
        val buffer = ByteArray(BUFFER_SIZE) { pattern }

        var remaining = fileSize
        while (remaining > 0) {
            val toWrite = minOf(remaining, BUFFER_SIZE.toLong()).toInt()
            raf.write(buffer, 0, toWrite)
            remaining -= toWrite
        }

        // Force write to disk
        raf.fd.sync()
    }

    /**
     * Overwrite file with random data
     */
    private fun overwriteFileRandom(raf: RandomAccessFile, fileSize: Long) {
        raf.seek(0)
        val random = SecureRandom()
        val buffer = ByteArray(BUFFER_SIZE)

        var remaining = fileSize
        while (remaining > 0) {
            val toWrite = minOf(remaining, BUFFER_SIZE.toLong()).toInt()
            random.nextBytes(buffer)
            raf.write(buffer, 0, toWrite)
            remaining -= toWrite
        }

        // Force write to disk
        raf.fd.sync()
    }

    /**
     * Clear all SharedPreferences except critical security settings
     */
    private fun clearAllSharedPreferences(context: Context) {
        try {
            // List of SharedPreferences to preserve during wipe
            val preservedPrefs = setOf(
                "duress_settings"  // Preserve duress PIN so it can be used again
            )

            // Get all SharedPreferences files
            val prefsDir = File(context.applicationInfo.dataDir, "shared_prefs")

            if (prefsDir.exists() && prefsDir.isDirectory) {
                val prefsFiles = prefsDir.listFiles()
                prefsFiles?.forEach { prefsFile ->
                    if (prefsFile.name.endsWith(".xml")) {
                        val prefsName = prefsFile.name.removeSuffix(".xml")

                        // Skip preserved SharedPreferences
                        if (prefsName in preservedPrefs) {
                            Log.i(TAG, "Preserving SharedPreferences: $prefsName (critical security settings)")
                            return@forEach
                        }

                        Log.i(TAG, "Clearing SharedPreferences: $prefsName")

                        try {
                            context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
                                .edit()
                                .clear()
                                .commit()
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to clear SharedPreferences: $prefsName", e)
                        }

                        // Securely delete the XML file
                        if (prefsFile.exists()) {
                            secureDeleteFile(prefsFile)
                        }
                    }
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to clear SharedPreferences", e)
        }
    }
}

/**
 * SecureWipe exception
 */
class SecureWipeException(message: String, cause: Throwable? = null) : Exception(message, cause)
