package com.securelegion.vault

import android.content.Context
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.VaultItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest

/**
 * Secure Vault repository + PIN gate.
 *
 * Stores encrypted media (images, voice, files) in `vault_items` table.
 * Protected by an optional 4+ digit PIN whose SHA-256 hash is kept in SharedPreferences.
 */
object VaultManager {

    private const val TAG = "VaultManager"
    private const val PREFS_NAME = "secure_vault"
    private const val KEY_PIN_HASH = "pin_sha256"

    // ─── CRUD ───────────────────────────────────────────────────────

    suspend fun insert(context: Context, item: VaultItem): Boolean = withContext(Dispatchers.IO) {
        try {
            val db = getDatabase(context)
            db.vaultItemDao().insert(item)
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to insert vault item", e)
            false
        }
    }

    suspend fun fetchAll(context: Context, type: String? = null): List<VaultItem> =
        withContext(Dispatchers.IO) {
            try {
                val dao = getDatabase(context).vaultItemDao()
                if (type != null) dao.fetchByType(type) else dao.fetchAll()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to fetch vault items", e)
                emptyList()
            }
        }

    suspend fun delete(context: Context, id: String): Boolean = withContext(Dispatchers.IO) {
        try {
            getDatabase(context).vaultItemDao().delete(id) > 0
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete vault item", e)
            false
        }
    }

    suspend fun count(context: Context): Int = withContext(Dispatchers.IO) {
        try {
            getDatabase(context).vaultItemDao().count()
        } catch (_: Exception) { 0 }
    }

    // ─── PIN Gate ───────────────────────────────────────────────────

    fun isPinSet(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return !prefs.getString(KEY_PIN_HASH, null).isNullOrBlank()
    }

    fun setPin(context: Context, pin: String): Boolean {
        if (pin.length < 4) return false
        val hash = sha256(pin)
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putString(KEY_PIN_HASH, hash).apply()
        return true
    }

    fun clearPin(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().remove(KEY_PIN_HASH).apply()
    }

    fun verifyPin(context: Context, pin: String): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val storedHash = prefs.getString(KEY_PIN_HASH, null) ?: return true // No PIN = always pass
        return sha256(pin) == storedHash
    }

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // ─── Internal ───────────────────────────────────────────────────

    private fun getDatabase(context: Context): SecureLegionDatabase {
        val passphrase = KeyManager.getInstance(context).getDatabasePassphrase()
        return SecureLegionDatabase.getInstance(context, passphrase)
    }
}
