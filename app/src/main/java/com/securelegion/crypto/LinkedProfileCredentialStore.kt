package com.securelegion.crypto

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.securelegion.database.DeviceRosterStore
import org.json.JSONObject
import java.security.SecureRandom

/**
 * Candidate-only database credential and public account binding.
 * A pending record is never an authorized profile; promotion requires the
 * signed roster to be committed in SQLCipher first. The account seed is absent.
 */
internal class LinkedProfileCredentialStore(context: Context) {
    private val appContext = context.applicationContext
    data class PublicProfile(
        val accountIdentity: ByteArray,
        val accountEd: ByteArray,
        val deviceId: String
    )

    private val prefs = EncryptedSharedPreferences.create(
        context.applicationContext, "secure_legion_keys",
        MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun stage(accountIdentity: ByteArray, identity: LocalDeviceIdentity): ByteArray {
        require(accountIdentity.size == ACCOUNT_IDENTITY_SIZE && identity.deviceId.length == 43)
        synchronized(lock) {
            check(!KeyManager.getInstance(appContext).isInitialized())
            check(prefs.getString(RECORD_KEY, null) == null) { "Linked profile already staged" }
            val accountEd = accountIdentity.copyOfRange(6, 38)
            val verified = JSONObject(RustBridge.deviceAuthorization(
                JSONObject().put("operation", "verify_account_identity")
                    .put("identity", Base64.encodeToString(accountIdentity, Base64.NO_WRAP))
                    .put("pinned_account", Base64.encodeToString(accountEd, Base64.NO_WRAP))
                    .toString().toByteArray(Charsets.UTF_8), null
            ).toString(Charsets.UTF_8))
            require(verified.getString("account_ed") == Base64.encodeToString(accountEd, Base64.NO_WRAP))
            val databaseKey = ByteArray(32)
            SecureRandom().nextBytes(databaseKey)
            val record = ByteArray(RECORD_SIZE)
            try {
                MAGIC.copyInto(record)
                record[6] = 0 // pending
                accountIdentity.copyInto(record, 7)
                identity.deviceId.toByteArray(Charsets.US_ASCII).copyInto(record, 7 + ACCOUNT_IDENTITY_SIZE)
                databaseKey.copyInto(record, RECORD_SIZE - 32)
                check(prefs.edit().putString(RECORD_KEY,
                    Base64.encodeToString(record, Base64.NO_WRAP)).commit())
                return databaseKey.copyOf()
            } finally { databaseKey.fill(0); record.fill(0); accountEd.fill(0) }
        }
    }

    /** Promote only after roster acceptance with this exact local device ID. */
    fun promote(rosterStore: DeviceRosterStore, identity: LocalDeviceIdentity): PublicProfile {
        synchronized(lock) {
            val record = readRecord() ?: throw IllegalStateException("No pending profile")
            try {
                check(record[6] == 0.toByte() || record[6] == 1.toByte())
                val accountEd = record.copyOfRange(13, 45)
                val storedId = String(record, 7 + ACCOUNT_IDENTITY_SIZE, 43, Charsets.US_ASCII)
                check(storedId == identity.deviceId)
                check(rosterStore.isLocalAuthorized(accountEd, identity.deviceId, 0x02))
                val roster = rosterStore.fetchSignedRoster(accountEd)
                    ?: throw IllegalStateException("Signed roster missing")
                check(roster.isNotEmpty())
                record[6] = 1
                check(prefs.edit().putString(RECORD_KEY,
                    Base64.encodeToString(record, Base64.NO_WRAP)).commit())
                return PublicProfile(record.copyOfRange(7, 7 + ACCOUNT_IDENTITY_SIZE),
                    accountEd, storedId)
            } finally { record.fill(0) }
        }
    }

    fun activeProfile(): PublicProfile? {
        val record = readRecord() ?: return null
        try {
            if (record[6] != 1.toByte()) return null
            return PublicProfile(record.copyOfRange(7, 7 + ACCOUNT_IDENTITY_SIZE),
                record.copyOfRange(13, 45),
                String(record, 7 + ACCOUNT_IDENTITY_SIZE, 43, Charsets.US_ASCII))
        } finally { record.fill(0) }
    }

    /** Only candidate onboarding uses this pending key; it is never an unlock token. */
    fun pendingDatabaseKey(): ByteArray? {
        val record = readRecord() ?: return null
        try { return if (record[6] == 0.toByte()) record.copyOfRange(RECORD_SIZE - 32, RECORD_SIZE)
            else null }
        finally { record.fill(0) }
    }

    fun activeDatabaseKey(): ByteArray? {
        val record = readRecord() ?: return null
        try { return if (record[6] == 1.toByte()) record.copyOfRange(RECORD_SIZE - 32, RECORD_SIZE)
            else null }
        finally { record.fill(0) }
    }

    fun discardPending() {
        synchronized(lock) {
            val record = readRecord() ?: return
            try {
                check(record[6] == 0.toByte()) { "Active profile cannot be discarded as pending" }
                check(prefs.edit().remove(RECORD_KEY).commit())
            } finally { record.fill(0) }
        }
    }

    private fun readRecord(): ByteArray? {
        val encoded = prefs.getString(RECORD_KEY, null) ?: return null
        val record = Base64.decode(encoded, Base64.DEFAULT)
        if (record.size != RECORD_SIZE || !record.copyOfRange(0, 6).contentEquals(MAGIC)) {
            record.fill(0)
            throw IllegalStateException("Invalid protected linked profile")
        }
        return record
    }

    companion object {
        private val lock = Any()
        private val MAGIC = "SLPL01".toByteArray(Charsets.US_ASCII)
        private const val RECORD_KEY = "securelegion_linked_profile_v1"
        private const val ACCOUNT_IDENTITY_SIZE = 1702
        private const val RECORD_SIZE = 6 + 1 + ACCOUNT_IDENTITY_SIZE + 43 + 32
    }
}
