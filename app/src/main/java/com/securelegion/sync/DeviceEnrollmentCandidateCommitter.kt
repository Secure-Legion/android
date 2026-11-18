package com.securelegion.sync

import android.content.Context
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LinkedProfileCredentialStore
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.SecureLegionDatabase
import java.security.MessageDigest

/** Recoverable two-store candidate commit; no receipt is sendable before roster acceptance. */
internal class DeviceEnrollmentCandidateCommitter(private val context: Context) {
    private val credentials = LinkedProfileCredentialStore(context)

    fun commit(session: DeviceEnrollmentCandidateSession,
               grant: DeviceEnrollmentCandidateSession.VerifiedGrant,
               identity: LocalDeviceIdentity): LinkedProfileCredentialStore.PublicProfile {
        check(!KeyManager.getInstance(context).isInitialized())
        check(grant.accountEd.size == 32 && grant.ownerDeviceId != identity.deviceId)
        val receipt = session.committedReceipt(grant)
        val pendingKey = credentials.pendingDatabaseKey()
        val databaseFile = context.getDatabasePath("secure_legion.db")
        check(!databaseFile.exists() || pendingKey != null) {
            "A new, empty candidate profile is required"
        }
        pendingKey?.fill(0)
        val key = credentials.stage(grant.accountIdentity, identity)
        credentials.stageReceipt(LinkedProfileCredentialStore.PendingReceipt(
            grant.accountEd, grant.ownerDeviceId, grant.ownerOnion, receipt))
        // No root wallet is initialized. Reopen with this candidate's own
        // protected key even if onboarding opened an unused Room singleton.
        SecureLegionDatabase.clearInstance()
        val database = SecureLegionDatabase.getInstance(context, key)
        val roster = DeviceRosterStore(database)
        val previous = roster.fetchSignedRoster(grant.accountEd)
        if (previous == null) requireEmptyCandidate(database)
        else check(MessageDigest.isEqual(previous, grant.signedRoster))
        roster.acceptSignedRoster(grant.signedRoster, grant.accountEd, identity.deviceId)
        return credentials.promote(roster, identity)
    }

    /** Complete a crash after SQLCipher commit but before the protected flag changed. */
    fun recoverCommitted(identity: LocalDeviceIdentity): LinkedProfileCredentialStore.PublicProfile? {
        if (KeyManager.getInstance(context).isInitialized()) return null
        val key = credentials.pendingDatabaseKey() ?: credentials.activeDatabaseKey() ?: return null
        if (!context.getDatabasePath("secure_legion.db").exists()) { key.fill(0); return null }
        SecureLegionDatabase.clearInstance()
        val database = SecureLegionDatabase.getInstance(context, key)
        val roster = DeviceRosterStore(database)
        return try { credentials.promote(roster, identity) }
        catch (_: IllegalStateException) { null }
    }

    fun pendingReceipt(identity: LocalDeviceIdentity): LinkedProfileCredentialStore.PendingReceipt? {
        val key = credentials.activeDatabaseKey() ?: return null
        val database = SecureLegionDatabase.getInstance(context, key)
        return credentials.pendingReceipt(DeviceRosterStore(database), identity)
    }

    private fun requireEmptyCandidate(database: SecureLegionDatabase) {
        val db = database.openHelper.readableDatabase
        for (table in arrayOf("wallets", "contacts", "messages", "groups",
            "device_rosters", "authorized_devices", "device_sync_outbox")) {
            val occupied = db.query(SimpleSQLiteQuery("SELECT 1 FROM $table LIMIT 1"))
                .use { it.moveToFirst() }
            check(!occupied) { "Candidate profile already contains account data" }
        }
    }
}
