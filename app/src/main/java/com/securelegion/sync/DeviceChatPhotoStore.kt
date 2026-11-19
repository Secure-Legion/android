package com.securelegion.sync

import android.graphics.BitmapFactory
import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** C0 contact-photo import with retained source revision and image bounds. */
internal object DeviceChatPhotoStore {
    private val magic = "SLPF01".toByteArray(StandardCharsets.US_ASCII)
    private val hex = Regex("[0-9a-f]{64}")

    fun apply(db: SupportSQLiteDatabase, sender: ByteArray, linked: Boolean,
              logicalId: String, body: ByteArray, timestamp: Long,
              nowMs: Long): Boolean {
        require(db.inTransaction() && sender.size == 32 && body.size <= 78 + 256 * 1024)
        val account = Base64.encodeToString(sender, Base64.NO_WRAP)
        val contactId = db.query(SimpleSQLiteQuery(if (linked)
            "SELECT rowid FROM linked_chat_contacts WHERE account_ed=? AND blocked=0 LIMIT 1"
        else "SELECT id FROM contacts WHERE publicKeyBase64=? AND " +
            "friendshipStatus='CONFIRMED' AND isBlocked=0 LIMIT 1", arrayOf(account)
        )).use { if (it.moveToFirst()) it.getLong(0) else null }
        require(contactId != null) { "Unknown C0 photo contact" }
        val wrapped = body.size >= 6 && body.copyOfRange(0, 6).contentEquals(magic)
        val sourceTime: Long
        val event: String
        val photo: ByteArray
        if (wrapped) {
            require(body.size in 78..(78 + 256 * 1024))
            sourceTime = (6..13).fold(0L) { n, i ->
                (n shl 8) or (body[i].toLong() and 255)
            }
            val digest = body.copyOfRange(14, 78).toString(StandardCharsets.US_ASCII)
            photo = body.copyOfRange(78, body.size)
            require(sourceTime in 1..nowMs + 300_000L && hex.matches(digest) &&
                digestFor(photo) == digest) {
                "Invalid versioned photo digest"
            }
            event = "profile:$digest"
        } else {
            sourceTime = timestamp
            event = logicalId
            photo = body
        }
        require(photo.size <= 256 * 1024)
        if (photo.isNotEmpty()) {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(photo, 0, photo.size, bounds)
            require(bounds.outWidth in 1..512 && bounds.outHeight in 1..512 &&
                bounds.outWidth.toLong() * bounds.outHeight <= 512L * 512)
        }
        db.execSQL("CREATE TABLE IF NOT EXISTS device_chat_profile_versions (" +
            "account_ed TEXT NOT NULL PRIMARY KEY,timestamp_ms INTEGER NOT NULL," +
            "event_id TEXT NOT NULL)")
        val old = db.query(SimpleSQLiteQuery("SELECT timestamp_ms,event_id FROM " +
            "device_chat_profile_versions WHERE account_ed=?", arrayOf(account)
        )).use { if (it.moveToFirst()) it.getLong(0) to it.getString(1) else null }
        val synced = db.query(SimpleSQLiteQuery("SELECT timestamp_ms,event_id FROM " +
            "device_sync_contact_profiles WHERE contact_id=?", arrayOf(contactId)
        )).use { if (it.moveToFirst()) it.getLong(0) to it.getString(1) else null }
        val newest = listOfNotNull(old, synced).maxWithOrNull(
            compareBy<Pair<Long, String>> { it.first }.thenBy { it.second })
        if (newest == null || sourceTime > newest.first ||
            sourceTime == newest.first && event > newest.second) {
            db.execSQL("INSERT OR REPLACE INTO device_chat_profile_versions " +
                "(account_ed,timestamp_ms,event_id) VALUES (?,?,?)",
                arrayOf(account, sourceTime, event))
            db.execSQL("INSERT OR REPLACE INTO device_sync_contact_profiles " +
                "(contact_id,timestamp_ms,event_id) VALUES (?,?,?)",
                arrayOf(contactId, sourceTime, event))
            val encoded = if (photo.isEmpty()) null else Base64.encodeToString(photo, Base64.NO_WRAP)
            if (linked) db.execSQL("UPDATE linked_chat_contacts SET avatar_base64=?," +
                "updated_at_ms=MAX(updated_at_ms,?) WHERE account_ed=? AND blocked=0",
                arrayOf(encoded, sourceTime, account))
            else db.execSQL("UPDATE contacts SET profilePictureBase64=? " +
                "WHERE publicKeyBase64=? AND isBlocked=0",
                arrayOf(encoded, account))
            db.execSQL("INSERT INTO device_sync_source_changes " +
                "(topic,object_id,kind,changed_at_ms) VALUES ('contacts',?,'upsert',?)",
                arrayOf(account, nowMs))
        }
        return false
    }

    private fun digestFor(photo: ByteArray): String {
        val value = if (photo.isEmpty()) "null" else
            "\"${Base64.encodeToString(photo, Base64.NO_WRAP)}\""
        val json = "{\"settings_id\":\"account:photo\",\"value\":$value,\"version\":1}"
        return MessageDigest.getInstance("SHA-256")
            .digest(json.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
