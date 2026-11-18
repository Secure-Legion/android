package com.securelegion

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.database.SecureLegionDatabase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Opens a real SQLCipher profile and checks contact capture and import isolation. */
@RunWith(AndroidJUnit4::class)
class DeviceSyncSchemaDeviceTest {
    @Test fun opensCurrentSchemaAndInstallsContactCapture() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals(BuildConfig.APPLICATION_ID, context.packageName)
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        db.query("PRAGMA user_version").use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals(64, cursor.getInt(0))
        }
        db.query("SELECT name FROM sqlite_master WHERE type='trigger' AND " +
            "name LIKE 'device_sync_capture_contact_%'").use { cursor ->
            val names = mutableSetOf<String>()
            while (cursor.moveToNext()) names.add(cursor.getString(0))
            assertEquals(setOf("device_sync_capture_contact_insert",
                "device_sync_capture_contact_update", "device_sync_capture_contact_delete"), names)
        }
        db.query("PRAGMA table_info(messages)").use { cursor ->
            val nameIndex = cursor.getColumnIndexOrThrow("name")
            var importedColumn = false
            while (cursor.moveToNext()) {
                if (cursor.getString(nameIndex) == "isDeviceSyncImported") importedColumn = true
            }
            assertTrue(importedColumn)
        }
    }
}
