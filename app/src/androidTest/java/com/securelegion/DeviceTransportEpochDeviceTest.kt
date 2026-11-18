package com.securelegion

import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.database.DeviceTransportEpochStore
import com.securelegion.database.SecureLegionDatabase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64

@RunWith(AndroidJUnit4::class)
class DeviceTransportEpochDeviceTest {
    @Test fun generationsNeverRollBackAndRetirementPrunesOldSession() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = SecureLegionDatabase.getInstance(context, ByteArray(32) { 0x53 })
        val db = database.openHelper.writableDatabase
        val account = ByteArray(32) { 0x51 }
        val encoded = Base64.getEncoder().encodeToString(account)
        val peer = "X".repeat(43)
        val local = "Y".repeat(43)
        try {
            db.beginTransaction()
            try {
                assertEquals(2L, DeviceTransportEpochStore.allocate(db,
                    account, peer, local).generation)
                assertEquals(3L, DeviceTransportEpochStore.allocate(db,
                    account, peer, local).generation)
                DeviceTransportEpochStore.admit(db, account, peer, local, 2, 0)
                db.execSQL("INSERT INTO device_transport_sessions " +
                    "(account_ed,peer_device_id,local_device_id,session_id,direction," +
                    "state,generation,prekey_wire,created_at_ms) " +
                    "VALUES (?,?,?,?,'rx','ready',2,?,1)",
                    arrayOf(encoded, peer, local, ByteArray(32) { 1 }, ByteArray(1)))
                DeviceTransportEpochStore.admit(db, account, peer, local, 3, 2)
                assertThrows(IllegalArgumentException::class.java) {
                    DeviceTransportEpochStore.admit(db, account, peer, local, 3, 2)
                }
                db.setTransactionSuccessful()
            } finally { db.endTransaction() }
            db.query(SimpleSQLiteQuery("SELECT COUNT(*) FROM device_transport_sessions " +
                "WHERE account_ed=? AND peer_device_id=?", arrayOf(encoded, peer))).use {
                assertTrue(it.moveToFirst())
                assertEquals(0, it.getInt(0))
            }
        } finally {
            db.execSQL("DELETE FROM device_transport_sessions WHERE account_ed=? " +
                "AND peer_device_id=?", arrayOf(encoded, peer))
            db.execSQL("DELETE FROM device_transport_epochs WHERE account_ed=? " +
                "AND peer_device_id=?", arrayOf(encoded, peer))
        }
    }
}
