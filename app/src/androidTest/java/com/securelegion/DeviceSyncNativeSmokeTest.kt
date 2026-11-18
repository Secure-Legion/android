package com.securelegion

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.crypto.RustBridge
import java.security.SecureRandom
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Device-side JNI packaging smoke test; no account or network is required. */
@RunWith(AndroidJUnit4::class)
class DeviceSyncNativeSmokeTest {
    @Test fun historyIdentityAndNoiseEngineLoad() {
        assertEquals(BuildConfig.APPLICATION_ID,
            InstrumentationRegistry.getInstrumentation().targetContext.packageName)
        val delta = """{"message_id":"native_smoke","status":2}"""
            .toByteArray(Charsets.UTF_8)
        val first = RustBridge.deviceHistoryIdentity(delta, "receipts", "native_smoke", 1_000L)
        val second = RustBridge.deviceHistoryIdentity(delta, "receipts", "native_smoke", 1_000L)
        assertTrue(first.size >= 66)
        assertArrayEquals(first, second)
        val random = SecureRandom()
        val account = ByteArray(32).also(random::nextBytes)
        val ed = ByteArray(32).also(random::nextBytes)
        val x = ByteArray(32).also(random::nextBytes)
        val handle = RustBridge.syncFsNew(account, ed, x)
        try { assertTrue(handle > 0L) }
        finally { if (handle > 0L) RustBridge.syncFsFree(handle) }
        account.fill(0); ed.fill(0); x.fill(0)
    }
}
