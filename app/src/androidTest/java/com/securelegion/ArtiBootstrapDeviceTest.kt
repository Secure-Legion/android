package com.securelegion

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.crypto.RustBridge
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises the packaged arm64 Arti JNI and a real Tor bootstrap. */
@RunWith(AndroidJUnit4::class)
class ArtiBootstrapDeviceTest {
    @Test(timeout = 240_000)
    fun bootstrapsAndShutsDown() {
        assertEquals(BuildConfig.APPLICATION_ID,
            InstrumentationRegistry.getInstrumentation().targetContext.packageName)
        try {
            assertEquals("Arti bootstrapped", RustBridge.initializeTor())
            assertTrue(RustBridge.getBootstrapStatus() >= 100)
        } finally {
            RustBridge.shutdownArti()
        }
    }
}
