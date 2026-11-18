package com.securelegion

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.sync.DeviceTransportFrame
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceTransportFrameDeviceTest {
    @Test fun c0SignatureBindsExactWireAndDeviceIdentity() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        LocalDeviceIdentity.loadOrCreate(context).use { identity ->
            val frame = DeviceTransportFrame.sign(
                DeviceTransportFrame.Kind.RESPONSIBILITY_REQUEST,
                ByteArray(32) { 1 }, ByteArray(32) { 2 },
                identity.deviceId, identity.deviceId,
                ByteArray(32), 0, ByteArray(32), ByteArray(0), identity)
            assertTrue(frame.verify(identity.signingPublicKey))
            val altered = frame.wire.copyOf().apply {
                this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
            }
            assertFalse(DeviceTransportFrame.parse(altered)
                .verify(identity.signingPublicKey))
        }
    }
}
