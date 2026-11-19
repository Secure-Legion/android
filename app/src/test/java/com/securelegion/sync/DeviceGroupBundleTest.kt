package com.securelegion.sync

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceGroupBundleTest {
    @Test fun liveBundleIsCanonicalAndClearRevokesAccess() {
        val bundle = DeviceGroupBundle.create(DeviceGroupBundle.Mode.LIVE,
            packedOperations = byteArrayOf(1, 2, 3))
        val encoded = bundle.encoded()
        assertEquals(DeviceGroupBundle.Mode.LIVE, DeviceGroupBundle.parse(encoded).mode)
        assertArrayEquals(byteArrayOf(1, 2, 3), bundle.packedOperations)
        assertThrows(IllegalArgumentException::class.java) {
            DeviceGroupBundle.parse(encoded + byteArrayOf(0))
        }
        bundle.clear()
        assertThrows(IllegalStateException::class.java) { bundle.encoded() }
        assertArrayEquals(byteArrayOf(0, 0, 0), bundle.packedOperations)
    }

    @Test fun invitationRequiresExactKeyAndReceiptSizes() {
        assertThrows(IllegalArgumentException::class.java) {
            DeviceGroupBundle.create(DeviceGroupBundle.Mode.INVITATION,
                groupKey = ByteArray(32), packedOperations = byteArrayOf(1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceGroupBundle.create(DeviceGroupBundle.Mode.PROOFS_ONLY)
        }
    }
}
