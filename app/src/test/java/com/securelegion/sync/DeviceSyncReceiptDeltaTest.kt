package com.securelegion.sync

import org.junit.Assert.assertEquals
import org.junit.Test

class DeviceSyncReceiptDeltaTest {
    @Test fun readAndDeliveryNeverRegress() {
        assertEquals(3, DeviceSyncReceiptDelta.mergeStatus(3, 1))
        assertEquals(2, DeviceSyncReceiptDelta.mergeStatus(2, 4))
        assertEquals(1, DeviceSyncReceiptDelta.mergeStatus(5, 1))
        assertEquals(7, DeviceSyncReceiptDelta.mergeStatus(6, 7))
    }
}
