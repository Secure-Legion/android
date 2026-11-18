package com.securelegion.services

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TorConnectionUiStatusTest {
    @Test fun verifiedTransportIsConnectedWithoutOnionSelfTest() {
        assertTrue(TorConnectionUiStatus.isConnected(
            TorService.TorState.RUNNING, true, 100, 1, true))
    }

    @Test fun networkChangeAndIncompleteTransportStayConnecting() {
        assertFalse(TorConnectionUiStatus.isConnected(
            TorService.TorState.RUNNING, true, 100, 1, false))
        assertFalse(TorConnectionUiStatus.isConnected(
            TorService.TorState.RUNNING, false, 100, 1, true))
        assertFalse(TorConnectionUiStatus.isConnected(
            TorService.TorState.BOOTSTRAPPING, true, 100, 1, true))
        assertFalse(TorConnectionUiStatus.isConnected(
            TorService.TorState.RUNNING, true, 100, 0, true))
    }
}
