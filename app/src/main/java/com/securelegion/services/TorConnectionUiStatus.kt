package com.securelegion.services

/** A green Tor network indicator means the service has opened its verified transport gate. */
internal object TorConnectionUiStatus {
    fun isConnected(state: TorService.TorState, validatedInternet: Boolean,
                    bootstrapPercent: Int, circuitsEstablished: Int,
                    transportGateOpen: Boolean): Boolean =
        validatedInternet && state == TorService.TorState.RUNNING &&
            bootstrapPercent >= 100 && circuitsEstablished == 1 && transportGateOpen
}
